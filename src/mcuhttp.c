/*
 * Copyright (c) 2019, Zheng Zhaocong. All rights reserved.
 *
 * This file is part of mcuhttp.
 * 
 * mcuhttp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as 
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * mcuhttp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with mcuhttp.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "mcuhttp.h"
#include "mcusock.h"

#ifdef MCUHTTP_ENABLE_SSL
#include "mcussl.h"
#endif

#define MCUHTTP_USER_AGENT "mcuhttp/0.0.1"
#define MCUHTTP_SERVER     "mcuhttp/0.0.1"

#ifndef MCUHTTP_INDEX
#define MCUHTTP_INDEX "/index.html"
#endif

#ifndef MCUHTTP_BUFFER_SIZE 
#define MCUHTTP_BUFFER_SIZE 128
#endif

#ifndef MCUHTTP_BUFFER_MAX
#define MCUHTTP_BUFFER_MAX 512
#endif

#define PRIV ((mcuhttp_priv_t*)con)

#ifndef MIN
#define MIN(a, b) ((a) > (b) ? (b) : (a) )
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b) )
#endif

struct mcuhttp_ll {
	struct mcuhttp_ll *next;
};

struct header_ll {
	struct mcuhttp_ll ll;
	char *header;
	char *value;
};

typedef struct {
	char *mem;
	char *data;
	unsigned int  size;
	unsigned int  used;
} mcuhttp_buffer_t;

typedef struct {
	mcuhttp_t con;
	int con_type;
	
	void *ctx;
	int (*send)(void *ctx, const void *buf, size_t len);
	int (*recv)(void *ctx, void *buf, size_t len);
	void (*close)(void *ctx);

	char *method;
	char *protocol;
	char *host;
	int  port;
	char *path;

	int chunk_remain;
	
	struct mcuhttp_ll *headers;
	mcuhttp_buffer_t buffer;
} mcuhttp_priv_t;

/*
	Utils
*/

const char *find_crlf(const char *buf, size_t len) {
	for (size_t i = 0; i < (len - 1); ++i)
	{
		if (buf[i] == '\r' && buf[i+1] == '\n') {
			return &buf[i];
		}
	}
	return NULL;
}

/*
	Linked list
*/

static 
void ll_free(struct mcuhttp_ll **pll) {
	struct mcuhttp_ll *ll = *pll;
	
	while (ll) {
		struct mcuhttp_ll *ptr = ll;
		ll = ll->next;
		free(ptr);
	}
	*pll = NULL;
}

static 
void ll_append(struct mcuhttp_ll **pll, void *entry) {
	while (*pll) {
		pll = &(*pll)->next;
	}
	*pll = entry;
	((struct mcuhttp_ll *)entry)->next = NULL;
}

static 
void ll_delete(struct mcuhttp_ll **pll, void *entry) {
	
	while (*pll) {
		if (*pll == entry) {
			struct mcuhttp_ll *ptr = *pll;
			*pll = (*pll)->next;
			free(ptr);
			break;
		} else {
			pll = &(*pll)->next;
		}
	}
}

static 
unsigned ll_count(struct mcuhttp_ll **pll) {
	unsigned count = 0;
	
	while (*pll) {
		count ++;
		pll = &(*pll)->next;
	}
	return count;
}

static 
void* ll_get(struct mcuhttp_ll **pll, unsigned index) {
	unsigned i = 0;
	
	while (*pll) {
		if (i == index)
			return *pll;
		
		pll = &(*pll)->next;
		i++;
	}
	return NULL;
}

/*
	Stream
*/

static
int buffer_init(mcuhttp_buffer_t *buffer, unsigned int size) {
	if (!buffer){
		errno = EINVAL;
		return -EINVAL;
	}

	if (buffer->mem)
		free(buffer->mem);

	memset(buffer, 0, sizeof(mcuhttp_buffer_t));

	buffer->size = size;
	buffer->mem = (char*)malloc(size);
	buffer->data = buffer->mem;

	if (!buffer->mem) {
		return -ENOMEM;
	}
	return 0;
}

static
int buffer_free(mcuhttp_buffer_t *buffer) {
	if (!buffer){
		errno = EINVAL;
		return -EINVAL;
	}

	free(buffer->mem);
	memset(buffer, 0, sizeof(mcuhttp_buffer_t));
	return 0;
}

static
void* buffer_alloc(mcuhttp_buffer_t *buffer, int len) {
	
	if (buffer->used == 0) {
		buffer->data = buffer->mem;
	}
	
	int dirty = buffer->data - buffer->mem;
	int free = buffer->size - dirty - buffer->used;

	if (free < len) {
		if (dirty) {
			// Free dirty space
			for (int i = 0; i < buffer->used; ++i)
			{
				buffer->mem[i] = buffer->data[i];
			}
			dirty = 0;
			buffer->data = buffer->mem;
			free = buffer->size - buffer->used;
		}

		if (free < len) {
			int new_size = buffer->used + MAX(MCUHTTP_BUFFER_SIZE, len + MCUHTTP_BUFFER_SIZE/2);
			buffer->mem = realloc(buffer->mem, new_size);
			buffer->data = buffer->mem;
			buffer->size = new_size;
		}
	}
	
	void *ptr = buffer->data + buffer->used;
	buffer->used += len;

	return ptr;
}

static 
int buffer_write(mcuhttp_buffer_t *buffer, const void *buf, int len) {
	memcpy(buffer_alloc(buffer, len), buf, len);
	return len;
}

static 
int buffer_read(mcuhttp_buffer_t *buffer, void *buf, int len) {
	int rlen = MIN(len, buffer->used);

	if (!rlen)
		return 0;

	if (buf)
		memcpy(buf, buffer->data, rlen);

	buffer->data += rlen;
	buffer->used -= rlen;

	return rlen;
}

static
const char *get_status_message(int status) {
	switch(status) {
		case 200: return "OK";
		case 301: return "Moved Permanently";
		case 304: return "Not Modified";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 500: return "Internal Server Error";
		case 505: return "HTTP Version Not Supported";
	}
	return "null";
}

/*
	mcuhttp
*/

mcuhttp_t* mcuhttp_alloc(int type, void *ctx) {
	mcuhttp_priv_t *priv = (mcuhttp_priv_t*)malloc(sizeof(mcuhttp_priv_t));
	
	memset(priv, 0, sizeof(mcuhttp_priv_t));
	buffer_init(&priv->buffer, MCUHTTP_BUFFER_SIZE);
	
	priv->con_type = type;
	priv->ctx = ctx;
	
	if (type == MCUHTTP_SSL) {
#ifdef MCUHTTP_ENABLE_SSL
		priv->send = mcussl_send;
		priv->recv = mcussl_recv;
		priv->close = mcussl_close;
#endif
	} else {
		priv->send = mcusock_send;
		priv->recv = mcusock_recv;
		priv->close = mcusock_close;
	}
	
	return (mcuhttp_t*)priv;
}

void mcuhttp_close(mcuhttp_t *con) {
	if (!con) {
		errno = EINVAL;
		return;
	}
	
	PRIV->close(PRIV->ctx);

	// Free header content
	for (int i = 0; i < ll_count(&PRIV->headers); ++i)
	{
		struct header_ll *hll = (struct header_ll*)ll_get(&PRIV->headers, i);
		if (hll->header)
			free(hll->header);
		if (hll->value)
			free(hll->value);
	}
	
	// Free linked list
	ll_free(&PRIV->headers);
	
	if (PRIV->method)
		free(PRIV->method);
	
	if (PRIV->protocol)
		free(PRIV->protocol);
	
	if (PRIV->host)
		free(PRIV->host);
	
	if (PRIV->path)
		free(PRIV->path);

	buffer_free(&PRIV->buffer);
	
	free(con);
}

const char *mcuhttp_get_header(
	mcuhttp_t *con,
	const char *header) {

	if (!con || !header) {
		errno = EINVAL;
		return NULL;
	}

	for (int i = 0; i < ll_count(&PRIV->headers); ++i)
	{
		struct header_ll *hll = (struct header_ll*)ll_get(&PRIV->headers, i);
		if (strcmp(hll->header, header) == 0)
			return hll->value;
	}
	return NULL;
}

int mcuhttp_set_header_ex(
	mcuhttp_t *con,
	const char *header,
	unsigned int header_len,
	const char *value,
	unsigned int value_len) {
	
	if (!con || !header){
		errno = EINVAL;
		return -EINVAL;
	}

	struct header_ll *hll_exists = NULL;

	for (int i = 0; i < ll_count(&PRIV->headers); ++i)
	{
		struct header_ll *hll = (struct header_ll*)ll_get(&PRIV->headers, i);
		if (strncmp(hll->header, header, header_len) == 0) {
			hll_exists = hll;
			break;
		}
	}

	if (value) {
		if (hll_exists) {
			if (value_len <= strlen(hll_exists->value)) {
				strncpy(hll_exists->value, value, value_len);
			} else {
				free(hll_exists->value);
				hll_exists->value = strndup(value, value_len);
			}
		} else {
			struct header_ll *hll = (struct header_ll *)malloc(sizeof(struct header_ll));
			hll->header = strndup(header, header_len);
			hll->value = strndup(value, value_len);
			ll_append(&PRIV->headers, hll);
		}
	} else {
		// Delete header
		if (hll_exists) 
			ll_delete(&PRIV->headers, hll_exists);
	}

	if (strncmp(header, "Transfer-Encoding", header_len) == 0) {
		if (value && strncmp(value, "chunked", value_len) == 0)
			con->chunked = 1;
		else
			con->chunked = 0;
	}

	return 0;
}

int mcuhttp_set_header(
					   mcuhttp_t *con,
					   const char *header,
					   const char *value) {
	return mcuhttp_set_header_ex(con, header, strlen(header), value, strlen(value));
}

int mcuhttp_set_content_length(mcuhttp_t *con, int len) {
	char buf[24];
	snprintf(buf, 24, "%d", len);
	mcuhttp_set_header(con, "Content-Length", buf);
	return 0;
}

int mcuhttp_get_content_length(mcuhttp_t *con) {
	const char *content_length =mcuhttp_get_header(con, "Content-Length");
	if (content_length)
		return atoi(content_length);
	return 0;
}

static 
int parse_url(const char *url, char **protocol, char **host, int *port, char **path) {
	if (strncmp(url, "http", 4)) {
		errno = EINVAL;
		return -EINVAL;
	}

	if (strncmp(url, "https", 5) == 0) {
		*protocol = strdup("https");
		*port = 443;
	} else {
		*protocol = strdup("http");
		*port = 80;
	}

	// Skip protocol
	url += strlen(*protocol);

	if (strncmp(url, "://", 3)) {
		errno = EINVAL;
		return -EINVAL;
	}

	// Skip ://
	url += 3;

	// Search first '/'
	// If / not found, path_ will pointer to string terminator '\0'
	const char *path_ = url;
	while (*path_ && *path_ != '/')
		path_ ++;

	// Search ':'
	const char *port_sep = url;
	while (*port_sep && *port_sep != ':' && port_sep < path_)
		port_sep ++;

	// Parse port
	if (*port_sep == ':') {
		*port = atoi(port_sep + 1);
	}

	// Parse host
	int host_len = port_sep - url;
	*host = strndup(url, host_len);

	if (!*path_) {
		// Emptry path
		*path = strdup("/");
	} else {
		*path = strdup(path_);
	}

	return 0;
}

mcuhttp_t *mcuhttp_create_request(
	const char *method, 
	const char *url,
	int timeout) {
	int con_type = 0;
	char *protocol = NULL;
	char *host = NULL;
	int port = -1;
	char *path = NULL;
	void *ctx = NULL;

	parse_url(url, &protocol, &host, &port, &path);

	if (!method || !protocol || !host || port <= 0 || !path ||
		(strcmp(protocol, "http") && strcmp(protocol, "https"))) {
		errno = EINVAL;
		goto CLEAN;
	}

	if (strcmp(protocol, "http") == 0) {
		con_type = MCUHTTP_PLAIN;
	} else {
		con_type = MCUHTTP_SSL;
	}
	
	if (con_type == MCUHTTP_SSL) {
#ifdef MCUHTTP_ENABLE_SSL
		ctx = mcussl_connect(host, port, timeout);
#else
		goto CLEAN;
#endif
	} else {
		ctx = mcusock_connect(host, port, timeout);
	}
	
	if (!ctx)
		goto CLEAN;

	mcuhttp_t *con = mcuhttp_alloc(con_type, ctx);
	if (!con)
		goto CLEAN;
	
	PRIV->method = strdup(method);
	PRIV->protocol = protocol;
	PRIV->host = host;
	PRIV->port = port;
	PRIV->path = path;

	// Set server
	int host_len = strlen(host) + 10;
	char *host_ = malloc(host_len);
	if (host_) {
		snprintf(host_, host_len, "%s:%d", host, port);
		mcuhttp_set_header(con, "Host", host_);
		free(host_);
	}

	// Set user agent
	mcuhttp_set_header(con, "User-Agent", MCUHTTP_USER_AGENT);

	// Set accept
	mcuhttp_set_header(con, "Accept", "*/*");
	
	return con;
CLEAN:
	if (ctx) {
		if (con_type == MCUHTTP_SSL) {
#ifdef MCUHTTP_ENABLE_SSL
			mcussl_close(ctx);
#endif
		} else {
			mcusock_close(ctx);
		}
	}

	if (protocol)
		free(protocol);
	if (host)
		free(host);
	if (path)
		free(path);
	return NULL;
}

int mcuhttp_send_request(
	mcuhttp_t *con) {
	int ret = 0;
	char temp[MCUHTTP_BUFFER_SIZE];

	int len = snprintf(temp, MCUHTTP_BUFFER_SIZE, "%s %s HTTP/1.1\r\n", PRIV->method, PRIV->path);
	buffer_write(&PRIV->buffer, temp, len);

	for (int i = 0; i < ll_count(&PRIV->headers); ++i)
	{
		struct header_ll *hll = (struct header_ll*)ll_get(&PRIV->headers, i);
		
		len = snprintf(temp, MCUHTTP_BUFFER_SIZE, "%s: %s\r\n", hll->header, hll->value);
		buffer_write(&PRIV->buffer, temp, len);
	}

	buffer_write(&PRIV->buffer, "\r\n", 2);

	ret = PRIV->send(PRIV->ctx, PRIV->buffer.data, PRIV->buffer.used);
	if (ret < 0) {
		goto CLEAN;
	}

CLEAN:
	// Reset buffer
	buffer_init(&PRIV->buffer, MCUHTTP_BUFFER_SIZE);
	return ret;
}

static
int parse_header(mcuhttp_t *con, const char *line, const char *crlf) {
	const char *header_sep = line;
	while (*header_sep != ':' && header_sep < crlf)
		header_sep ++;
	
	if (header_sep == crlf) {
		return -1;
	}
	
	const char *value = header_sep + 1;
	
	while (*value == ' ' && value < crlf)
		value ++;
	
	if (value == crlf) {
		return -1;
	}
	
	mcuhttp_set_header_ex(con, line, header_sep - line, value, crlf - value);
	return 0;
}

int mcuhttp_recv_response(
	mcuhttp_t *con) {
	int ret = 0;
	int first_line = 1;
	int parse_done = 0;
	char temp[MCUHTTP_BUFFER_SIZE];

	PRIV->buffer.used = 0;

	ll_free(&PRIV->headers);

	while (!parse_done) {
		int rlen = PRIV->recv(PRIV->ctx, temp, MCUHTTP_BUFFER_SIZE);
		if (rlen < 0) {
			ret = rlen;
			break;
		}
		buffer_write(&PRIV->buffer, temp, rlen);
		
		if (PRIV->buffer.size > MCUHTTP_BUFFER_MAX) {
			ret = -EMSGSIZE;
			goto CLEAN;
		}

		while (!parse_done) {
			// Serach CRLF
			const char *crlf = find_crlf(PRIV->buffer.data, PRIV->buffer.used);
			if (!crlf)
				break;
			
			char *line = PRIV->buffer.data;
			
			if (line == crlf) {
				parse_done = 1;
			} else {
				if (first_line) {
					first_line = 0;
					if (strncmp(line, "HTTP/", 5)) {
						errno = EBADMSG;
						ret = -EBADMSG;
						goto CLEAN;
					}

					// Goto status
					while (*line != ' ' && line < crlf)
						line ++;
					
					// Status not found
					if (line == crlf) {
						errno = EBADMSG;
						ret = -EBADMSG;
						goto CLEAN;
					} else {
						line ++;
						con->status = atoi(line);
					}
				} else {
					// Parse header
					if (parse_header(con, line, crlf) < 0) {
						errno = EBADMSG;
						ret = -EBADMSG;
						goto CLEAN;
					}
				}
			}
			// Pop this line
			buffer_read(&PRIV->buffer, NULL, crlf + 2 - PRIV->buffer.data);
		}
	}

	PRIV->chunk_remain = 0;

CLEAN:
	return ret;
}

static
int mcuhttp_send_body_chunked(
	mcuhttp_t *con,
	const void *buf,
	unsigned len) {
	char chunk[24];
	
	// Send chunk header
	snprintf(chunk, 24, "%x\r\n", len);
	
	int ret = PRIV->send(PRIV->ctx, chunk, strlen(chunk));
	if (ret < 0)
		return ret;
	
	if (len) {
		// Send chunk body
		ret = PRIV->send(PRIV->ctx, buf, len);
		if (ret < 0)
			return ret;
	}
	
	// Send chunk footer
	return PRIV->send(PRIV->ctx, "\r\n", 2);
}

int mcuhttp_send_body(
	mcuhttp_t *con,
	const void *buf,
	unsigned len) {

	if (con->chunked)
		return mcuhttp_send_body_chunked(con, buf, len);

	int offset = 0;
	while (offset < len) {
		int ret = PRIV->send(PRIV->ctx, buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}
	
	return len;
}

static
int mcuhttp_recv_body_chunked(
	mcuhttp_t *con,
	void *buf,
	unsigned len) {
	char temp[MCUHTTP_BUFFER_SIZE];

	if (PRIV->chunk_remain == 0) {
		const char *crlf = NULL;
		
		while(1) {
			crlf = find_crlf(PRIV->buffer.data, PRIV->buffer.used);
			if (crlf == PRIV->buffer.data) {
				// Skip crlf(end of a chunk)
				buffer_read(&PRIV->buffer, NULL, 2);
				continue;
			} else if (crlf) {
				break;
			}
			int rlen = PRIV->recv(PRIV->ctx, temp, MCUHTTP_BUFFER_SIZE);
			if (rlen < 0) {
				return rlen;
			}
			buffer_write(&PRIV->buffer, temp, rlen);
		}

		PRIV->chunk_remain = (int)strtol(PRIV->buffer.data, NULL, 16);
		buffer_read(&PRIV->buffer, NULL, crlf - PRIV->buffer.data + 2);

		if (PRIV->chunk_remain == 0) {
			con->finish = 1;
			buffer_read(&PRIV->buffer, NULL, 2);
			
			// Reset buffer
			buffer_init(&PRIV->buffer, MCUHTTP_BUFFER_SIZE);
			return 0;
		}
	}

	if (PRIV->buffer.used == 0) {
		int rlen = PRIV->recv(PRIV->ctx, temp, MCUHTTP_BUFFER_SIZE);
		if (rlen < 0) {
			return rlen;
		}
		buffer_write(&PRIV->buffer, temp, rlen);
	}

	int rd = MIN(len, MIN(PRIV->chunk_remain, PRIV->buffer.used));
	PRIV->chunk_remain -= rd;
	buffer_read(&PRIV->buffer, buf, rd);
	return rd;
}

int mcuhttp_recv_body(
	mcuhttp_t *con,
	void *buf,
	unsigned len) {

	if (con->finish)
		return 0;

	if (con->chunked)
		return mcuhttp_recv_body_chunked(con, buf, len);

	int rlen = 0;

	if (PRIV->buffer.used) {
		rlen = buffer_read(&PRIV->buffer, buf, len);
		if (rlen == len)
			return len;
	}
	
	while (rlen < len) {
		int ret = PRIV->recv(PRIV->ctx, buf + rlen, len - rlen);
		if (ret < 0)
			return ret;
		rlen += ret;
	}

	return len;
}

int mcuhttp_send_response(
    mcuhttp_t *con, int status) {
	int ret = 0;
	char temp[MCUHTTP_BUFFER_SIZE];
	
	int len = snprintf(temp, MCUHTTP_BUFFER_SIZE, "HTTP/1.1 %d %s\r\n", status, get_status_message(status));
	buffer_write(&PRIV->buffer, temp, len);
	
	for (int i = 0; i < ll_count(&PRIV->headers); ++i)
	{
		struct header_ll *hll = (struct header_ll*)ll_get(&PRIV->headers, i);
		
		len = snprintf(temp, MCUHTTP_BUFFER_SIZE, "%s: %s\r\n", hll->header, hll->value);
		buffer_write(&PRIV->buffer, temp, len);
	}
	
	buffer_write(&PRIV->buffer, "\r\n", 2);
	
	ret = PRIV->send(PRIV->ctx, PRIV->buffer.data, PRIV->buffer.used);
	if (ret < 0) {
		goto CLEAN;
	}
	
CLEAN:
	// Reset buffer
	buffer_init(&PRIV->buffer, MCUHTTP_BUFFER_SIZE);
	return ret;
}

int mcuhttp_create_response(
	mcuhttp_t *con) {
	
	// Clear header
	ll_free(&PRIV->headers);
	
	// Set default headers
	mcuhttp_set_header(con, "Connection", "close");
	
	mcuhttp_set_header(con, "Server", MCUHTTP_SERVER);
	
	return 0;
}

static
int file_response(mcuhttp_t *con, const mcuhttp_router_t *router) {
	char buf[24];
	
	mcuhttp_create_response(con);

	mcuhttp_set_header(con, "Content-Type", router->data.mime);
	
	snprintf(buf, 24, "%d", router->data.data_len);
	mcuhttp_set_header(con, "Content-Length", buf);
	
	if (router->type == MCUHTTP_ROUTER_GZIP){
		mcuhttp_set_header(con, "Content-Encoding", "gzip");
	}
	
	mcuhttp_send_response(con, 200);
	
	mcuhttp_send_body(con, router->data.data, router->data.data_len);
	
	return 0;
}

static
int serve(void *ctx, void *pdata) {
	mcuhttp_server_t *server = (mcuhttp_server_t*)pdata;
	char temp[MCUHTTP_BUFFER_SIZE];
	int first_line = 1;
	int parse_done = 0;
	int status = 0;
	
	mcuhttp_t *con = mcuhttp_alloc(server->type, ctx);
	if (!con)
		return -ENOMEM;
	
	while (!parse_done) {
		int rlen = PRIV->recv(ctx, temp, MCUHTTP_BUFFER_SIZE);
		if (rlen <= 0) {
			// Error occured
			goto CLEAN;
		}
		
		buffer_write(&PRIV->buffer, temp, rlen);
		
		if (PRIV->buffer.size > MCUHTTP_BUFFER_MAX) {
			status = 400;
			goto ERROR_CHECK;
		}
		
		while (!parse_done) {
			// Serach CRLF
			const char *crlf = find_crlf(PRIV->buffer.data, PRIV->buffer.used);
			if (!crlf)
				break;
			
			char *line = PRIV->buffer.data;
			
			if (line == crlf) {
				parse_done = 1;
			} else {
				if (first_line) {
					first_line = 0;
					
					// Goto end of method
					char *method = line;
					while (*line != ' ' && line < crlf)
						line ++;
					
					if (line == crlf) {
						status = 400;
						goto ERROR_CHECK;
					}
					
					PRIV->method = strndup(method, line - method);
					
					// Goto path
					while (*line == ' ' && line < crlf)
						line ++;
					char *path = line;
					
					if (path == crlf) {
						status = 400;
						goto ERROR_CHECK;
					}
					
					// Goto end of path
					while (*line != ' ' && line < crlf)
						line ++;
					
					if (line == crlf) {
						status = 400;
						goto ERROR_CHECK;
					}
					
					PRIV->path = strndup(path, line - path);
					
					// Ignore version
				} else {
					// Parse header
					if (parse_header(con, line, crlf) < 0) {
						status = 400;
						goto ERROR_CHECK;
					}
				}
			}
			// Pop this line
			buffer_read(&PRIV->buffer, NULL, crlf - PRIV->buffer.data + 2);
		}
	}
	
	// Match router
	char *path = PRIV->path;
	const mcuhttp_router_t *router = NULL;
	
RETRY:
	for (int i = 0; i < server->router_count; ++i)
	{
		if (strcmp(server->routers[i].path, path) == 0) {
			router = &server->routers[i];
		}
	}
	
	if (router == NULL && strcmp(path, "/") == 0) {
		path = MCUHTTP_INDEX;
		goto RETRY;
	}
	
	if (router == NULL)
		status = 404;
	
	if (status == 0) {
		int ret = 0;
		if (router->type == MCUHTTP_ROUTER_CALLBACK){
			ret = ((thinhttp_callback_t)router->callback.callback)((mcuhttp_t*)PRIV, router);
		} else {
			ret = file_response((mcuhttp_t*)PRIV, router);
		}
		
		if (ret < 0)
			status = 500;
	}
ERROR_CHECK:
	if (status != 0) {
		PRIV->buffer.used = 0;
		
		mcuhttp_create_response(con);
		
		mcuhttp_set_header(con, "Content-Type", "text/plain");
		
		int len = strlen(get_status_message(status));
		snprintf(temp, MCUHTTP_BUFFER_SIZE, "%d", len);
		mcuhttp_set_header(con, "Content-Length", temp);
		
		mcuhttp_send_response(con, status);
		
		mcuhttp_send_body(con, get_status_message(status), len);
	}
CLEAN:
	mcuhttp_close(con);
	return 0;
}

int mcuhttp_serve(mcuhttp_server_t *server, int *terminator) {
	
	if (server->type == MCUHTTP_SSL) {
#ifdef MCUHTTP_ENABLE_SSL
		return mcussl_serve(
							server->addr,
							server->port,
							server->max_con,
							server->timeout,
							serve,
							server,
							terminator,
							server->srvcert,
							server->srvcert_len,
							server->pkey,
							server->pkey_len);
#else
		return -EPROTONOSUPPORT;
#endif
	} else {
		return mcusock_serve(server->addr,
							 server->port,
							 server->max_con,
							 server->timeout,
							 serve,
							 server,
							 terminator);
	}
}
