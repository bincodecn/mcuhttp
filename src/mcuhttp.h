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
#ifndef __MCUHTTP_H__
#define __MCUHTTP_H__

#ifdef __cplusplus
extern "C" {
#endif
	
#define MCUHTTP_PLAIN 0
#define MCUHTTP_SSL 1
	
// Router type
#define MCUHTTP_ROUTER_FILE			1
#define MCUHTTP_ROUTER_GZIP			2
#define MCUHTTP_ROUTER_CALLBACK		3
	
#define mcuhttp_enable_chunk(con) mcuhttp_set_header(con, "Transfer-Encoding", "chunked")

#define MCUHTTP_SIZE_OF_ARRAY(array)	sizeof(array) / sizeof((array)[0])

#define MCUHTTP_CALLBACK_ROUTER(p, f) \
    { \
        .path = p, \
        .type = MCUHTTP_ROUTER_CALLBACK, \
        .callback = { \
            .callback = f, \
        } \
    }

typedef struct {
	int status;
	int chunked;
	int finish;
} mcuhttp_t;

typedef struct {
	const char *path;
	int type;
	union {
		struct {
			const char *mime;
			const char *data;
			unsigned int data_len;
		} data;
		struct {
			void *callback;
			void *data;
		} callback;
	};
} mcuhttp_router_t;
	
typedef struct mcuhttp_server {
	const char *addr;
	int port;
	int max_con;
	int timeout;
	int type;
	const mcuhttp_router_t *routers;
	unsigned int router_count;
	void *srvcert;
	unsigned int srvcert_len;
	void *pkey;
	unsigned int pkey_len;
} mcuhttp_server_t;
	
typedef int (*thinhttp_callback_t)(mcuhttp_t *con, const mcuhttp_router_t *router);
	
void mcuhttp_close(mcuhttp_t *con);

const char *mcuhttp_get_header(
	mcuhttp_t *con,
	const char *header);

int mcuhttp_set_header(
	mcuhttp_t *con,
	const char *header,
	const char *value);
	
int mcuhttp_set_content_length(mcuhttp_t *con, int len);
	
int mcuhttp_get_content_length(mcuhttp_t *con);
	
int mcuhttp_send_body(
					  mcuhttp_t *con,
					  const void *buf,
					  unsigned len);

int mcuhttp_recv_body(
					  mcuhttp_t *con,
					  void *buf,
					  unsigned len);

mcuhttp_t *mcuhttp_create_request(
	const char *method, 
	const char *url,
	int timeout);

int mcuhttp_send_request(
	mcuhttp_t *con);

int mcuhttp_recv_response(
	mcuhttp_t *con);

int mcuhttp_send_response(
	mcuhttp_t *con, int status);
	
int mcuhttp_create_response(
	mcuhttp_t *con);
	
int mcuhttp_serve(mcuhttp_server_t *server, int *terminator);
	
#ifdef __cplusplus
}
#endif

#endif
