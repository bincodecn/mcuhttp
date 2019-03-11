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
#include <unistd.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef MCUHTTP_NO_INET_HEADERS
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "mcusock.h"

#define PRIV_SOCK ((int)ctx)

#ifndef MCUSOCK_DEFAULT_TIMEOUT
#define MCUSOCK_DEFAULT_TIMEOUT 		20000 // ms
#endif

static
void set_sock_opt(int sock, int timeout) {
	struct linger linger;
	struct timeval tv;
	
	linger.l_onoff = 0;
	linger.l_linger = 0;
	
	// If turn it on, there will lost data when close sock.
	setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	
	if (timeout >= 0) {
		if (!timeout)
			timeout = MCUSOCK_DEFAULT_TIMEOUT;
		
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}
}

mcusock_t mcusock_connect(const char *host, int port, int timeout) {
	int sock = -1;
	struct sockaddr_in dst_addr;

	// Convert hostname to addr
	struct hostent *hostent = gethostbyname(host);
	if (!hostent){
		errno = EHOSTUNREACH;
		return NULL;
	}
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock < 0){
		return NULL;
	}
	
	set_sock_opt(sock, timeout);

	// Connect to server
	dst_addr.sin_addr.s_addr = *(in_addr_t*)hostent->h_addr;
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(port);

	if (connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0){
		goto CLEAN;
	}

	return (mcusock_t)(intptr_t)sock;

CLEAN:
	if (sock != -1) {
		shutdown(sock, 0);
		close(sock);
	}
	return NULL;
}

int mcusock_recv(mcusock_t ctx, void *buf, size_t len) {
	if (!ctx || !buf) {
		errno = EINVAL;
		return -EINVAL;
	}
	return recv(PRIV_SOCK, buf, len, 0);
}

int mcusock_send(mcusock_t ctx, const void *buf, size_t len) {
	if (!ctx || !buf) {
		errno = EINVAL;
		return -EINVAL;
	}
	return send(PRIV_SOCK, buf, len, 0);
}

int mcusock_get_fd(mcusock_t ctx) {
	return (int)ctx;
}

void mcusock_close(mcusock_t ctx) {
	if (PRIV_SOCK != -1) {
		shutdown(PRIV_SOCK, 0);
		close(PRIV_SOCK);
	}
}

int mcusock_serve(
	const char *addr,
	int port,
	int max_cli,
	int timeout,
	int (*callback)(void *ctx, void *data),
	void *data,
	int *terminator) {
	int ret = -1;
	int sock = -1;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len;
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1){
		return -errno;
	}
	
	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	
	set_sock_opt(sock, timeout);
	
	struct sockaddr_in srv_addr;
	srv_addr.sin_addr.s_addr = inet_addr(addr);
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	
	ret = bind(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if (ret < 0){
		ret = -errno;
		goto CLEAN;
	}
	
	ret = listen(sock, max_cli);
	if (ret < 0) {
		ret = -errno;
		goto CLEAN;
	}
	
	while (!terminator || !*terminator) {
		cli_addr_len = sizeof(cli_addr);
		int client = accept(sock, (struct sockaddr*)&cli_addr, &cli_addr_len);
		if (client == -1) {
			continue;
		}
		
		set_sock_opt(client, timeout);
		
		callback((mcusock_t)(intptr_t)client, data);
	}
	
CLEAN:
	if (sock != -1) {
		shutdown(sock, 0);
		close(sock);
	}
	return ret;
}
