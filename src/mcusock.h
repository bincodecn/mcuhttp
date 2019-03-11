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
#ifndef __MCUSOCK_H__
#define __MCUSOCK_H__

#define mcusock_t void*

mcusock_t mcusock_connect(const char *addr, int port, int timeout);

int mcusock_recv(mcusock_t ctx, void *buf, size_t len);

int mcusock_send(mcusock_t ctx, const void *buf, size_t len);

int mcusock_get_fd(mcusock_t ctx);

void mcusock_close(mcusock_t ctx);

int mcusock_serve(
	const char *addr,
	int port,
	int max_cli,
	int timeout,
	int (*callback)(void *ctx, void *data),
	void *data,
	int *terminator);

#endif
