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
#ifndef __MCUSSL_H__
#define __MCUSSL_H__

#define mcussl_t void*

mcussl_t mcussl_connect(const char *addr, int port, int timeout);

int mcussl_recv(mcussl_t ctx, void *buf, size_t len);

int mcussl_send(mcussl_t ctx, const void *buf, size_t len);

int mcussl_get_fd(mcussl_t ctx);

void mcussl_close(mcussl_t ctx);

int mcussl_serve(
	 const char *addr,
	 int port,
	 int max_cli,
	 int timeout,
	 int (*callback)(void *ctx, void *data),
	 void *data,
	 int *terminator,
	 void *srvcert,
	 unsigned int srvcert_len,
	 void *pkey,
	 unsigned int pkey_len);

int mcussl_init();
int mcussl_deinit();

/*
 * ca_cert  One or more cert(PEM or DER)
 * ca_len 	Length of ca_cert
 */
int mcussl_client_init(void *ca_cert, size_t ca_len);

int mcussl_client_deinit();

#endif
