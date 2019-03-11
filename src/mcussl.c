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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef MCUHTTP_NO_INET_HEADERS
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include "mcusock.h"
#include "mcussl.h"

#define PRIV ((mcussl_priv_t*)ctx)

const char *pers = "mcussl";

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

mbedtls_x509_crt cli_ca;
mbedtls_ssl_config cli_conf;

typedef struct mcussl_priv_t {
	mcusock_t ctx;
	mbedtls_ssl_context ssl;
}mcussl_priv_t;

static
void print_error(int errnum) {
	char buf [128];
	mbedtls_strerror(errnum, buf, 128);
	puts(buf);
}

mcussl_t mcussl_connect(const char *host, int port, int timeout) {
	int err = 0;
	mcussl_priv_t *priv = (mcussl_priv_t*)malloc(sizeof(mcussl_priv_t));
	if (!priv) {
		return NULL;
	}
	
	mbedtls_ssl_init( &priv->ssl );
	
	err = mbedtls_ssl_setup( &priv->ssl, &cli_conf );
	if( err != 0 )
	{
		print_error(err);
		goto CLEAN;
	}
	
	err = mbedtls_ssl_set_hostname( &priv->ssl, host );
	if( err != 0 )
	{
		print_error(err);
		goto CLEAN;
	}
	
	priv->ctx = mcusock_connect(host, port, timeout);
	if (!priv->ctx) {
		goto CLEAN;
	}
	
	mbedtls_ssl_set_bio( &priv->ssl, priv->ctx, (mbedtls_ssl_send_t*)mcusock_send, (mbedtls_ssl_recv_t*)mcusock_recv, NULL );
	
	err = mbedtls_ssl_handshake( &priv->ssl );
	if( err != 0 )
	{
		print_error(err);
		goto CLEAN;
	}
	
	return (mcussl_t)priv;
CLEAN:
	mcussl_close(priv);
	return NULL;
}

int mcussl_recv(mcussl_t ctx, void *buf, size_t len) {
	return mbedtls_ssl_read( &PRIV->ssl, buf, len);
}

int mcussl_send(mcussl_t ctx, const void *buf, size_t len) {
	return mbedtls_ssl_write( &PRIV->ssl, buf, len);
}

int mcussl_get_fd(mcussl_t ctx) {
	return mcusock_get_fd(PRIV->ctx);
}

void mcussl_close(mcussl_t ctx) {
	mbedtls_ssl_close_notify( &PRIV->ssl );
	mbedtls_ssl_free(&PRIV->ssl);
	
	if (PRIV->ctx)
		mcusock_close(PRIV->ctx);
	
	free(ctx);
}

struct wrapper_data {
	mbedtls_ssl_config srvconf;
	int (*callback)(void *ctx, void *data);
	void *data;
};

static
int wrapper(void *ctx, void *pdata) {
	int ret = -1;
	struct wrapper_data *wrapper_data = (struct wrapper_data *)pdata;
	
	mcussl_priv_t *priv = (mcussl_priv_t*)malloc(sizeof(mcussl_priv_t));
	if (!priv) {
		return -1;
	}
	
	priv->ctx = ctx;
	mbedtls_ssl_init( &priv->ssl );
	
	ret = mbedtls_ssl_setup( &priv->ssl, &wrapper_data->srvconf );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	mbedtls_ssl_set_bio( &priv->ssl, priv->ctx, (mbedtls_ssl_send_t*)mcusock_send, (mbedtls_ssl_recv_t*)mcusock_recv, NULL );
	
	ret = mbedtls_ssl_handshake( &priv->ssl );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	return wrapper_data->callback((mcussl_t*)priv, wrapper_data->data);
CLEAN:
	mcussl_close(priv);
	return ret;
}

int mcussl_serve(
	  const char *addr,
	  int port,
	  int max_cli,
	  int timeout,
	  int (*callback)(void *ctx, void *data),
	  void *data,
	  int *terminator,
	  void *srvcert_bin,
	  unsigned int srvcert_len,
	  void *pkey_bin,
	  unsigned int pkey_len) {
	int ret = -1;
	struct wrapper_data wrapper_data;
	mbedtls_x509_crt srvcert;
	mbedtls_pk_context pkey;
	
	wrapper_data.callback = callback;
	wrapper_data.data = data;
	
	mbedtls_ssl_config_init( &wrapper_data.srvconf );
	mbedtls_x509_crt_init( &srvcert );
	mbedtls_pk_init( &pkey );
	
	ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) srvcert_bin,
								 srvcert_len );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) pkey_bin,
								pkey_len, NULL, 0 );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	if( ( ret = mbedtls_ssl_config_defaults( &wrapper_data.srvconf,
											MBEDTLS_SSL_IS_SERVER,
											MBEDTLS_SSL_TRANSPORT_STREAM,
											MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	mbedtls_ssl_conf_rng( &wrapper_data.srvconf, mbedtls_ctr_drbg_random, &ctr_drbg );
	
	mbedtls_ssl_conf_ca_chain( &wrapper_data.srvconf, srvcert.next, NULL );
	if( ( ret = mbedtls_ssl_conf_own_cert( &wrapper_data.srvconf, &srvcert, &pkey ) ) != 0 )
	{
		goto CLEAN;
	}

	ret = mcusock_serve(addr, port, max_cli, timeout, wrapper, &wrapper_data, terminator);
	
CLEAN:
	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_config_free( &wrapper_data.srvconf );
	return ret;
}

int mcussl_init(void *ca_cert, size_t ca_len) {
	int ret = -1;
	
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	
	ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
								(const unsigned char *) pers, strlen( pers ));
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}

	return 0;
CLEAN:
	mcussl_deinit();
	return ret;
}

int mcussl_deinit() {
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	return 0;
}

int mcussl_client_init(void *ca_cert, size_t ca_len) {
	int ret = -1;
	
	mbedtls_x509_crt_init( &cli_ca );
	mbedtls_ssl_config_init( &cli_conf );
	
	ret = mbedtls_ssl_config_defaults( &cli_conf,
								MBEDTLS_SSL_IS_CLIENT,
								MBEDTLS_SSL_TRANSPORT_STREAM,
								MBEDTLS_SSL_PRESET_DEFAULT );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	mbedtls_ssl_conf_rng( &cli_conf, mbedtls_ctr_drbg_random, &ctr_drbg );
	
	ret = mbedtls_x509_crt_parse( &cli_ca, ca_cert, ca_len );
	if( ret != 0 )
	{
		print_error(ret);
		goto CLEAN;
	}
	
	mbedtls_ssl_conf_ca_chain( &cli_conf, &cli_ca, NULL );
	mbedtls_ssl_conf_authmode( &cli_conf, MBEDTLS_SSL_VERIFY_REQUIRED );
	
	return 0;
CLEAN:
	mcussl_client_deinit();
	return ret;
}

int mcussl_client_deinit() {
	mbedtls_ssl_config_free( &cli_conf );
	mbedtls_x509_crt_free( &cli_ca );
	return 0;
}
