#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcuhttp.h"
#include "mcussl.h"

#include "test-certs.h"
#include "test-resources.h"

#define TEST_SSL 0

#if !TEST_SSL
#define TEST_GET_URL "http://127.0.0.1:8811/phpinfo.php"
#define TEST_POST_URL "http://127.0.0.1:8811/post_chunk.php"
#else
#define TEST_GET_URL "https://bincodecn.github.io/untitled/index.html"
//#define TEST_GET_URL "https://oldsky.gitee.io/homepage/index.html"
#define TEST_POST_URL "https://bincodecn.github.io/untitled/index.html"
#endif

int test_get() {
	char buf[4096];
	mcuhttp_t *con = NULL;
	
	con = mcuhttp_create_request("GET", TEST_GET_URL, 3000);
	
	if (!con) {
		fprintf(stderr, "Request failed\n");
		return -1;
	}
	
	mcuhttp_send_request(con);
	
	mcuhttp_recv_response(con);
	
	int clen = mcuhttp_get_content_length(con);
	
	int sum = 0;
	
	while (1) {
		int len = mcuhttp_recv_body(con, buf, 4096);
		if (len < 0) {
			fprintf(stderr, "Receive body failed\n");
			return -1;
		}
		
		if (len == 0)
			break;
		
		sum += len;
		
		fwrite(buf, len, 1, stdout);
		
		if (clen && sum == clen)
			break;
	}
	
	printf("\nsum: %d\n", sum);
	
	mcuhttp_close(con);
	
	return 0;
}

int test_post() {
	char buf[4096];
	mcuhttp_t *con = NULL;
	
	con = mcuhttp_create_request("POST", TEST_POST_URL, 3000);
	
	if (!con) {
		fprintf(stderr, "Request failed\n");
		return -1;
	}
	
	mcuhttp_enable_chunk(con);
	
	mcuhttp_send_request(con);
	
	strncpy(buf, "Hello", 5);
	mcuhttp_send_body(con, buf, 5);

	strncpy(buf, "World", 5);
	mcuhttp_send_body(con, buf, 5);

	mcuhttp_send_body(con, NULL, 0);
	
	mcuhttp_recv_response(con);
	
	int sum = 0;
	
	while (1) {
		int len = mcuhttp_recv_body(con, buf, 4096);
		if (len < 0) {
			fprintf(stderr, "Receive body failed\n");
			return -1;
		}
		
		if (len == 0)
			break;
		
		sum += len;
		
		fwrite(buf, len, 1, stdout);
	}
	
	printf("\nsum: %d\n", sum);
	
	mcuhttp_close(con);
	
	return 0;
}

int index_json(mcuhttp_t *con, const mcuhttp_router_t *router) {
	mcuhttp_create_response(con);
	
	mcuhttp_set_header(con, "Content-Type", "text/html");
	
	mcuhttp_set_header(con, "Transfer-Encoding", "chunked");
	
	mcuhttp_send_response(con, 200);
	
	mcuhttp_send_body(con, "<h1>hello</h1>", 14);
	
	mcuhttp_send_body(con, NULL, 0);
	
	return 0;
}

mcuhttp_router_t routers[] = {
	MCUHTTP_ROUTER_INDEX_HTML,
	MCUHTTP_ROUTER_LENNA_PNG,
	MCUHTTP_CALLBACK_ROUTER("/index.json", index_json),
};

int test_server() {
	mcuhttp_server_t server;
	
	memset(&server, 0, sizeof(server));
	
	server.addr = "127.0.0.1";
	server.port = 8822;
	server.max_con = 32;
	server.timeout = 3000;
	server.routers = routers;
	server.router_count = MCUHTTP_SIZE_OF_ARRAY(routers);
#if TEST_SSL
	server.type = MCUHTTP_SSL;
	server.srvcert = server_crt;
	server.srvcert_len = server_crt_len;
	server.pkey = server_key;
	server.pkey_len = server_key_len;
#else
	server.type = MCUHTTP_PLAIN;
#endif
	return mcuhttp_serve(&server, NULL);
}

int main(int argc, char const *argv[])
{
#if TEST_SSL
	mcussl_init();
	mcussl_client_init(DigiCert_High_Assurance_EV_Root_CA_cer, DigiCert_High_Assurance_EV_Root_CA_cer_len);
#endif
	
	test_get();
//	test_post();
//	test_server();
	
#if TEST_SSL
	mcussl_client_deinit();
	mcussl_deinit();
#endif
	return 0;
}
