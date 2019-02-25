#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define key_file 		"key.pem"
#define certificate_file 	"cert.pem"

int main(int argc, char *argv[]) {
	int port = 10001;
	int n;
	int s;

	if (argc > 1) {
		sscanf(argv[1], "%d", &port);
	}

//	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	SSL_CTX *ssl_ctx = 0;
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
	if (SSL_CTX_use_certificate_file(ssl_ctx, certificate_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1) {
		perror("socket");
		exit(1);
	}
	int cs;
	struct sockaddr_in sa;
	int on;
	on = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = INADDR_ANY;
	bind(s, (struct sockaddr *)&sa, sizeof(sa));
	listen(s, 1);
	printf("accepting on port %d..\n", port);
	while (1) {
		cs = accept(s, NULL, NULL);
		if (cs == -1) {
			perror("accept");
			exit(1);
		}
		SSL *ssl = SSL_new(ssl_ctx);
		if (!ssl) {
			printf("couldn't create server ssl\n");
			exit(1);
		}
		if (!SSL_set_fd(ssl, cs)) {
			printf("failed to SSL set fd\n");
			exit(1);
		}
//		printf("SSL accepting..\n");
		n = SSL_accept(ssl);
		if (n != 1) {
			unsigned long err = ERR_get_error();
			printf("failed to SSL accept (%d, %d) (%ld, %s)\n", n, SSL_get_error(ssl, n), err, ERR_error_string(err, NULL));
			exit(1);
		}
//		printf("ssl initiated\n");
		char buf[1024] = "Hello client\n";
		if ((n = SSL_write(ssl, buf, strlen(buf))) <= 0) {
			printf("failed to SSL write\n");
			exit(1);
		}
		SSL_free(ssl);
		close(cs);
	}

	close(s);
	SSL_CTX_free(ssl_ctx);
	EVP_cleanup();

	return 0;
}
