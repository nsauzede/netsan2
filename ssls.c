#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define key_file 		"test.key"
#define certificate_file 	"test.crt"

int main(int argc, char *argv[]) {
	int port = 10001;
	int n;
	int s;

	if (argc > 1) {
		sscanf(argv[1], "%d", &port);
	}

	SSL_library_init();
	SSL_load_error_strings();

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s != -1) {
		int cs;
		char buf[1024];
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
		while (1) {
			printf("accepting on port %d..\n", port);
			cs = accept(s, NULL, NULL);
			if (cs != -1) {
				SSL *ssl = 0;
				SSL_CTX *ssl_ctx = 0;

				ssl_ctx = SSL_CTX_new(SSLv23_server_method());
				if (ssl_ctx) {
					ssl = SSL_new(ssl_ctx);
					if (ssl) {
						n = SSL_use_PrivateKey_file(ssl, key_file, 1);
						if (n != 1)
							printf("failed to SSL use key (%d, %d)\n", n, SSL_get_error(ssl, n));
						n = SSL_use_certificate_file(ssl, certificate_file, 1);
						if (n != 1)
							printf("failed to SSL use cert (%d, %d)\n", n, SSL_get_error(ssl, n));
						if (SSL_set_fd(ssl, cs)) {
							printf("SSL accepting..\n");
							n = SSL_accept(ssl);
							if (n == 1) {
								printf("ssl initiated\n");
								if ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
									if (n > (sizeof(buf) - 1))
										n = sizeof(buf) - 1;
									buf[n] = 0;
									printf("SSL_read %d bytes [%s]\n", n, buf);
								}
								else
									printf("failed to SSL read\n");
							}
							else {
#ifdef WIN32
								unsigned long err = ERR_get_error();
								printf("failed to SSL accept (%d, %d) (%ld, %s)\n", n, SSL_get_error(ssl, n), err, ERR_error_string(err, NULL));
#else
								printf("failed to SSL accept (%d)\n", n);
#endif
							}
						}
						else
							printf("failed to SSL set fd\n");
						SSL_shutdown(ssl);
					}
					else
						printf("couldn't create server ssl\n");
					SSL_CTX_free(ssl_ctx);
				}
				else
					printf("couldn't create server ctx\n");
				close(cs);
			}
			else
				perror("accept");
		}
	}
	else
		perror("socket");

	return 0;
}
