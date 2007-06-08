#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

int main( int argc, char *argv[])
{
	int port = 10001;
	int n;
	int s;

	if (argc > 1)
	{
		sscanf( argv[1], "%d", &port);
	}

	SSL_library_init();
	SSL_load_error_strings();

	s = socket( PF_INET, SOCK_STREAM, 0);
	if (s != -1)
	{
		struct sockaddr_in sa;
		char *host = "127.0.0.1";

		memset( &sa, 0, sizeof( sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons( port);
		sa.sin_addr.s_addr = inet_addr( host);
		printf( "connecting on port %d..\n", port);
		if (!connect( s, (struct sockaddr *)&sa, sizeof( sa)))
		{
			SSL_CTX *ssl_ctx = 0;
			SSL *ssl = 0;

			ssl_ctx = SSL_CTX_new( SSLv23_client_method());
			if (ssl_ctx)
			{
				ssl = SSL_new( ssl_ctx);
				if (ssl)
				{
					if (SSL_set_fd( ssl, s))
					{
						printf( "SSL connecting..\n");
						n = SSL_connect( ssl);
						if (n == 1)
						{
							char buf[1024];

							printf( "ssl initiated\n");
							n = snprintf( buf, sizeof( buf), "hello ssl\n");
							n = SSL_write( ssl, buf, n);
							printf( "SSL_write %d bytes\n", n);
						}
						else
						{
							unsigned long err = ERR_get_error();
							printf( "failed to SSL connect (%d, %d) (%ld, %s)\n", n, SSL_get_error( ssl, n), err, ERR_error_string( err, NULL));
						}
					}
					else
						printf( "failed to SSL set fd\n");
					SSL_shutdown( ssl);
				}
				else
					printf( "couldn't create server ssl\n");
				SSL_CTX_free( ssl_ctx);
			}
			else
				printf( "couldn't create server ctx\n");
		}
		else
			perror( "connect");
	}
	else
		perror( "socket");

	return 0;
}

