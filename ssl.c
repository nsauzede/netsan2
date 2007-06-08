#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

int main()
{
	SSL_CTX *ssl_ctxs = 0, *ssl_ctxc = 0;
	SSL *ssls = 0, *sslc = 0;

	SSL_library_init();

	ssl_ctxs = SSL_CTX_new( SSLv23_server_method());
	if (ssl_ctxs)
	{
		ssls = SSL_new( ssl_ctxs);
		if (ssls)
		{
			ssl_ctxc = SSL_CTX_new( SSLv23_client_method());
			if (ssl_ctxc)
			{
				sslc = SSL_new( ssl_ctxc);
				if (sslc)
				{
					int s[2];

					if (!socketpair( PF_UNIX, SOCK_STREAM, 0, s))
					{
						SSL_set_fd( ssls, s[0]);
						SSL_set_fd( sslc, s[1]);
						printf( "accepting..\n");
						SSL_accept( ssls);
						printf( "connecting..\n");
						SSL_connect( sslc);
						printf( "ssl initiated\n");
					}
					SSL_shutdown( sslc);
				}
				else
					printf( "couldn't create client ssl\n");
				SSL_CTX_free( ssl_ctxc);
			}
			else
				printf( "couldn't create client ctx\n");
			SSL_shutdown( ssls);
		}
		else
			printf( "couldn't create server ssl\n");
		SSL_CTX_free( ssl_ctxs);
	}
	else
		printf( "couldn't create server ctx\n");

	return 0;
}

