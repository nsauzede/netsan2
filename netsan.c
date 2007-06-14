#include <stdio.h>
#include <sys/types.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define ARG_TUN		"-t"
#ifdef HAVE_SSL
#define ARG_SSL		"-s"
#endif
#define ARG_PROX	"-p"
#define ARG_AUTH	"-a"
#define ARG_VERBOSE	"-v"

#define MAX_TH	1024

enum { VERBOSE_NONE, VERBOSE_INFO, VERBOSE_DEBUG };

void asciify( char *ptr, int n)
{
	while (n > 0)
	{
		if ((*ptr < ' ') && (*ptr != '\t') && (*ptr != '\r') && (*ptr != '\n'))
			*ptr = '.';
		 ptr++;
		 n--;
	}
	*ptr = 0;
}

int isdignum( const char *str)
{
    int result = 0;
    char *endptr;
    long val;

    errno = 0;
    val = strtol( str, &endptr, 10);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
      || (errno != 0 && val == 0))
        printf( "%s: error somewhere\n", __func__);
    else
        if (endptr != str)
            if (*endptr == '\0')
                result = 1;
   
    return result;
}

int main( int argc, char *argv[])
{
	int tunnels = 0;
	int tunnelc = 0;
	int proxy = 0;
#ifdef HAVE_SSL
	int use_ssls = 0;
	int use_sslc = 0;
	char *key = NULL;
	char *cert = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
#endif
	int lp = 0;
	char *rh = NULL;
	int rp = 0;
	char *th = NULL;
	int tp = 0;
	char *ph = NULL;
	int pp = 0;
	char *auth = NULL;
	int err = 1;
	char *prog = basename( argv[0]);
//	char *prog = argv[0];
	int arg = 1;
//	int verbose = VERBOSE_NONE;
	int verbose = VERBOSE_INFO;

	int ls = 0, rs = 0, cs = 0;
	struct sockaddr_in sa;
	int on;
	struct hostent *he;

	while (arg < argc)
	{
		if (isdignum( argv[arg]))
		{
			if (lp != 0)
			{
				printf( "*** only one lp authorized\n");
				goto err;
			}
			if (sscanf( argv[arg], "%d", &lp) != 1)
			{
				printf( "*** bad lp\n");
				goto err;
			}
			arg++;
		}
		else if (argv[arg][0] != '-')
		{
			if (rh)
			{
				printf( "*** only one rh authorized\n");
				goto err;
			}
			rh = argv[arg++];
			if (arg < argc)
			{
				if (isdignum( argv[arg]))
				{
					if (sscanf( argv[arg], "%d", &rp) != 1)
					{
						printf( "*** bad rp\n");
						goto err;
					}
					arg++;
				}
				else if (!lp)
				{
					printf( "*** missing rp\n");
					goto err;
				}
			}
			else if (!lp)
			{
				printf( "*** missing rp\n");
				goto err;
			}
		}
		else	// options beginning by '-'
		{
			if (!strcmp( argv[arg], ARG_VERBOSE))
			{
				arg++;
				verbose++;
			}
#ifdef HAVE_SSL
			else if (!strcmp( argv[arg], ARG_SSL))
			{
				arg++;
				if (lp && !rh)
				{
					if (arg < argc)
					{
						key = argv[arg++];
						if (arg < argc)
						{
							cert = argv[arg++];
							use_ssls = 1;
						}
						else
						{
							printf( "*** missing cert\n");
							goto err;
						}
					}
					else
					{
						printf( "*** missing key\n");
						goto err;
					}
				}
				else if (rh)
				{
					use_sslc = 1;
				}
				else
				{
					printf( "*** ssl arg needs lp and/or rh\n");
					goto err;
				}
			}
#endif
			else if (!strcmp( argv[arg], ARG_TUN))
			{
				arg++;
				if (rh)
				{
					tunnelc = 1;
					if (arg < argc)
					{
						th = argv[arg++];
						if (arg < argc)
						{
							if (sscanf( argv[arg], "%d", &tp) != 1 || !isdignum( argv[arg]))
							{
								printf( "*** bad tp\n");
								goto err;
							}
							arg++;
						}
						else
						{
							printf( "*** missing tp\n");
							goto err;
						}
					}
					else
					{
						printf( "*** missing th\n");
						goto err;
					}
				}
				if (lp)
				{
					tunnels = 1;
				}
				else
				{
					printf( "*** needs lp and/or rh\n");
					goto err;
				}
			}
			else if (!strcmp( argv[arg], ARG_PROX))
			{
				arg++;
				proxy = 1;
				if (arg < argc)
				{
					ph = argv[arg++];
					if (arg < argc)
					{
						if (sscanf( argv[arg], "%d", &pp) != 1 || !isdignum( argv[arg]))
						{
							printf( "*** bad pp\n");
							goto err;
						}
						arg++;
					}
					else
					{
						printf( "*** missing pp\n");
						goto err;
					}
				}
				else
				{
					printf( "*** missing ph\n");
					goto err;
				}
			}
			else if (!strcmp( argv[arg], ARG_AUTH))
			{
				arg++;
				if (arg < argc)
				{
					auth = argv[arg++];
				}
				else
				{
					printf( "*** missing auth\n");
					goto err;
				}
			}
			else
			{
				printf( "*** unknown option : '%s'\n", argv[arg]);
				goto err;
			}
		}
	}
	if (verbose >= VERBOSE_DEBUG)
#ifdef HAVE_SSL
	printf( "got lp=%d ssls=%d key=%s cert=%s tunnels=%d rh=%s rp=%d sslc=%d tunnelc=%d th=%s tp=%d proxy=%d ph=%s pp=%d auth=%s\n", lp, use_ssls, key, cert, tunnels, rh, rp, use_sslc, tunnelc, th, tp, proxy, ph, pp, auth);
#else
	printf( "got lp=%d tunnels=%d rh=%s rp=%d tunnelc=%d th=%s tp=%d proxy=%d ph=%s pp=%d auth=%s\n", lp, tunnels, rh, rp, tunnelc, th, tp, proxy, ph, pp, auth);
#endif

#ifdef HAVE_SSL
	if (use_ssls || use_sslc)
	{
		SSL_library_init();
		SSL_load_error_strings();
		if (verbose >= VERBOSE_DEBUG)
		printf( ">>>SSL inited\n");
	}
#endif

	if (!lp)
	{
		if (rh && rp)
		{
			rs = socket( PF_INET, SOCK_STREAM, 0);
			memset( &sa, 0, sizeof( sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons( rp);
			he = gethostbyname( rh);
			if (he)
				memcpy( &sa.sin_addr.s_addr, he->h_addr, sizeof( sa.sin_addr.s_addr));
			else
				sa.sin_addr.s_addr = inet_addr( rh);
			if (!connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
			{
//				if (verbose >= VERBOSE_INFO)
				printf( "{client mode rh=%s rp=%d}\n", rh, rp);
				err = 0;
			}
			else
			{
				perror( "connect");
				return 123;
			}
		}
	}
	else
	{
//		if (verbose >= VERBOSE_INFO)
		printf( "{server mode lp=%d}\n", lp);
		err = 0;
	}
	if (!err)
	{
	while (1)
	{
		fd_set rfds;
		int max = 0;
		int n;
		char buf[1024];
		int in = -1, out = 0;

		static int count = 0;

		if (count++ > 10)
		{
//			printf( "+++++watchdog\n");
//			break;
		}

		if (!ls && lp)			// create local server
		{
			if (verbose >= VERBOSE_DEBUG)
			printf( "||||creating local server\n");
			ls = socket( PF_INET, SOCK_STREAM, 0);
			on = 1;
			setsockopt( ls, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof( on));
			memset( &sa, 0, sizeof( sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons( lp);
			sa.sin_addr.s_addr = INADDR_ANY;
			if (bind( ls, (struct sockaddr *)&sa, sizeof( sa)))
			{
				perror( "bind");
				break;
			}
			listen( ls, 1);
		}

		FD_ZERO( &rfds);
		FD_SET( 0, &rfds);
		if (verbose >= VERBOSE_DEBUG)
		printf( "[select : 0");
		if (ls)
		{
			if (verbose >= VERBOSE_DEBUG)
			printf( " ls");
			FD_SET( ls, &rfds);
			if (ls > max)
				max = ls;
		}
		if (rs)
		{
			if (verbose >= VERBOSE_DEBUG)
			printf( " rs");
			FD_SET( rs, &rfds);
			if (rs > max)
				max = rs;
		}
		if (cs)
		{
			if (verbose >= VERBOSE_DEBUG)
			printf( " cs");
			FD_SET( cs, &rfds);
			if (cs > max)
				max = cs;
		}
		if (verbose >= VERBOSE_DEBUG)
		printf( " ]\n");
		max++;
		n = select( max, &rfds, NULL, NULL, NULL);
		if (n < 0)
		{
			perror( "select");
			break;
		}
		else if (!n)
		{
			printf( "select returned 0 ?\n");
			break;
//			continue;
		}
		if (FD_ISSET( 0, &rfds))
		{
			in = 0;
			if (cs && !rs)
				out = cs;
			else if (!cs && rs)
				out = rs;
		}
		else if (ls && FD_ISSET( ls, &rfds))
		{
			if (verbose >= VERBOSE_DEBUG)
			printf( "--- sg to read in ls\n");
			if (!cs)
			{
				if (rh)
				{
					if (!rs)
					{
						if (verbose >= VERBOSE_DEBUG)
						printf( "trying to connect rs to %s:%d\n", rh, rp);
						rs = socket( PF_INET, SOCK_STREAM, 0);
						memset( &sa, 0, sizeof( sa));
						sa.sin_family = AF_INET;
						sa.sin_port = htons( rp);
						he = gethostbyname( rh);
						if (he)
							memcpy( &sa.sin_addr.s_addr, he->h_addr, sizeof( sa.sin_addr.s_addr));
						else
							sa.sin_addr.s_addr = inet_addr( rh);
						if (connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
						{
							perror( "connect");
							close( rs);
							rs = 0;
							if (verbose >= VERBOSE_DEBUG)
							printf( "closed remote\n");
						}
#ifdef HAVE_SSL
						else if (use_sslc && rh)
						{
							int ok = 0;

							ssl_ctx = SSL_CTX_new( SSLv23_client_method());
							if (ssl_ctx)
							{
								if (verbose >= VERBOSE_DEBUG)
								printf( ">>>SSL CTX created\n");
								ssl = SSL_new( ssl_ctx);
								if (ssl)
								{
									if (verbose >= VERBOSE_DEBUG)
									printf( ">>>SSL created\n");
									if (SSL_set_fd( ssl, rs))
									{
										if (verbose >= VERBOSE_DEBUG)
										printf( ">>>SSL fd set\n");
										n = SSL_connect( ssl);
										if (verbose >= VERBOSE_DEBUG)
										printf( ">>>SSL connect returned %d\n", n);
										if (n == 1)
										{
											if (verbose >= VERBOSE_DEBUG)
											printf( ">>>SSL connected\n");
											ok = 1;
										}
										else
										{
											unsigned long err = ERR_get_error();
											printf( ">>>SSL err : %d,%d %lu,%s\n", n, SSL_get_error( ssl, n), err, ERR_error_string( err, NULL));
										}
									}
								}
							}
							if (!ok)
							{
								if (ssl)
								{
									SSL_shutdown( ssl);
									ssl = NULL;
									if (verbose >= VERBOSE_DEBUG)
									printf( ">>>SSL shutdown\n");
								}
								if (ssl_ctx)
								{
									SSL_CTX_free( ssl_ctx);
									ssl_ctx = NULL;
									if (verbose >= VERBOSE_DEBUG)
									printf( ">>>SSL CTX freed\n");
								}
								if (rs)
								{
									close( rs);
									rs = 0;
								}
							}
						}
#endif
						if (rs)
						{
							if (tunnelc && th)
							{
								n = snprintf( buf, sizeof( buf), "CONNECT %s %d\n", th, tp);
								if (n <= 0)
								{
									perror( "snprintf");
									break;
								}
#ifdef HAVE_SSL
								if (ssl)
								{
									if (verbose >= VERBOSE_DEBUG)
									printf( ">>>SSL about to write\n");
									n = SSL_write( ssl, buf, n);
								}
								else
#endif
								{
								if (verbose >= VERBOSE_DEBUG)
								printf( "about to write..\n");
								n = write( rs, buf, n);
								}
							}
						}
					}
				}

				if (rh && !rs)
				{
					close( ls);
					ls = 0;
					if (verbose >= VERBOSE_DEBUG)
					printf( "|||closed local\n");
				}
				else
				{
					if (verbose >= VERBOSE_DEBUG)
					printf( "accepting cs..\n");
					cs = accept( ls, NULL, NULL);
					if (cs == -1)
					{
						perror( "accept");
						break;
					}
#ifdef HAVE_SSL
					if (use_ssls && !rh)
					{
						int ok = 0;

						ssl_ctx = SSL_CTX_new( SSLv23_server_method());
						if (ssl_ctx)
						{
							ssl = SSL_new( ssl_ctx);
							if (ssl)
							{
								n = SSL_use_PrivateKey_file( ssl, key, 1);
								if (verbose >= VERBOSE_DEBUG)
								printf( ">>>SSL use key returned %d\n", n);
								n = SSL_use_certificate_file( ssl, cert, 1);
								if (verbose >= VERBOSE_DEBUG)
								printf( ">>>SSL use cert returned %d\n", n);
								if (SSL_set_fd( ssl, cs))
								{
									n = SSL_accept( ssl);
									if (verbose >= VERBOSE_DEBUG)
									printf( ">>>SSL accept returned %d\n", n);
									if (n == 1)
										ok = 1;
									else
									{
										unsigned long err = ERR_get_error();

										printf( ">>>SSL err : %d,%d %lu,%s\n", n, SSL_get_error( ssl, n), err, ERR_error_string( err, NULL));
									}
								}
							}
						}
						if (!ok)
						{
							if (ssl)
							{
								SSL_shutdown( ssl);
								ssl = NULL;
								if (verbose >= VERBOSE_DEBUG)
								printf( ">>>SSL shutdown\n");
							}
							if (ssl_ctx)
							{
								SSL_CTX_free( ssl_ctx);
								ssl_ctx = NULL;
								if (verbose >= VERBOSE_DEBUG)
								printf( ">>>SSL CTX free\n");
							}
							if (cs)
							{
								close( cs);
								cs = 0;
								if (verbose >= VERBOSE_DEBUG)
								printf( "closed client\n");
							}
						}
						else
						{
							printf( "[accepted client]\n");
						}
					}
					else
					{
						printf( "[accepted client]\n");
					}
#endif
				}
			}
		}
		else if (rs && FD_ISSET( rs, &rfds))
        {
			if (verbose >= VERBOSE_DEBUG)
			printf( "--- sg to read in rs\n");
            in = rs;
            if (cs)
                out = cs;
        }
		else if (cs && FD_ISSET( cs, &rfds))
        {
			if (verbose >= VERBOSE_DEBUG)
			printf( "--- sg to read in cs\n");
            in = cs;
            if (rs)
                out = rs;
        }
		if (in >= 0)
		{
#ifdef HAVE_SSL
			if (ssl && (((in == rs) && rh) || ((in == cs) && !rh)))
			{
				if (verbose >= VERBOSE_DEBUG)
				printf( ">>>SSL about to read\n");
				n = SSL_read( ssl, buf, sizeof( buf));
				if (verbose >= VERBOSE_DEBUG)
				printf( ">>>SSL read returned %d\n", n);
				if (n < 0)		// read error
				{
					unsigned long err = ERR_get_error();

					printf( ">>>SSL***%d,%d %lu,%s\n", n, SSL_get_error( ssl, n), err, ERR_error_string( err, NULL));
					break;
				}
			}
			else
#endif
			{
				if (verbose >= VERBOSE_DEBUG)
				printf( "about to read..\n");
				n = read( in, buf, sizeof( buf));
				if (n < 0)		// read error
				{
					perror( "read");
					break;
				}
			}
			if (!n)	// remote closed
			{
				if (in && (in == rs))
				{
#ifdef HAVE_SSL
					if (ssl)
					{
						SSL_shutdown( ssl);
						ssl = 0;
						SSL_CTX_free( ssl_ctx);
						ssl_ctx = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( ">>>SSL closed\n");
					}
#endif
					close( rs);
					rs = 0;
					if (verbose >= VERBOSE_DEBUG)
					printf( "closed remote\n");
					if (cs)
					{
						close( cs);
						cs = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( "closed client\n");
					}
					else
					{
//						if (verbose >= VERBOSE_DEBUG)
						printf( "[server left]\n");
						break;
					}
				}
				else if (in && (in == cs))
				{
#ifdef HAVE_SSL
					if (ssl)
					{
						SSL_shutdown( ssl);
						ssl = 0;
						SSL_CTX_free( ssl_ctx);
						ssl_ctx = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( ">>>SSL closed\n");
					}
#endif
					if (rs)
					{
						close( rs);
						rs = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( "closed server\n");
					}
					close( cs);
					cs = 0;
//					if (verbose >= VERBOSE_DEBUG)
					printf( "[client left]\n");
				}
				else			// user hit ctrl-d
				{
					int must_break = 0;

					if (!cs)
						must_break = 1;
					if (cs)		// disc client
					{
#ifdef HAVE_SSL
						if (ssl && !rh)
						{
							SSL_shutdown( ssl);
							ssl = 0;
							SSL_CTX_free( ssl_ctx);
							ssl_ctx = 0;
							if (verbose >= VERBOSE_DEBUG)
							printf( ">>>SSL closed\n");
						}
#endif
						close( cs);
						cs = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( "closed client\n");
					}
					if (rs)		// disc server
					{
#ifdef HAVE_SSL
						if (ssl && rh)
						{
							SSL_shutdown( ssl);
							ssl = 0;
							SSL_CTX_free( ssl_ctx);
							ssl_ctx = 0;
							if (verbose >= VERBOSE_DEBUG)
							printf( ">>>SSL closed\n");
						}
#endif
						close( rs);
						rs = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( "closed remote\n");
					}
					if (must_break)
						break;	// terminate
				}
			}
			else			// valid data to read
			{
				if (tunnelc && !rs)
				{
					char host[MAX_TH];
					int ok = 0;
						
					if (2 == sscanf( buf, "CONNECT %s %d\n", host, &tp))
					{
						if (verbose >= VERBOSE_DEBUG)
						printf( "+++tunnel about to connect rs to %s:%d\n", host, tp);
						rs = socket( PF_INET, SOCK_STREAM, 0);
						memset( &sa, 0, sizeof( sa));
						sa.sin_family = AF_INET;
						sa.sin_port = htons( tp);
						he = gethostbyname( host);
						if (he)
							memcpy( &sa.sin_addr.s_addr, he->h_addr, sizeof( sa.sin_addr.s_addr));
						else
							sa.sin_addr.s_addr = inet_addr( host);
						if (!connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
						{
							int size;
							char *ptr;

							ptr = strchr( buf, '\n');
							if (ptr)
							{
								size = n - ((long)ptr + 1 - (long)buf);
								memcpy( buf, ptr + 1, size);
								n = size;
							}
							out = rs;
							ok = 1;
						}
						else
						{
							perror( "connect");
						}
					}
					if (!ok)
					{
						if (rs)
						{
							close( rs);
							rs = 0;
							if (verbose >= VERBOSE_DEBUG)
							printf( "closed remote\n");
						}
						close( cs);
						cs = 0;
						if (verbose >= VERBOSE_DEBUG)
						printf( "closed client\n");
						if (verbose >= VERBOSE_DEBUG)
						printf( "<demux failed>\n");
					}
				}
				if (out)
				{
#ifdef HAVE_SSL
					if (ssl && (((out == rs) && rh) ||((out == cs) && !rh)))
					{
						if (verbose >= VERBOSE_DEBUG)
						printf( ">>>SSL about to write\n");
						SSL_write( ssl, buf, n);
					}
					else
#endif
					{
					if (verbose >= VERBOSE_DEBUG)
					printf( "about to write...\n");
					write( out, buf, n);
					}
				}
				if (in)
				{
					if (n > (sizeof( buf) - 1))
						n = sizeof( buf) - 1;
					asciify( buf, n);
#if 0
					printf( "%d bytes [%s]\n", n, buf);
#else
					printf( "%s", buf);
#endif
				}
			}
		}
	}
err:

	if (verbose >= VERBOSE_DEBUG)
	printf( "[close :");
	if (ls)
	{
		close( ls);
		if (verbose >= VERBOSE_DEBUG)
		printf( " ls");
	}
	if (rs)
	{
		close( rs);
		if (verbose >= VERBOSE_DEBUG)
		printf( " rs");
	}
	if (cs)
	{
		close( cs);
		if (verbose >= VERBOSE_DEBUG)
		printf( " cs");
	}
	if (verbose >= VERBOSE_DEBUG)
	printf( " ]\n");

	}
	else
	{
		printf( "Usage :\n");
#ifdef HAVE_SSL
		printf( " %s rh rp [%s] [%s th tp] [%s ph pp [%s auth]]\n", prog, ARG_SSL, ARG_TUN, ARG_PROX, ARG_AUTH);
		printf( " %s lp [%s key cert] [%s] [rh [rp] [%s] [%s th tp] [%s ph pp [%s auth]]]\n", prog, ARG_SSL, ARG_TUN, ARG_SSL, ARG_TUN, ARG_PROX, ARG_AUTH);
#else
		printf( " %s rh rp [%s th tp] [%s ph pp [%s auth]]\n", prog, ARG_TUN, ARG_PROX, ARG_AUTH);
		printf( " %s lp [%s] [rh [rp] [%s th tp] [%s ph pp [%s auth]]]\n", prog, ARG_TUN, ARG_TUN, ARG_PROX, ARG_AUTH);
#endif
	}

	return 0;
}

