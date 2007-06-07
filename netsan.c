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

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif

#define ARG_TUN	"-t"
#define ARG_SSL	"-s"

#define MAX_TH	1024

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
	int tunnel = 0;
#ifdef HAVE_SSL
	int ssl = 0;
#endif
	int lp = 0;
	char *rh = NULL;
	int rp = 0;
	char *th = NULL;
	int tp = 0;
	int err = 1;
//	char *prog = basename( argv[0]);
	char *prog = argv[0];
	int arg = 1;

	int ls = 0, rs = 0, cs = 0;
	struct sockaddr_in sa;
	int on;

	if (arg < argc)
	{
		if (isdignum( argv[arg]))
		{
			if (sscanf( argv[arg], "%d", &lp) != 1)
			{
				printf( "*** bad lp\n");
				goto err;
			}
			arg++;
			while (arg < argc)
			{
#ifdef HAVE_SSL
				if (!strcmp( argv[arg], ARG_SSL))
				{
					arg++;
					if (tunnel)
						ssl = 1;
					else
					{
						printf( "*** ssl available only with tunnel\n");
						goto err;
					}
				}
				else
#endif
				if (!strcmp( argv[arg], ARG_TUN))
				{
					arg++;
					tunnel = 1;
					if (rh)
					{
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
				}
				else
				{
					rh = argv[arg++];
					if (arg < argc)
					{
						if (sscanf( argv[arg], "%d", &rp) != 1 || !isdignum( argv[arg]))
						{
							printf( "*** bad rp\n");
							goto err;
						}
						arg++;
					}
					else
						rp = lp;
				}
			}
		}
		else
		{
			rh = argv[arg++];
			if (arg < argc)
			{
				if (sscanf( argv[arg], "%d", &rp) != 1 || !isdignum( argv[arg]))
				{
					printf( "*** bad rp\n");
					goto err;
				}
				arg++;
			}
			else
			{
				printf( "*** missing rp\n");
				goto err;
			}
		}
	}
//	printf( "got lp=%d rh=%s rp=%d tunnel=%d th=%s tp=%d\n", lp, rh, rp, tunnel, th, tp);

	if (!lp)
	{
		if (rh && rp && !tunnel)
		{
			rs = socket( PF_INET, SOCK_STREAM, 0);
			memset( &sa, 0, sizeof( sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons( rp);
			sa.sin_addr.s_addr = inet_addr( rh);
			if (!connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
			{
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
			goto err;
		}
		listen( ls, 1);
		if (rh && rp && (!tunnel || (tunnel && th && tp)))
		{
			if (!tunnel)
			{
				printf( "{proxy mode lp=%d rh=%s rp=%d}\n", lp, rh, rp);
				err = 0;
			}
			else if (th && tp)
			{
				printf( "{mux mode lp=%d rh=%s rp=%d %stunnelling to th=%s tp=%d}\n", lp, rh, rp,
#ifdef HAVE_SSL
				ssl ? "ssl/" :
#endif
				"", th, tp);
				err = 0;
			}
		}
		else if (!tunnel || (tunnel && !th && !tp))
		{
			if (!tunnel)
			{
				printf( "{server mode lp=%d}\n", lp);
				err = 0;
			}
			else if (!th && !tp)
			{
				printf( "{demux mode lp=%d, %stunnelling}\n", lp,
#ifdef HAVE_SSL
				ssl ? "ssl/" :
#endif
				"");
				err = 0;
			}
		}
	}
	if (!err)
	while (1)
	{
		fd_set rfds;
		int max = 0;
		int n;
		char buf[1024];
		int in = -1, out = 0;

		FD_ZERO( &rfds);
		FD_SET( 0, &rfds);
		printf( "[select : 0");
		if (ls)
		{
			printf( " ls");
			FD_SET( ls, &rfds);
			if (ls > max)
				max = ls;
		}
		if (rs)
		{
			printf( " rs");
			FD_SET( rs, &rfds);
			if (rs > max)
				max = rs;
		}
		if (cs)
		{
			printf( " cs");
			FD_SET( cs, &rfds);
			if (cs > max)
				max = cs;
		}
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
			if (!cs)
			{
				cs = accept( ls, NULL, NULL);
				if (cs == -1)
				{
					perror( "accept");
					break;
				}
				if (rh)
				{
					if (!rs)
					{
						rs = socket( PF_INET, SOCK_STREAM, 0);
						memset( &sa, 0, sizeof( sa));
						sa.sin_family = AF_INET;
						sa.sin_port = htons( rp);
						sa.sin_addr.s_addr = inet_addr( rh);
						if (connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
						{
							perror( "connect");
							break;
						}
						else if (tunnel && th)
						{
							n = snprintf( buf, sizeof( buf), "CONNECT %s %d\n", th, tp);
							if (n <= 0)
							{
								perror( "snprintf");
								break;
							}
							n = write( rs, buf, n);
						}
					}
				}
			}
		}
		else if (rs && FD_ISSET( rs, &rfds))
        {
            in = rs;
            if (cs)
                out = cs;
        }
		else if (cs && FD_ISSET( cs, &rfds))
        {
            in = cs;
            if (rs)
                out = rs;
        }
		if (in >= 0)
		{
			n = read( in, buf, sizeof( buf));
			if (n < 0)		// read error
			{
				perror( "read");
				break;
			}
			else if (!n)	// remote closed
			{
				if (in && (in == rs))
				{
					close( rs);
					rs = 0;
					if (cs)
					{
						close( cs);
						cs = 0;
						printf( "closed client\n");
					}
					else
					{
						printf( "server left\n");
						break;
					}
				}
				else if (in && (in == cs))
				{
					if (rs)
					{
						close( rs);
						rs = 0;
						printf( "closed server\n");
					}
					close( cs);
					cs = 0;
					printf( "client left\n");
				}
				else			// user hit ctrl-d
				{
					int must_break = 0;

					if (!cs)
						must_break = 1;
					if (cs)		// disc client
					{
						close( cs);
						cs = 0;
					}
					if (rs)		// disc server
					{
						close( rs);
						rs = 0;
					}
					if (must_break)
						break;	// terminate
				}
			}
			else			// valid data to read
			{
				if (tunnel && !rs)
				{
					char host[MAX_TH];
					int ok = 0;
						
					if (2 == sscanf( buf, "CONNECT %s %d\n", host, &tp))
					{
						rs = socket( PF_INET, SOCK_STREAM, 0);
						memset( &sa, 0, sizeof( sa));
						sa.sin_family = AF_INET;
						sa.sin_port = htons( tp);
						sa.sin_addr.s_addr = inet_addr( host);
						if (!connect( rs, (struct sockaddr *)&sa, sizeof( sa)))
						{
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
						close( cs);
						cs = 0;
						printf( "<demux failed>\n");
					}
				}
				if (out)
				{
					write( out, buf, n);
				}
				if (in)
				{
					if (n > (sizeof( buf) - 1))
						n = sizeof( buf) - 1;
					buf[n] = 0;
//					printf( "%d bytes [%s]\n", n, buf);
					printf( "%s", buf);
				}
			}
		}
	}
	else
	{
		printf( "Usage :\n");
		printf( "        %s rh rp\t\t\tclient: connect to rh:rp\n", prog);
		printf( "        %s lp\t\t\tserver: listen on lp\n", prog);
		printf( "        %s lp rh rp\t\tproxy: bridge lp to rh:rp\n", prog);
#ifdef HAVE_SSL
		printf( "        %s lp %s [%s]\t\tmux: demux lp to th:tp\n", prog, ARG_TUN, ARG_SSL);
		printf( "        %s lp rh rp %s th tp [%s]\tmux: mux th:tp from lp to rh:rp\n", prog, ARG_TUN, ARG_SSL);
#else
		printf( "        %s lp %s\t\t\tmux: demux lp to th:tp\n", prog, ARG_TUN);
		printf( "        %s lp rh rp %s th tp\tmux: mux th:tp from lp to rh:rp\n", prog, ARG_TUN);
#endif
	}

err:

	printf( "[close :");
	if (ls)
	{
		close( ls);
		printf( " ls");
	}
	if (rs)
	{
		close( rs);
		printf( " rs");
	}
	if (cs)
	{
		close( cs);
		printf( " cs");
	}
	printf( " ]\n");

	return 0;
}

