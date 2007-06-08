#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

int main()
{
	int p[2];

	if (!socketpair( PF_UNIX, SOCK_STREAM, 0, p))
	{
		char buf[1024];
		int n;

		snprintf( buf, sizeof( buf), "hello sun\n");
		n = write( p[0], buf, strlen( buf));
		printf( "wrote %d bytes\n", n);
		n = read( p[1], buf, sizeof( buf));
		printf( "read %d bytes [%s]\n", n, buf);
	}
	else
		perror( "socketpair");

	return 0;
}

