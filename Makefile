#TARGET=	sock std pipe netsan
TARGET=		sock std netsan

CFLAGS=		-Wall -Werror -O0 -g
#LDFLAGS=	-lpthread

all:	$(TARGET)

clean:
	$(RM) $(TARGET) *.o

