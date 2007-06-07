TARGET=		netsan

CFLAGS=		-Wall -Werror -O0 -g

ifdef SSL
CFLAGS+=	-DHAVE_SSL
CFLAGS+=	-DOPENSSL_NO_KRB5
endif

all:	$(TARGET)

clean:
	$(RM) $(TARGET) *.o

