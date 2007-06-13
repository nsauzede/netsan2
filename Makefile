ifneq ($(strip $(shell $(CC) -v 2>&1 | grep "mingw")),)
OS_WIN32=true
endif

TARGET=		netsan

ifdef WIN32
TARGET+= ssl sun ssls sslc
endif

CFLAGS=		-Wall -Werror -O0 -g

ifdef OS_WIN32
LIBYACAPI=	/home/sauzeden/tmp/build-libyacapi/install
CFLAGS+=	-I$(LIBYACAPI)/include/compat
LDFLAGS+=	-L$(LIBYACAPI)/lib -lyacapi -lws2_32
endif

ifdef SSL
CFLAGS+=	-DHAVE_SSL
CFLAGS+=	-DOPENSSL_NO_KRB5
LDFLAGS+=	-lssl
endif

ssl:	CFLAGS+=-DOPENSSL_NO_KRB5
ssl:	LDFLAGS+=-lssl

ssls:	CFLAGS+=-DOPENSSL_NO_KRB5
ssls:	LDFLAGS+=-lssl

sslc:	CFLAGS+=-DOPENSSL_NO_KRB5
sslc:	LDFLAGS+=-lssl

netsan:	netsan.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

%:	%.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

all:	$(TARGET)

test.key:
	openssl genrsa > $@

test.csr:	test.key
	openssl req -new -key test.key > $@

test.crt:	test.key test.csr
	openssl x509 -req -days 365 -in test.csr -signkey test.key -out $@

clean:
	$(RM) $(TARGET) *.o

