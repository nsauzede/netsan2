ifneq ($(strip $(shell $(CC) -v 2>&1 | grep "mingw")),)
OS_WIN32=true
endif

TARGET=		netsan

ifdef WIN32
TARGET+= ssl sun ssls sslc
endif

CFLAGS=		-Wall -Werror -O0 -g

ifdef USE32
CFLAGS+=-m32
LDFLAGS+=-m32
endif
ifdef STATIC
LDFLAGS+=-static
endif

ifdef OS_WIN32
LIBYACAPI=	$(USR)
CFLAGS+=	-I$(LIBYACAPI)/include/yacapi/compat
LDFLAGS+=	-L$(LIBYACAPI)/lib -lyacapi -lws2_32
endif

ifdef SSL
CFLAGS+=	-DHAVE_SSL
CFLAGS+=	-DOPENSSL_NO_KRB5
ifdef OS_WIN32
OPENSSL=	/c/OpenSSL
CFLAGS+=	-I$(OPENSSL)/include
LDFLAGS+=	$(OPENSSL)/lib/MinGW/libeay32.a $(OPENSSL)/lib/MinGW/ssleay32.a
else
LDFLAGS+=	-lssl
endif
endif

ifdef DAEMON
CFLAGS+=	-DHAVE_DAEMONIZE
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

