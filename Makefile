ifneq ($(strip $(shell $(CC) -v 2>&1 | grep "mingw")),)
WIN32=1
endif

TARGET=		netsan.exe

ifndef WIN32
DAEMON=1
endif

ifeq ("$(shell md5sum /usr/include/openssl/ssl.h 2>&1 > /dev/null;echo $$?)","0")
SSL=1
endif

CFLAGS=		-Wall -Werror -O0 -g

ifdef USE32
CFLAGS+=-m32
LDFLAGS+=-m32
endif
ifdef STATIC
LDFLAGS+=-static
endif

ifdef WIN32
YC=$(shell which yacapi-config)
ifneq ("$(YC)","")
CFLAGS+=`$(YC) --compat --cflags`
LDFLAGS+=`$(YC) --static-libs`
endif
endif

ifdef SSL
TARGET+= ssls.exe
TARGET+= sslc.exe
CFLAGS+=	-DHAVE_SSL
CFLAGS+=	-DOPENSSL_NO_KRB5
ifdef WIN32
OPENSSL=	/c/OpenSSL-Win32
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
#ssls:	LDFLAGS+=-lssl

sslc:	CFLAGS+=-DOPENSSL_NO_KRB5
#sslc:	LDFLAGS+=-lssl

%.exe:	%.c
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

clobber: clean
	$(RM) *~
