TARGET=		netsan ssl ssls sslc sun

CFLAGS=		-Wall -Werror -O0 -g

ifdef SSL
CFLAGS+=	-DHAVE_SSL
CFLAGS+=	-DOPENSSL_NO_KRB5
endif

ssl:	CFLAGS+=-DOPENSSL_NO_KRB5
ssl:	LDFLAGS+=-lssl

ssls:	CFLAGS+=-DOPENSSL_NO_KRB5
ssls:	LDFLAGS+=-lssl

sslc:	CFLAGS+=-DOPENSSL_NO_KRB5
sslc:	LDFLAGS+=-lssl

all:	$(TARGET)

test.key:
	openssl genrsa > $@

test.csr:	test.key
	openssl req -new -key test.key > $@

test.crt:	test.key test.csr
	openssl x509 -req -days 365 -in test.csr -signkey test.key -out $@

clean:
	$(RM) $(TARGET) *.o

