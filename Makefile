TARGET=		netsan

CFLAGS=		-Wall -Werror -O0 -g

all:	$(TARGET)

clean:
	$(RM) $(TARGET) *.o

