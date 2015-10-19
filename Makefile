CC=clang
LDFLAGS=-Lopenssl/ -lssl -lcrypto
CFLAGS= -std=c11 -I. -Iopenssl/build/include -c
SRCS := net_utils.c ssl_comm.c ssl_client.c ssl_server.c main.c
OBJS=$(SRCS:.c=.o)
TARGET=ssltest

all: $(SRCS) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET) *.o
	
