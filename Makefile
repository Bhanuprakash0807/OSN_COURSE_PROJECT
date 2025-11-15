CC = gcc
CFLAGS = -Wall -Wextra -pthread -g
LDFLAGS = -pthread

# Targets
all: nameserver storageserver client

nameserver: nameserver.o common.o
	$(CC) $(LDFLAGS) -o nameserver nameserver.o common.o

storageserver: storageserver.o common.o
	$(CC) $(LDFLAGS) -o storageserver storageserver.o common.o

client: client.o common.o
	$(CC) $(LDFLAGS) -o client client.o common.o

nameserver.o: nameserver.c common.h
	$(CC) $(CFLAGS) -c nameserver.c

storageserver.o: storageserver.c common.h
	$(CC) $(CFLAGS) -c storageserver.c

client.o: client.c common.h
	$(CC) $(CFLAGS) -c client.c

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c

clean:
	rm -f *.o nameserver storageserver client *.log

.PHONY: all clean