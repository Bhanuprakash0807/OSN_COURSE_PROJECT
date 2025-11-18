CC := gcc
CFLAGS := -Wall -Wextra -g -I.
LDFLAGS := -pthread

# Directories
CLIENT_DIR := client-files
SERVER_DIR := server-files
STORAGE_DIR := storage-files

# Source lists
CLIENT_SRCS := $(wildcard $(CLIENT_DIR)/*.c)
SERVER_SRCS := $(wildcard $(SERVER_DIR)/*.c)
STORAGE_SRCS := $(wildcard $(STORAGE_DIR)/*.c)

CLIENT_OBJS := $(patsubst %.c,%.o,$(CLIENT_SRCS))
SERVER_OBJS := $(patsubst %.c,%.o,$(SERVER_SRCS))
STORAGE_OBJS := $(patsubst %.c,%.o,$(STORAGE_SRCS))

COMMON_OBJS := common.o

BINS := nameserver storageserver client

.PHONY: all clean

all: $(BINS)

nameserver: $(SERVER_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(COMMON_OBJS)

storageserver: $(STORAGE_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(STORAGE_OBJS) $(COMMON_OBJS)

client: $(CLIENT_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CLIENT_OBJS) $(COMMON_OBJS)

# Generic rule to build .o from .c (preserves directory structure)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(CLIENT_OBJS) $(SERVER_OBJS) $(STORAGE_OBJS) $(COMMON_OBJS) $(BINS)

# End of Makefile