.PHONY: all clean

# use 'make EXTERNFLAGS=...' to specify own compiler flags
# in particular 'make EXTERNFLAGS="-DDEBUG -DCOLOR -g"' to make a debug build

CC = cc
CFLAGS = -std=c99 -D_XOPEN_SOURCE=700 -Wall -Wextra -Wpedantic -I./include
LDFLAGS =

all: mqttserver

mqttserver: src/* include/*
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ src/*.c

clean:
	rm -f mqttserver
