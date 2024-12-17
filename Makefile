.PHONY: all clean

# use 'make EXTERNFLAGS=...' to specify own compiler flags
# in particular 'make EXTERNFLAGS="-DCOLOR -g"' to make a debug build

CC = cc
CFLAGS = -std=c99 -D_XOPEN_SOURCE=700 -Wall -Wextra -Wpedantic -I./include
LDFLAGS =

SOURCES ::= $(wildcard src/*.c)
HEADERS ::= $(wildcard include/*.h)

all: mqttserver

mqttserver: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ $(SOURCES)

clean:
	rm -f mqttserver
