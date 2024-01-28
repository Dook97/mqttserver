.PHONY: all clean

# use 'make EXTERNFLAGS=...' to specify own compiler flags
# in particular 'make EXTERNFLAGS="-DDEBUG -DCOLOR -g"' to make a debug build

CC = cc
CFLAGS = -std=c99 -D_XOPEN_SOURCE=700 -Wall -Wextra -Wpedantic -I./include
LDFLAGS =

SOURCES = src/main.c src/mqtt.c
HEADERS = include/magic.h include/main.h include/mqtt.h include/vector.h

all: mqttserver

mqttserver: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ $(SOURCES)

clean:
	rm -f mqttserver
