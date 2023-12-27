.PHONY: all clean

CC = cc
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -Wextra -Wpedantic -I./include
LDFLAGS =
# flags set from terminal: make [TARGET] EXTERNFLAGS=...
EXTERNFLAGS = -g

all: mqttserver

mqttserver: src/* include/*
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ src/*.c

clean:
	rm -f mqttserver
