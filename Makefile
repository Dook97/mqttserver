.PHONY: all clean

CC = cc
CFLAGS = -g -std=c99 -Wall -Wextra -Wpedantic -I./include
LDFLAGS =

all: mqttserver

mqttserver: src/*.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ src/*.c
