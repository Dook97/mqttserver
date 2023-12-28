#ifndef MAGIC_H_
#define MAGIC_H_

#include <stdio.h>

#define USER_ERR 1
#define SERVER_ERR 2
#define NO_SOCKET 254
#define NO_MEMORY 255

#define MQTT_DEFAULT_PORT "1883"

// ANSI escape color sequences
#define GREEN(str)	"\033[1;32m" str "\033[0m"
#define RED(str)	"\033[1;91m" str "\033[0m"

// debug print macro hackery
#define str(param) xstr(param)
#define xstr(param) #param
#define dprintf(...)                                                                  \
	do {                                                                          \
		fprintf(stderr, "[DEBUG from " __FILE__ " line " str(__LINE__) "] "); \
		fprintf(stderr, __VA_ARGS__);                                         \
	} while (0)

#endif
