#ifndef MAGIC_H_
#define MAGIC_H_

#include <stdio.h>

#define USER_ERR 1
#define SERVER_ERR 2
#define NO_SOCKET 254
#define NO_MEMORY 255

#define MQTT_DEFAULT_PORT "1883"

// ANSI escape color sequences
#ifdef DEBUG
#define GREEN(str)	"\033[1;32m" str "\033[0m"
#define RED(str)	"\033[1;91m" str "\033[0m"
#define YELLOW(str)	"\033[1;93m" str "\033[0m"
#define MAGENTA(str)	"\033[1;95m" str "\033[0m"
#else
#define GREEN(str)	str
#define RED(str)	str
#define YELLOW(str)	str
#define MAGENTA(str)	str
#endif

// debug macros
#define str(param) xstr(param)
#define xstr(param) #param

#define dprintf(...)                                                                       \
	do {                                                                               \
		fprintf(stderr, "[" MAGENTA("DEBUG") " " __FILE__ ":" str(__LINE__) "] "); \
		fprintf(stderr, __VA_ARGS__);                                              \
	} while (0)

#define derr(errn, ...)                                                              \
	do {                                                                         \
		fprintf(stderr, "[" RED("ERR") " " __FILE__ ":" str(__LINE__) "] "); \
		err(errn, __VA_ARGS__);                                              \
	} while (0)

#define derrx(errn, ...)                                                              \
	do {                                                                          \
		fprintf(stderr, "[" RED("ERRX") " " __FILE__ ":" str(__LINE__) "] "); \
		errx(errn, __VA_ARGS__);                                              \
	} while (0)

#define dwarn(...)                                                                       \
	do {                                                                             \
		fprintf(stderr, "[" YELLOW("WARN") " " __FILE__ ":" str(__LINE__) "] "); \
		warn(__VA_ARGS__);                                                       \
	} while (0)

#define dwarnx(...)                                                                       \
	do {                                                                              \
		fprintf(stderr, "[" YELLOW("WARNX") " " __FILE__ ":" str(__LINE__) "] "); \
		warnx(__VA_ARGS__);                                                       \
	} while (0)

/* server exit code */
extern int server_exit;

#endif
