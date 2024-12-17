/* misc and helper stuffz */

#ifndef MAGIC_H_
#define MAGIC_H_

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) (((a) <= (b)) ? (a) : (b))
#define MAX(a, b) (((a) >= (b)) ? (a) : (b))

#define ARR_LEN(arr) (sizeof((arr)) / sizeof((arr)[0]))

/* ANSI color escape sequences */
#ifdef COLOR
#define GREEN(str)      "\033[1;32m" str "\033[0m"
#define RED(str)        "\033[1;91m" str "\033[0m"
#define YELLOW(str)     "\033[1;93m" str "\033[0m"
#define MAGENTA(str)    "\033[1;95m" str "\033[0m"
#else
#define GREEN(str)      str
#define RED(str)        str
#define YELLOW(str)     str
#define MAGENTA(str)    str
#endif

#ifndef NDEBUG
#define DPRINTF(...)                                                                    \
	do {                                                                            \
		fprintf(stderr, "[" MAGENTA("DEBUG") " " __FILE__ ":%-3d] ", __LINE__); \
		fprintf(stderr, __VA_ARGS__);                                           \
	} while (0)
#else
#define DPRINTF(...) do { } while (0)
#endif

#define derr(errn, ...)                                                             \
	do {                                                                        \
		fprintf(stderr, "[" RED("ERR  ") " " __FILE__ ":%-3d] ", __LINE__); \
		err(errn, __VA_ARGS__);                                             \
	} while (0)

#define derrx(errn, ...)                                                            \
	do {                                                                        \
		fprintf(stderr, "[" RED("ERRX ") " " __FILE__ ":%-3d] ", __LINE__); \
		errx(errn, __VA_ARGS__);                                            \
	} while (0)

#define dwarn(...)                                                                     \
	do {                                                                           \
		fprintf(stderr, "[" YELLOW("WARN ") " " __FILE__ ":%-3d] ", __LINE__); \
		warn(__VA_ARGS__);                                                     \
	} while (0)

#define dwarnx(...)                                                                    \
	do {                                                                           \
		fprintf(stderr, "[" YELLOW("WARNX") " " __FILE__ ":%-3d] ", __LINE__); \
		warnx(__VA_ARGS__);                                                    \
	} while (0)

/* Thin wrapper around realloc which calls derr() on allocation failure. */
static inline void *xrealloc(void *ptr, size_t size) {
	void *ret = realloc(ptr, size);
	if (ret == NULL)
		derr(ENOMEM, "xrealloc: failed allocating %zuB", size);
	return ret;
}

/* Thin wrapper around malloc which calls derr() on allocation failure. */
static inline void *xmalloc(size_t size) {
	return xrealloc(NULL, size);
}

/* Write a human readable IPv4 or IPv6 address and port to buffer */
static inline char *print_inaddr(size_t bufsize, char *dest, struct sockaddr addr[static 1], socklen_t addrlen) {
	char stripaddr[INET6_ADDRSTRLEN];
	char strport[6]; // max port number is 65535, so 5 chars + null terminator
	getnameinfo(addr, addrlen, stripaddr, sizeof(stripaddr), strport, sizeof(strport),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(dest, bufsize, addr->sa_family == AF_INET6 ? "[%s]:%s" : "%s:%s", stripaddr, strport);
	return dest;
}

/*!
 * Compare a null terminated string with a non-null terminated memory buffer. buf mustn't contain a
 * '\0', otherwise uninitialized memory access may occur.
 *
 * @param buflen nbytes of data available in buf
 * @param str the string
 * @param buf the buffer
 * @returns true when equal false when not
 */
static inline bool strmemeq(size_t buflen, const char *str, const char buf[static buflen]) {
	return !strncmp(str, buf, buflen) && str[buflen] == 0;
}

/*!
 * Read a 2B big-endian unsigned integer from buffer buf.
 *
 * @param buf Read buffer.
 * @return The read integer.
 */
static inline uint16_t read_BE_16b(const uint8_t buf[static 2]) {
	return ((uint16_t)buf[0] << 8) + (uint16_t)buf[1];
}

#endif
