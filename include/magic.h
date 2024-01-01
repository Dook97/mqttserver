#ifndef MAGIC_H_
#define MAGIC_H_

#include <stdio.h>
#include <err.h>

#define USER_ERR 1
#define SERVER_ERR 2
#define NO_SOCKET 126
#define NO_MEMORY 127

#define MQTT_DEFAULT_PORT "1883"
#define CLIENT_ID_MAXLEN 23

// block signals
#define SIG_PROTECT_BEGIN                                                                       \
	do {                                                                                    \
		sigset_t SIG_PROTECT__mask;                                                     \
		sigset_t SIG_PROTECT__oldmask;                                                  \
		sigfillset(&SIG_PROTECT__mask);                                                 \
                                                                                                \
		/* blocking these is a BAD idea */                                              \
		sigdelset(&SIG_PROTECT__mask, SIGBUS);                                          \
		sigdelset(&SIG_PROTECT__mask, SIGFPE);                                          \
		sigdelset(&SIG_PROTECT__mask, SIGILL);                                          \
		sigdelset(&SIG_PROTECT__mask, SIGSEGV);                                         \
                                                                                                \
		DPRINTF(MAGENTA("Blocking signals") ", to ensure consistency of user data.\n"); \
                                                                                                \
		if (sigprocmask(SIG_SETMASK, &SIG_PROTECT__mask, &SIG_PROTECT__oldmask))        \
			dwarn("sigprocmask")

// ...do whatever needs to be done then unblock them again
#define SIG_PROTECT_END                                                    \
		if (sigprocmask(SIG_SETMASK, &SIG_PROTECT__oldmask, NULL)) \
			dwarn("sigprocmask");                              \
		else                                                       \
			DPRINTF(MAGENTA("Signals unblocked\n"));           \
	} while (0)

// ANSI escape color sequences
#ifdef COLOR
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

#ifdef DEBUG
#define DPRINTF(...)                                                                       \
	do {                                                                               \
		fprintf(stderr, "[" MAGENTA("DEBUG") " " __FILE__ ":" str(__LINE__) "] "); \
		fprintf(stderr, __VA_ARGS__);                                              \
	} while (0)
#else
#define DPRINTF(...) do { } while (0)
#endif

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
