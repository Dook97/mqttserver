#ifndef MAIN_H_
#define MAIN_H_

#include <poll.h>
#include <signal.h>
#include <sys/socket.h>

#include "vector.h"
#include "magic.h"

#define POLL_TIMEOUT 50 // milisecs
#define MAX_MESSAGE_LEN 2048 // not counting the fixed header

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
			dwarn("sigprocmask")                                                    \

// ...do whatever needs to be done and the unblock them again
#define SIG_PROTECT_END                                                    \
		if (sigprocmask(SIG_SETMASK, &SIG_PROTECT__oldmask, NULL)) \
			dwarn("sigprocmask");                              \
									   \
		DPRINTF(MAGENTA("Signals unblocked\n"));                   \
	} while (0)                                                        \

typedef struct {
	char *port;
} args;

typedef struct {
	socklen_t addrlen;
	struct sockaddr_storage addr;

	bool CONNECT_recieved;
	str_vec *subscriptions;
} user_data;

VECTOR_DEF(user_data, user_vec);
VECTOR_DEF(struct pollfd, pollfd_vec);

typedef struct {
	user_vec *data;
	pollfd_vec *conns;
} users_t;

char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1],
		   socklen_t addrlen);

#endif
