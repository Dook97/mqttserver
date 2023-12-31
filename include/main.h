#ifndef MAIN_H_
#define MAIN_H_

#include <poll.h>
#include <sys/socket.h>

#include "vector.h"

#define POLL_TIMEOUT 50

typedef struct {
	char *port;
} args;

typedef struct {
	socklen_t addrlen;
	struct sockaddr_storage addr;
	str_vec *subscriptions;
} user;

VECTOR_DEF(user, user_vec);
VECTOR_DEF(struct pollfd, pollfd_vec);

#endif
