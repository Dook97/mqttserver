#ifndef MAIN_H_
#define MAIN_H_

#include <poll.h>

#include "vector.h"

typedef struct {
	char *port;
} args;

VECTOR_DEF(struct pollfd, pollfd_vec);

#endif
