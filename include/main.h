#ifndef MAIN_H_
#define MAIN_H_

#include <stdint.h>

#include "vector.h"

typedef struct {
	char *port;
} args;

VECTOR_DEF(int, int_vec);

#endif
