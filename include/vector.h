#ifndef VECTOR_H_
#define VECTOR_H_

/* Dynamic array library written for use with the mqttserver program by Jan Doskočil.
 *
 * License is same as mqttserver, which should be GPLv3.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_DEF(type, vectype)                                                             \
	/* Define a new vector type named 'vectype' holding items of type 'type'.             \
	 *                                                                                    \
	 * 'vectype' will be an incomplete type, because it contains a flexible array member. \
	 * Users will only have a pointer to dynamically allocated instances of the type      \
	 *                                                                                    \
	 * @member capacity Number of reserved memory slots for data items.                   \
	 * @member nmemb Number of members.                                                   \
	 * @member data Array storing the data.                                               \
	 */                                                                                   \
	typedef struct {                                                                      \
		size_t capacity;                                                              \
		size_t nmemb;                                                                 \
		type data[];                                                                  \
	} vectype

#define vec_init(vec, reserve)                                                                     \
	/* Initialize a vector and allocate space for 'reserve' items.                             \
	 *                                                                                         \
	 * @param vector Pointer to user's pointer to the vector.                                  \
	 * @param reserve Number of items to reserve space for on the heap.                        \
	 * @retval NULL If the vector is NULL after calling this macro, it means memory allocation \
	 * failure.                                                                                \
	 */                                                                                        \
	do {                                                                                       \
		const size_t membsize = sizeof((*vec)->data[0]);                                   \
		if (reserve < 1) {                                                                 \
			*vec = NULL;                                                               \
			break;                                                                     \
		}                                                                                  \
		*vec = malloc(sizeof(**vec) + reserve * membsize);                                 \
		if (*vec == NULL)                                                                  \
			break;                                                                     \
		(*vec)->capacity = reserve;                                                        \
		(*vec)->nmemb = 0;                                                                 \
	} while (0)

#define vec_append(vec, item, error)                                                            \
	/* Append an item to the vector.                                                        \
	 *                                                                                      \
	 * May move the vector to a different memory address.                                   \
	 *                                                                                      \
	 * @param vector Pointer to user's pointer to the vector.                               \
	 * @param item The item to append.                                                      \
	 * @param error Pointer to a boolean signifying error.                                  \
	 */                                                                                     \
	do {                                                                                    \
		const size_t membsize = sizeof((*vec)->data[0]);                                \
		if ((*vec)->nmemb == (*vec)->capacity) {                                        \
			(*vec)->capacity *= 2;                                                  \
			void *tmp = realloc(*vec, sizeof(**vec) + (*vec)->capacity * membsize); \
			if (tmp == NULL) {                                                      \
				*error = true;                                                  \
				break;                                                          \
			}                                                                       \
			*vec = tmp;                                                             \
		}                                                                               \
		(*vec)->data[(*vec)->nmemb] = item;                                             \
		++(*vec)->nmemb;                                                                \
		*error = false;                                                                 \
	} while (0)

#endif
