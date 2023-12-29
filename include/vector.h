#ifndef VECTOR_H_
#define VECTOR_H_

/* Dynamic array library written for use with the mqttserver program by Jan Doskočil.
 *
 * License is same as mqttserver, which should be GPLv3.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#define VECTOR_DEF(type, vectype)                                                             \
	/* Define a new vector type named 'vectype' holding items of type 'type'.             \
	 *                                                                                    \
	 * 'vectype' will be an incomplete type, because it contains a flexible array member. \
	 * Users will only have a pointer to dynamically allocated instances of the type      \
	 *                                                                                    \
	 * @member cap Number of reserved memory slots for data items.                        \
	 * @member nmemb Number of members.                                                   \
	 * @member data Array storing the data.                                               \
	 */                                                                                   \
	typedef struct {                                                                      \
		size_t cap;                                                                   \
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
		(*vec)->cap = reserve;                                                             \
		(*vec)->nmemb = 0;                                                                 \
	} while (0)

#define vec_append(vec, item, error)                                                       \
	/* Append an item to the vector.                                                   \
	 *                                                                                 \
	 * May move the vector to a different memory address.                              \
	 *                                                                                 \
	 * @param vector Pointer to user's pointer to the vector.                          \
	 * @param item The item to append.                                                 \
	 * @param error Pointer to a boolean signifying error.                             \
	 */                                                                                \
	do {                                                                               \
		const size_t membsize = sizeof((*vec)->data[0]);                           \
		if ((*vec)->nmemb == (*vec)->cap) {                                        \
			(*vec)->cap *= 2;                                                  \
			void *tmp = realloc(*vec, sizeof(**vec) + (*vec)->cap * membsize); \
			if (tmp == NULL) {                                                 \
				*error = true;                                             \
				break;                                                     \
			}                                                                  \
			*vec = tmp;                                                        \
		}                                                                          \
		(*vec)->data[(*vec)->nmemb] = item;                                        \
		++(*vec)->nmemb;                                                           \
		*error = false;                                                            \
	} while (0)

#define vec_trunc(vec, newcap, error)                                            \
	/* Truncate vector to given capacity.                                    \
	 *                                                                       \
	 * May move the vector to a different memory address.                    \
	 *                                                                       \
	 * If an error occurs 'error' will be set and vec will remain unchanged. \
	 *                                                                       \
	 * @param vec Pointer to user's pointer to the vector.                   \
	 * @param newcap Desired capacity.                                       \
	 * @param error Pointer to a boolean signifying error.                   \
	 *                                                                       \
	 */                                                                      \
	do {                                                                     \
		const size_t membsize = sizeof((*vec)->data[0]);                 \
		void *tmp = realloc(*vec, sizeof(**vec) + newcap * membsize);    \
		if (tmp == NULL) {                                               \
			*error = true;                                           \
			break;                                                   \
		}                                                                \
		*vec = tmp;                                                      \
		vec->cap = newcap;                                               \
		*error = false;                                                  \
	} while (0)

#define vec_extend(vec, capdiff, error)                                                        \
	/* Extend vector capacity by 'capdiff' members.                                        \
	 *                                                                                     \
	 * @param vec Pointer to user's pointer to the vector.                                 \
	 * @param capdiff Capacity delta.                                                      \
	 * @param error Pointer to a boolean signifying error.                                 \
	 */                                                                                    \
	do {                                                                                   \
		const size_t membsize = sizeof((*vec)->data[0]);                               \
		void *tmp = realloc(*vec, sizeof(**vec) + ((*vec)->cap + capdiff) * membsize); \
		if (tmp == NULL) {                                                             \
			*error = true;                                                         \
			break;                                                                 \
		}                                                                              \
		*vec = tmp;                                                                    \
		vec->cap += diff;                                                              \
		*error = false;                                                                \
	} while (0)

#endif
