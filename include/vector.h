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
	 * @member cap Number of reserved memory slots for data items.                        \
	 * @member nmemb Number of members.                                                   \
	 * @member arr Array storing the data.                                                \
	 */                                                                                   \
	typedef struct {                                                                      \
		size_t cap;                                                                   \
		size_t nmemb;                                                                 \
		type arr[];                                                                   \
	} vectype

#define vec_init(vec, reserve)                                                                     \
	/* Initialize a vector and allocate space for 'reserve' items.                             \
	 *                                                                                         \
	 * @param vector Pointer to user's pointer to the vector.                                  \
	 * @param reserve Number of items to reserve space for on the heap - optimally use a power \
	 * of 2 and don't use values < 1.                                                          \
	 * @retval NULL If the vector is NULL after calling this macro, it means memory allocation \
	 * failure.                                                                                \
	 */                                                                                        \
	do {                                                                                       \
		const size_t vec_init__membsize = sizeof((*(vec))->arr[0]);                        \
		if ((reserve) < 1) {                                                               \
			*(vec) = NULL;                                                             \
			break;                                                                     \
		}                                                                                  \
		*(vec) = malloc(sizeof(**(vec)) + (reserve)*vec_init__membsize);                   \
		if (*(vec) == NULL)                                                                \
			break;                                                                     \
		(*(vec))->cap = (reserve);                                                         \
		(*(vec))->nmemb = 0;                                                               \
	} while (0)

#define vec_append(vec, item_, error)                                                            \
	/* Append an item to the vector.                                                         \
	 *                                                                                       \
	 * May move the vector to a different memory address.                                    \
	 *                                                                                       \
	 * @param vector Pointer to user's pointer to the vector.                                \
	 * @param item The item to append.                                                       \
	 * @param error Pointer to a boolean signifying error.                                   \
	 */                                                                                      \
	do {                                                                                     \
		const size_t vec_append__membsize = sizeof((*(vec))->arr[0]);                    \
		if ((*(vec))->nmemb == (*(vec))->cap) {                                          \
			(*(vec))->cap *= 2;                                                      \
			void *vec_append__tmp = realloc(                                         \
				*(vec), sizeof(**(vec)) + (*(vec))->cap * vec_append__membsize); \
			if (vec_append__tmp == NULL) {                                           \
				*(error) = true;                                                 \
				break;                                                           \
			}                                                                        \
			*(vec) = vec_append__tmp;                                                \
		}                                                                                \
		(*(vec))->arr[(*(vec))->nmemb] = (item_);                                        \
		++(*(vec))->nmemb;                                                               \
		*(error) = false;                                                                \
	} while (0)

#define vec_pop(vec)                        \
	/* Remove last element of a vector. \
	 *                                  \
	 * @param vec Pointer to the vector \
	 */                                 \
	do {                                \
		--(vec)->nmemb;             \
	} while (0)

#define vec_trunc(vec, newcap, error)                                                    \
	/* Truncate vector to given capacity.                                            \
	 *                                                                               \
	 * May move the vector to a different memory address.                            \
	 *                                                                               \
	 * If an error occurs 'error' will be set and vec will remain unchanged.         \
	 *                                                                               \
	 * @param vec Pointer to user's pointer to the vector.                           \
	 * @param newcap Desired capacity.                                               \
	 * @param error Pointer to a boolean signifying error.                           \
	 *                                                                               \
	 */                                                                              \
	do {                                                                             \
		const size_t vec_trunc__membsize = sizeof((*(vec))->arr[0]);             \
		void *vec_trunc__tmp =                                                   \
			realloc(*(vec), sizeof(**(vec)) + (newcap)*vec_trunc__membsize); \
		if (vec_trunc__tmp == NULL) {                                            \
			*(error) = true;                                                 \
			break;                                                           \
		}                                                                        \
		*(vec) = vec_trunc__tmp;                                                 \
		(vec)->cap = (newcap);                                                   \
		*(error) = false;                                                        \
	} while (0)

#define vec_extend(vec, capdiff, error)                                                        \
	/* Extend vector capacity by 'capdiff' members.                                        \
	 *                                                                                     \
	 * @param vec Pointer to user's pointer to the vector.                                 \
	 * @param capdiff Capacity delta.                                                      \
	 * @param error Pointer to a boolean signifying error.                                 \
	 */                                                                                    \
	do {                                                                                   \
		const size_t vec_extend__membsize = sizeof((*(vec))->arr[0]);                  \
		void *vec_extend__tmp = realloc(                                               \
			*(vec),                                                                \
			sizeof(**(vec)) + ((*(vec))->cap + (capdiff)) * vec_extend__membsize); \
		if (vec_extend__tmp == NULL) {                                                 \
			*(error) = true;                                                       \
			break;                                                                 \
		}                                                                              \
		*(vec) = vec_extend__tmp;                                                      \
		(vec)->cap += (capdiff);                                                       \
		*(error) = false;                                                              \
	} while (0)

#define vec_remove_at(vec, index)                                            \
	/* Remove item at index from vector.                                 \
	 *                                                                   \
	 * @param vec Pointer to the vector.                                 \
	 * @param index Index of the item to be removed.                     \
	 */                                                                  \
	do {                                                                 \
		memmove(&(vec)->arr[(index)], &(vec)->arr[(index) + 1],      \
			sizeof((vec)->arr[0]) * ((vec)->nmemb - (index)-1)); \
		--((vec)->nmemb);                                            \
	} while (0)

#endif
