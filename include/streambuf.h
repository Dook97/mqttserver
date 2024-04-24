#ifndef STREAMBUF_H_
#define STREAMBUF_H_

#include <unistd.h>

typedef struct {
	size_t begin; // first valid data[] index
	size_t end;   // just behind the last valid data[] index
	size_t cap;   // just behind the last allocated byte of data[] index
	unsigned char data[];
} streambuf;

#define SBUF_ENOMEM -2

#define SB_EMPTY(sbuf) ((sbuf)->begin == (sbuf)->end)
#define SB_DATASIZE(sbuf) ((sbuf)->end - (sbuf)->begin)
#define SB_DATA(sbuf) (&(sbuf)->data[(sbuf)->begin])

/* @brief Allocate and initialize a new streambuffer.
 * @retval Pointer to a streambuf.
 * @returns NULL on ENOMEM
 */
streambuf *sbuf_make(void);

/* @brief Moves data to the beggining of the streambuffer. */
void sbuf_compact(streambuf *sb);

/* @brief Ensures there is enough memory in the streambuffer that it can fit size bytes of
 * continuous data in total. This may move the streambuffer to a new address.
 * @retval Pointer to the possibly moved streambuf.
 * @returns NULL on ENOMEM
 */
streambuf *sbuf_make_fit(streambuf *sb, size_t size);

/* @brief Attempt to read() count bytes of data from fd into the streambuffer. The buffer will
 * automatically resize if needed. read() errno will be preserved.
 * @param sbuf Pointer to user's pointer to the buffer - the buffer might be moved by this
 * operation.
 * @retval return value of read()
 * @returns SBUF_ENOMEM on ENOMEM
 */
ssize_t sbuf_load(streambuf **sbuf, int fd, size_t count);

/* @brief Move the "read head" of sbuf by count bytes */
void sbuf_mark_read(streambuf *sbuf, size_t count);

#endif
