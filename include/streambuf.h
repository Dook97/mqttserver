#ifndef STREAMBUF_H_
#define STREAMBUF_H_

#include <stdint.h>
#include <unistd.h>

typedef struct {
	size_t begin; // first valid data[] index
	size_t end;   // just behind the last valid data[] index
	size_t cap;   // just behind the last allocated byte of data[] index
	uint8_t data[];
} streambuf;

#define SB_DATASIZE(sbuf)	((sbuf)->end - (sbuf)->begin)
#define SB_EMPTY(sbuf)		((sbuf)->begin == (sbuf)->end)

/* pointer to first valid data byte */
#define SB_DATA(sbuf)		(&(sbuf)->data[(sbuf)->begin])

/* immediately available storage bytes */
#define SB_AVAIL(sbuf)		((sbuf)->cap - (sbuf)->end)

/* storage bytes available as if the buffer were compacted */
#define SB_FREE(sbuf)		((sbuf)->begin + SB_AVAIL((sbuf)))

/*!
 * @brief Allocate and initialize a new streambuffer.
 * @retval Pointer to a streambuf.
 */
streambuf *sbuf_make(void);

/*! @brief Moves data to the beggining of the streambuffer. */
void sbuf_compact(streambuf *sb);

/*!
 * @brief Ensures there is enough memory in the streambuffer that it can fit size bytes of
 * continuous data in total. This may move the streambuffer to a new address.
 * @retval Pointer to the possibly moved streambuf.
 */
streambuf *sbuf_make_fit(streambuf *sb, size_t size);

/*!
 * @brief Attempt to read() count bytes of data from fd into the streambuffer. The buffer will
 * automatically resize if needed. read() errno will be preserved.
 * @param sbuf Pointer to user's pointer to the buffer - the buffer might be moved by this
 * operation.
 * @retval return value of read()
 */
ssize_t sbuf_load(streambuf **sbuf, int fd, size_t count);

/*! @brief Move the "read head" of sbuf by count bytes */
void sbuf_mark_read(streambuf *sbuf, size_t count);

#endif
