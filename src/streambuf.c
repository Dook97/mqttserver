#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "streambuf.h"

#define STREAMBUF_DEFAULT_SIZE 2048

streambuf *sbuf_make(void) {
	streambuf* ret = malloc(sizeof(streambuf) + STREAMBUF_DEFAULT_SIZE);
	if (ret == NULL)
		return NULL;
	ret->begin = ret->end = 0;
	ret->cap = STREAMBUF_DEFAULT_SIZE;
	return ret;
}

void sbuf_compact(streambuf *sb) {
	if (sb->begin == 0)
		return;

	memmove(&sb->data[0], SB_DATA(sb), SB_DATASIZE(sb));
	sb->end -= sb->begin;
	sb->begin = 0;
}

streambuf *sbuf_make_fit(streambuf *sb, size_t size) {
	/* if we can't fit the requested data into the stream buffer, compact existing data by
	 * shifting them to the beggining of storage */
	if (sb->begin + size > sb->cap)
		sbuf_compact(sb);

	/* if that doesn't cut it, realloc */
	if (sb->begin + size > sb->cap) {
		size_t new_size = STREAMBUF_DEFAULT_SIZE;
		while (new_size < size)
			new_size *= 2;
		sb->cap = new_size;
		sb = realloc(sb, sizeof(streambuf) + new_size);
	}

	return sb;
}

ssize_t sbuf_load(streambuf **sbuf, int fd, size_t count) {
	streambuf *sb = *sbuf;

	assert(sb->begin <= sb->end);
	assert(sb->end <= sb->cap);

	sb = sbuf_make_fit(sb, SB_DATASIZE(sb) + count);
	if (sb == NULL)
		return SBUF_ENOMEM;

	ssize_t nread = read(fd, &sb->data[sb->end], count);
	if (nread > 0)
		sb->end += nread;

	*sbuf = sb;
	return nread;
}

void sbuf_mark_read(streambuf *sbuf, size_t count) {
	sbuf->begin += count;
}
