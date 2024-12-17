#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "magic.h"
#include "streambuf.h"

#define STREAMBUF_DEFAULT_SIZE 2048

streambuf *sbuf_make(void) {
	streambuf *ret = xmalloc(sizeof(streambuf) + STREAMBUF_DEFAULT_SIZE);

	*ret = (streambuf){
		.begin = 0,
		.end = 0,
		.cap = STREAMBUF_DEFAULT_SIZE,
	};

	return ret;
}

void sbuf_compact(streambuf *sb) {
	assert(sb->begin <= sb->end);
	assert(sb->end <= sb->cap);

	if (sb->begin == 0)
		return;

	memmove(&sb->data[0], SB_DATA(sb), SB_DATASIZE(sb));
	sb->end -= sb->begin;
	sb->begin = 0;
}

streambuf *sbuf_make_fit(streambuf *sb, size_t size) {
	assert(sb->begin <= sb->end);
	assert(sb->end <= sb->cap);

	/* if we can't fit the requested data into the stream buffer, compact existing data by
	 * shifting them to the beggining of storage */
	if (size > SB_AVAIL(sb))
		sbuf_compact(sb);

	/* if that doesn't cut it, realloc */
	if (size > SB_AVAIL(sb)) {
		size_t new_size = sb->cap;
		while (new_size < size)
			new_size *= 2;
		sb->cap = new_size;
		sb = xrealloc(sb, sizeof(streambuf) + new_size);
	}

	assert(sb->end <= sb->cap);

	return sb;
}

ssize_t sbuf_load(streambuf **sbuf, int fd, size_t count) {
	streambuf *sb = *sbuf;

	assert(sb->begin <= sb->end);
	assert(sb->end <= sb->cap);

	sb = sbuf_make_fit(sb, SB_DATASIZE(sb) + count);

	ssize_t nread = read(fd, &sb->data[sb->end], count);
	if (nread > 0)
		sb->end += nread;

	assert(sb->begin <= sb->end);
	assert(sb->end <= sb->cap);

	*sbuf = sb;
	return nread;
}

void sbuf_mark_read(streambuf *sbuf, size_t nread) {
	assert(sbuf->begin <= sbuf->end);
	assert(sbuf->end <= sbuf->cap);

	sbuf->begin += nread;
	if (sbuf->begin == sbuf->end)
		sbuf->begin = sbuf->end = 0;

	assert(sbuf->begin <= sbuf->end);
}
