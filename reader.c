/*
 * Copyright 2012 Ricardo Garcia Gonzalez
 * 
 * This file is part of saircd.
 * 
 * saircd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * saircd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with saircd.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "buffer.h"
#include "reader.h"

void reader_init(struct reader *rdr, const int *fd, reader_callback cb, struct buffer *buf)
{
	rdr->fd = fd;
	rdr->state = RS_NORMAL;
	rdr->cb = cb;
	rdr->buf = buf;
}

int read_and_callback(struct reader *rdr, void *arg)
{
	ssize_t ret;
	ssize_t i;
	char *cur;
	int msglen;
	int iret;

	cur = rdr->buf->data + rdr->buf->used;

	/* Read attempt. */
	while ((ret = read(*(rdr->fd), cur, buffer_remaining(rdr->buf))) == -1 &&
	       errno == EINTR)
		;

	/* EOF or read error. */
	if (ret == 0 || ret == -1)
		return ret;

	iret = buffer_append(rdr->buf, cur, ret);
	assert(iret == 0);

	/* Process each read character and update internal state. */
	for (i = 0; i < ret; ++i) {
		switch (rdr->state) {
		case RS_NORMAL:
			if (*cur == '\n') {
				/* Callback on new message. */
				msglen = cur - rdr->buf->data + 1;
				if (msglen > 2)
					/* Nonempty message. */
					rdr->cb(*(rdr->fd), rdr->buf->data, msglen, arg);

				/* Consume message. */
				buffer_consume(rdr->buf, msglen);
				cur = rdr->buf->data;
				continue;
			}
			break;
		case RS_GREEDY:
			if (*cur == '\n') {
				buffer_consume(rdr->buf, cur - rdr->buf->data + 1);
				cur = rdr->buf->data;
				rdr->state = RS_NORMAL;
				continue;
			}
			break;
		}
		++cur;
	}

	/* Change to greedy mode if buffer filled. */
	if (buffer_remaining(rdr->buf) == 0 && rdr->state != RS_GREEDY)
		rdr->state = RS_GREEDY;

	/* Discard buffer data if in greedy mode. */
	if (rdr->state == RS_GREEDY)
		buffer_consume(rdr->buf, -1);

	return ret;
}
