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

/*
 * reader.h - Input reader automaton based on buffers.
 */
#ifndef _READER_H_
#define _READER_H_

/*
 * Prototype for reader callbacks. These will be called when the reader detects
 * a full IRC message has been read.
 */
typedef void (*reader_callback)(int fd, const char *msg, int msglen, void *arg);

enum reader_state { RS_NORMAL, RS_GREEDY };

struct reader {
	const int *fd;			/* File descriptor. */
	enum reader_state state;	/* Reader state. */
	reader_callback cb;		/* Reader callback. */
	struct buffer *buf;		/* Input buffer. */
};

/*
 * Initialize a reader structure with the given data. The file descriptor
 * should normally have the O_NONBLOCK flag set.
 */
void reader_init(struct reader *rdr, const int *fd, reader_callback cb, struct buffer *buf);

/*
 * Read input from the file descriptor and call callback on each IRC message.
 * Returns the number of bytes read on success, zero on EOF and -1 on problems
 * (i.e. like read()). In the latter case, errno will have the error code.
 */
int read_and_callback(struct reader *rdr, void *arg);

#endif /* _READER_H_ */
