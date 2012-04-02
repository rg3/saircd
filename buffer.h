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
 * buffer.h - Input and output buffers.
 */
#ifndef _BUFFER_H_
#define _BUFFER_H_

struct buffer {
	int size;
	int used;
	char *data;
};

/* Create a new buffer. Returns zero on success. */
int buffer_create(struct buffer *buf, int size);

/* Append data to a buffer. Returns zero on success. */
int buffer_append(struct buffer *buf, const char *in, int count);

/* Delete data from a buffer (negative empties buffer). Zero on success. */
int buffer_consume(struct buffer *buf, int count);

/* Calculate remaining space. */
int buffer_remaining(const struct buffer *buf);

/* Destroy a buffer. */
int buffer_destroy(struct buffer *buf);

#endif /* _BUFFER_H_ */
