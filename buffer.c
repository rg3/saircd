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
#include <stdlib.h>
#include <string.h>

#include "buffer.h"

int buffer_create(struct buffer *buf, int size)
{
	buf->used = 0;
	buf->data = malloc(size * sizeof(char));

	if (buf->data == NULL) {
		buf->size = 0;
		return 1;
	}

	buf->size = size;
	return 0;
}

int buffer_append(struct buffer *buf, const char *in, int count)
{
	char *aux;

	if (count < 0 || count > buffer_remaining(buf))
		return 1;

	if (count == 0)
		return 0;

	aux = buf->data + buf->used;
	if (in != aux)
		memmove(aux, in, count);
	buf->used += count;
	return 0;
}

int buffer_consume(struct buffer *buf, int count)
{
	if (count == 0)
		return 0;

	if (count < 0) {
		buf->used = 0;
		return 0;
	}

	if (count > buf->used)
		return 1;

	buf->used -= count;
	memmove(buf->data, buf->data + count, buf->used);
	return 0;
}

int buffer_remaining(const struct buffer *buf)
{
	return (buf->size - buf->used);
}

int buffer_destroy(struct buffer *buf)
{
	buf->size = 0;
	buf->used = 0;
	if (buf->data != NULL) {
		free(buf->data);
		buf->data = NULL;
	}
	return 0;
}
