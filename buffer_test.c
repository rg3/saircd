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
#include <stdio.h>
#include <string.h>

#include "buffer.h"

#define BUFFER_SIZE 40

int tests_counter;
int tests_passed;
int tests_failed;

void init_counters(void)
{
	tests_counter = 0;
	tests_passed = 0;
	tests_failed = 0;
}

int tests_summary(void)
{
	float percentage;

	if (tests_counter == 0)
		percentage = 100.0f;
	else
		percentage =
			(float)(tests_passed) / (float)(tests_counter) * 100.0f;

	printf("Buffer test: %.1f%% passed (failed %d out of %d tests)\n",
	       percentage, tests_failed, tests_counter);

	return (tests_passed == tests_counter)?0:1;
}

int main()
{
	struct buffer b;
	const char *aux;

	init_counters();
	b.data = NULL;

	++tests_counter;
	if (buffer_create(&b, BUFFER_SIZE) != 0 ||
	    b.size != BUFFER_SIZE ||
	    b.used != 0 ||
	    b.data == NULL) {
		printf("Unable to create buffer\n");
		++tests_failed;
	} else
		++tests_passed;

	aux = "This string is more than forty characters long.";

	++tests_counter;
	if (buffer_append(&b, aux, strlen(aux)) == 0) {
		printf("Long string was not discarded with error\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_append(&b, "0123456789" "0123456789", 20) != 0 ||
	    buffer_remaining(&b) != 20) {
		printf("Unable to append short string\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_append(&b, "0123456789" "0123456789" "0", 21) == 0) {
		printf("Long string was not discarded on non-empty buffer\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_append(&b, "0123456789" "0123456789", 20) != 0 ||
	    buffer_remaining(&b) != 0 ||
	    memcmp(b.data, "0123456789012345678901234567890123456789", BUFFER_SIZE) != 0) {
		printf("Unable to fill buffer to its max capacity\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_consume(&b, 50) == 0) {
		printf("Unable to detect excessive count consuming\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_consume(&b, 7) != 0 ||
	    buffer_remaining(&b) != 7 ||
	    memcmp(b.data, "789012345678901234567890123456789", b.used) != 0) {
		printf("Unable to correctly extract part of stored data\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_consume(&b, 32) != 0 ||
	    buffer_remaining(&b) != 39 ||
	    b.data[0] != '9') {
		printf("Unable to correctly extract all data except one byte\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_consume(&b, -1) != 0 ||
	    buffer_remaining(&b) != BUFFER_SIZE) {
		printf("Unable to flush all buffer data\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_consume(&b, 1) == 0) {
		printf("Unable to detect error extracting data from empty buffer\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (buffer_destroy(&b) != 0 ||
	    b.size != 0 ||
	    b.used != 0 ||
	    b.data != NULL) {
		printf("Unable to destroy buffer\n");
		++tests_failed;
	} else
		++tests_passed;

	return tests_summary();
}
