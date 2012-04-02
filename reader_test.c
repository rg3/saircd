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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "messages.h"
#include "buffer.h"
#include "reader.h"
#include "util.h"

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

	printf("Reader test: %.1f%% passed (failed %d out of %d tests)\n",
	       percentage, tests_failed, tests_counter);

	return (tests_passed == tests_counter)?0:1;
}

void test_callback(int fd, const char *msg, int msglen, void *arg)
{
	static const char *expected[] = {
		"PRIVMSG gregor :We don't want any bugs in here",
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"01234567890123456789012345678901234567890123456789"
		"0123456789",
		"This is \ra weird message\r",
		"JOIN #kafka",
		NULL
	};
	static char aux[MESSAGE_BUFFER_SIZE];
	static int i = 0;


	UNUSED(fd);
	UNUSED(arg);

	++tests_counter;

	if (msglen > MAX_MESSAGE_LEN || msglen < 2) {
		printf("Incorrect message length (%d bytes)\n", msglen);
		++tests_failed;
		return;
	}

	if (expected[i] == NULL) {
		printf("Too many messages received\n");
		++tests_failed;
		return;
	}

	memmove(aux, msg, msglen);
	aux[msglen - 2] = '\0';
	if (strcmp(aux, expected[i]) != 0) {
		printf("Message mismatch: <%s> <%s>\n", aux, expected[i]);
		++tests_failed;
	} else
		++tests_passed;

	++i;
}

int main()
{
	/*
	 * The tests will be:
	 * 	Feeding too much data.
	 * 	Recovering and feeding an empty message.
	 * 	Feeding a normal message.
	 * 	Feeding a full-length message.
	 * 	Feeding a message with separated \r and \n in the middle.
	 * 	Feeding too much data again.
	 * 	Recovering and feeding a normal message.
	 */
	static const char *blocks[] = {
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxx\r\n\r\nPRIVMSG gregor :We don't want any bugs ",
		"in here\r\n" "01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"01234567890123456789012345678901234567890123456789",
		"0123456789\r\n" "This is \ra weird message\r\r\n",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxx\r\n",
		"JOIN #kafka\r\n",
		NULL
	};

	int i;
	int pipefd[2];
	ssize_t l;

	struct reader r;
	struct buffer b;

	assert(pipe(pipefd) == 0);
	assert(nonblock(pipefd[0]) == 0);
	assert(buffer_create(&b, MAX_MESSAGE_LEN) == 0);
	reader_init(&r, pipefd + 0, test_callback, &b);

	init_counters();


	for (i = 0; blocks[i] != NULL; ++i) {
		l = (ssize_t)strlen(blocks[i]);
		assert(write(pipefd[1], blocks[i], l) == l);
		read_and_callback(&r, NULL);
	}

	close(pipefd[1]);

	++tests_counter;
	if (read_and_callback(&r, NULL) != 0) {
		printf("Unable to correctly receive EOF\n");
		++tests_failed;
	} else
		++tests_passed;

	close(pipefd[0]);
	assert(buffer_destroy(&b) == 0);
	return tests_summary();
}
