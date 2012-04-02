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
#include "messages.h"

struct tokens t;
struct command c;

int tests_counter;
int tests_passed;
int tests_failed;

void init_structs(void)
{
	init_tokens(&t);
	init_command(&c);
}

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

	printf("Messages test: %.1f%% passed (failed %d out of %d tests)\n",
	       percentage, tests_failed, tests_counter);

	return (tests_passed == tests_counter)?0:1;
}

/*
 * Test functions.
 */

void test_empty(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("", &t) >= 0) {
		printf("Empty line passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_longline(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                                  "
		     "                                              \r\n", &t) >= 0) {
		printf("Excessive length line passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_notoks(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("\r\n", &t) >= 0) {
		printf("Line with no tokens passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_prefixonly(void)
{
	init_structs();
	++tests_counter;
	if (tokenize(":prefix\r\n", &t) >= 0) {
		printf("Line with only a prefix passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_suffixonly(void)
{
	init_structs();
	++tests_counter;
	if (tokenize(":suffix\r\n", &t) >= 0) {
		printf("Line with only a suffix passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_nomiddlecommand(void)
{
	init_structs();
	++tests_counter;
	if (tokenize(":prefix :suffix\r\n", &t) >= 0) {
		printf("Line with only a prefix and suffix passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_cmdonly(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command\r\n", &t) == 1 &&
	    t.counter == 1 &&
	    strcmp(t.token[0], "command") == 0) {
		++tests_passed;
	} else {
		printf("Failed to tokenize legit command-only line\n");
		++tests_failed;
	}
}

void test_trailingspace(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command  \r\n", &t) == 1 &&
	    t.counter == 1 &&
	    strcmp(t.token[0], "command") == 0) {
		++tests_passed;
	} else {
		printf("Failed to tokenize line with trailing spaces\n");
		++tests_failed;
	}
}

void test_cronly(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command\r", &t) < 0) {
		++tests_passed;
	} else {
		printf("Line without new line passed without failure\n");
		++tests_failed;
	}
}

void test_lfonly(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command\n", &t) == 1 &&
	    t.counter == 1 &&
	    strcmp(t.token[0], "command") == 0) {
		++tests_passed;
	} else {
		printf("Line without carriage return failed to parse properly\n");
		++tests_failed;
	}
}

void test_prefixtok(void)
{
	init_structs();
	++tests_counter;
	if (tokenize(":prefix command\r\n", &t) == 2 &&
	    t.counter == 2 &&
	    strcmp(":prefix", t.token[0]) == 0 &&
	    strcmp("command", t.token[1]) == 0) {
		++tests_passed;
	} else {
		printf("Line with prefix and command failed to tokenize\n");
		++tests_failed;
	}
}

void test_prefixsuffix(void)
{
	init_structs();
	++tests_counter;
	if (tokenize(":prefix command :suffix words\r\n", &t) == 3 &&
	    t.counter == 3 &&
	    strcmp(":prefix", t.token[0]) == 0 &&
	    strcmp("command", t.token[1]) == 0 &&
	    strcmp("suffix words", t.token[2]) == 0) {
		++tests_passed;
	} else {
		printf("Line with prefix and suffix failed to tokenize\n");
		++tests_failed;
	}
}

void test_singlewordsuffix(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command :suffix\r\n", &t) == 2 &&
	    t.counter == 2 &&
	    strcmp("command", t.token[0]) == 0 &&
	    strcmp("suffix", t.token[1]) == 0) {
		++tests_passed;
	} else {
		printf("Line with single word suffix failed to tokenize\n");
		++tests_failed;
	}
}

void test_emptysuffix(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command :\r\n", &t) == 2 &&
	    t.counter == 2 &&
	    strcmp("command", t.token[0]) == 0 &&
	    strlen(t.token[1]) == 0) {
		++tests_passed;
	} else {
		printf("Line with empty suffix failed to parse properly\n");
		++tests_failed;
	}
}

void test_nospacebeforesuffix(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command:suffix\r\n", &t) < 0) {
		++tests_passed;
	} else {
		printf("Line with no space before suffix passed without failure\n");
		++tests_failed;
	}
}

void test_multispace(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("command  one   two    :third   argument\r\n", &t) == 4 &&
	    t.counter == 4 &&
	    strcmp("command", t.token[0]) == 0 &&
	    strcmp("one", t.token[1]) == 0 &&
	    strcmp("two", t.token[2]) == 0 &&
	    strcmp("third   argument", t.token[3]) == 0) {
		++tests_passed;
	} else {
		printf("Multispaced line failed to tokenize\n");
		++tests_failed;
	}
}

void test_crinmiddle(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("comm\rand\r\n", &t) < 0) {
		++tests_passed;
	} else {
		printf("Line with CR in the middle passed without failure\n");
		++tests_failed;
	}
}

void test_lfinmiddle(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("comm\nand\r\n", &t) < 0) {
		++tests_passed;
	} else {
		printf("Line with LF in the middle passed without failure\n");
		++tests_failed;
	}
}

void test_17tokens(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17\r\n", &t) == 17 &&
	    t.counter == 17 &&
	    strcmp(t.token[0], "1") == 0 &&
	    strcmp(t.token[1], "2") == 0 &&
	    strcmp(t.token[2], "3") == 0 &&
	    strcmp(t.token[3], "4") == 0 &&
	    strcmp(t.token[4], "5") == 0 &&
	    strcmp(t.token[5], "6") == 0 &&
	    strcmp(t.token[6], "7") == 0 &&
	    strcmp(t.token[7], "8") == 0 &&
	    strcmp(t.token[8], "9") == 0 &&
	    strcmp(t.token[9], "10") == 0 &&
	    strcmp(t.token[10], "11") == 0 &&
	    strcmp(t.token[11], "12") == 0 &&
	    strcmp(t.token[12], "13") == 0 &&
	    strcmp(t.token[13], "14") == 0 &&
	    strcmp(t.token[14], "15") == 0 &&
	    strcmp(t.token[15], "16") == 0 &&
	    strcmp(t.token[16], "17") == 0) {
		++tests_passed;
	} else {
		printf("Line with 17 tokens failed to tokenize\n");
		++tests_failed;
	}
}

void test_18tokens(void)
{
	init_structs();
	++tests_counter;
	if (tokenize("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18\r\n", &t) < 0) {
		++tests_passed;
	} else {
		printf("Line with 18 tokens passed without failure\n");
		++tests_failed;
	}
}

void test_parse_unknowncmd(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("FOO\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_UNKNOWNCOMMAND) {
		printf("Uknown command parsed without ERR_UNKNOWNCOMMAND\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_ison(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != 0) {
		printf("Correct ISON line failed to parse\n");
		++tests_failed;
	} else if (strlen(c.prefix) == 0 && 
		   c.number == CMD_ISON && 
		   c.args.cmd_ison.num_nicknames == 1 && 
		   strcmp(c.args.cmd_ison.nicknames[0], "foo") == 0) {
		++tests_passed;
	} else {
		printf("Basic ISON command was not correctly parsed\n");
		++tests_failed;
	}
}

void test_parse_toomanyargs(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON n1 n2 n3 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13 n14 n15 n16\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Command with too many arguments parsed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_15args(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON n1 n2 n3 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13 n14 n15 \r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != 0) {
		printf("Correct ISON line failed to parse\n");
		++tests_failed;
	} else if (strlen(c.prefix) == 0 && 
		   c.number == CMD_ISON && 
		   c.args.cmd_ison.num_nicknames == 15 &&
		   strcmp(c.args.cmd_ison.nicknames[0], "n1") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[1], "n2") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[2], "n3") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[3], "n4") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[4], "n5") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[5], "n6") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[6], "n7") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[7], "n8") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[8], "n9") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[9], "n10") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[10], "n11") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[11], "n12") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[12], "n13") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[13], "n14") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[14], "n15") == 0) {
		++tests_passed;
	} else {
		printf("Command with 15 args and prefix failed to parse\n");
		++tests_failed;
	}
}

void test_parse_prefix15args(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize(":foo ISON n1 n2 n3 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13 n14 n15 \r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != 0) {
		printf("Correct ISON line failed to parse\n");
		++tests_failed;
	} else if (strcmp(c.prefix, ":foo") == 0 && 
		   c.number == CMD_ISON && 
		   c.args.cmd_ison.num_nicknames == 15 &&
		   strcmp(c.args.cmd_ison.nicknames[0], "n1") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[1], "n2") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[2], "n3") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[3], "n4") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[4], "n5") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[5], "n6") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[6], "n7") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[7], "n8") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[8], "n9") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[9], "n10") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[10], "n11") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[11], "n12") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[12], "n13") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[13], "n14") == 0 &&
		   strcmp(c.args.cmd_ison.nicknames[14], "n15") == 0) {
		++tests_passed;
	} else {
		printf("Command with 15 args and prefix failed to parse\n");
		++tests_failed;
	}
}

void test_parse_passnopass(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PASS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("PASS command with no arguments passed without failure\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_passwithpassword(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PASS 2842ccamfsal%%[]á\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
		   strlen(c.prefix) == 0 &&
		   c.number == CMD_PASS &&
		   strcmp(c.args.cmd_pass.password, "2842ccamfsal%%[]á") == 0) {
		++tests_passed;
	} else {
		printf("Correct PASS command failed to parse correctly\n");
		++tests_failed;
	}
}

void test_parse_passignoreextra(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PASS password foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
		   strlen(c.prefix) == 0 &&
		   c.number == CMD_PASS &&
		   strcmp(c.args.cmd_pass.password, "password") == 0) {
		++tests_passed;
	} else {
		printf("Failed to ignore extra arguments in PASS command\n");
		++tests_failed;
	}
}

void test_parse_nicknonick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NONICKNAMEGIVEN) {
		printf("NICK command with no nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_nickdigit(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK 1foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_ERRONEUSNICKNAME) {
		printf("NICK command with leading digit in nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_nickdash(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK -foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_ERRONEUSNICKNAME) {
		printf("NICK command with leading dash in nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_nickpercent(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK foo%\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_ERRONEUSNICKNAME) {
		printf("NICK command with percent symbol in nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_nicktoolong(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK foo222333a\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_ERRONEUSNICKNAME) {
		printf("NICK command with too long nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_propernick1(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK a1[]\\`_^-\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_NICK &&
	    strcmp(c.args.cmd_nick.nickname, "a1[]\\`_^-") == 0) {
		++tests_passed;
	} else {
		printf("First case of proper nick command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_propernick2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK [z{|}]-\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_NICK &&
	    strcmp(c.args.cmd_nick.nickname, "[z{|}]-") == 0) {
		++tests_passed;
	} else {
		printf("Second case of proper nick command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_singlecharnick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NICK a\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_NICK &&
	    strcmp(c.args.cmd_nick.nickname, "a") == 0) {
		++tests_passed;
	} else {
		printf("Single-char proper nick command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_userneedmoreparams(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USER foo 1 *\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("USER command with too few arguments did not return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_userinvaliduser(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USER foo! 1 * :Bar Baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("USER command with invalid user did not return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_userinvalidmode1(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USER foo T * :Bar Baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_USER &&
	    strcmp(c.args.cmd_user.user, "foo") == 0 &&
	    c.args.cmd_user.mode == 0 &&
	    strcmp(c.args.cmd_user.realname, "Bar Baz") == 0) {
		++tests_passed;
	} else {
		printf("USER command with non-numeric mode failed parse properly\n");
		++tests_failed;
	}
}

void test_parse_userinvalidmode2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USER foo 1T * :Bar Baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_USER &&
	    strcmp(c.args.cmd_user.user, "foo") == 0 &&
	    c.args.cmd_user.mode == 0 &&
	    strcmp(c.args.cmd_user.realname, "Bar Baz") == 0) {
		++tests_passed;
	} else {
		printf("USER command with half-numeric mode failed parse properly\n");
		++tests_failed;
	}
}

void test_parse_usercommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USER foo 4 * :Bar Baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_USER &&
	    strcmp(c.args.cmd_user.user, "foo") == 0 &&
	    c.args.cmd_user.mode == 4 &&
	    strcmp(c.args.cmd_user.realname, "Bar Baz") == 0) {
		++tests_passed;
	} else {
		printf("Proper USER command failed to parse correctly\n");
		++tests_failed;
	}
}

void test_parse_invalidoper1(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("OPER\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Invalid OPER command (1) failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invalidoper2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("OPER foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Invalid OPER command (2) failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_opercommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("OPER foo bar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_OPER &&
	    strcmp(c.args.cmd_oper.name, "foo") == 0 &&
	    strcmp(c.args.cmd_oper.password, "bar") == 0) {
		++tests_passed;
	} else {
		printf("Valid OPER command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_modeargs(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("MODE command with no arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_modetarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE =foo=\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("MODE command with invalid target failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_umode(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_MODE &&
	    c.args.cmd_mode.mode_type == TYPE_NICK &&
	    strcmp(c.args.cmd_mode.mode_args.type_nick.nickname, "foo") == 0 &&
	    c.args.cmd_mode.mode_args.type_nick.away == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.invisible == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.wallops == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.restricted == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.net_operator == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.local_operator == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_nick.notices == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Valid MODE command with nickname only failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_umodeargs(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE foo -a+i-w+r-o+O-s\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_MODE &&
	    c.args.cmd_mode.mode_type == TYPE_NICK &&
	    strcmp(c.args.cmd_mode.mode_args.type_nick.nickname, "foo") == 0 &&
	    c.args.cmd_mode.mode_args.type_nick.away == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_nick.invisible == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_nick.wallops == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_nick.restricted == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_nick.net_operator == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_nick.local_operator == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_nick.notices == ACTION_REMOVE) {
		++tests_passed;
	} else {
		printf("Valid MODE command with nickname arguments failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_serviceneedmoreparams(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVICE foo * * bar *\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("SERVICE command lacking arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_serviceinvalidnick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVICE 1foo * * bar * baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_ERRONEUSNICKNAME) {
		printf("SERVICE command with bad nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_servicecommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVICE foo * * bar * baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_SERVICE &&
	    strcmp(c.args.cmd_service.nickname, "foo") == 0 &&
	    strcmp(c.args.cmd_service.distribution, "*") == 0 &&
	    strcmp(c.args.cmd_service.type, "bar") == 0 &&
	    strcmp(c.args.cmd_service.info, "baz") == 0) {
		++tests_passed;
	} else {
		printf("Correct SERVICE command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_emptyquit(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("QUIT\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_QUIT &&
	    strlen(c.args.cmd_quit.message) == 0) {
		++tests_passed;
	} else {
		printf("QUIT command with no message failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_singlewordquit(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("QUIT foo :bar baz etcetera\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_QUIT &&
	    strcmp(c.args.cmd_quit.message, "foo") == 0) {
		++tests_passed;
	} else {
		printf("QUIT command with single word message failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_multiwordquit(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("QUIT :foo bar baz \r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_QUIT &&
	    strcmp(c.args.cmd_quit.message, "foo bar baz ") == 0) {
		++tests_passed;
	} else {
		printf("QUIT command with multiword message failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_squitbad(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SQUIT foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("SQUIT command with too few arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_squitcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SQUIT server.example.com :Server out of control\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_SQUIT &&
	    strcmp(c.args.cmd_squit.server, "server.example.com") == 0 &&
	    strcmp(c.args.cmd_squit.comment, "Server out of control") == 0) {
		++tests_passed;
	} else {
		printf("Correct SQUIT command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_emptyjoin(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("JOIN command with too few arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_joinzero(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN 0\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_JOIN &&
	    c.args.cmd_join.num_channels == 1 &&
	    strcmp(c.args.cmd_join.channels[0], "0") == 0 &&
	    c.args.cmd_join.num_keys == 0) {
		++tests_passed;
	} else {
		printf("Correct JOIN 0 command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_joinzerowithkey(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN 0 key\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("JOIN 0 command with key failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_joinzerointhemiddle(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN #foo,0,#bar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("JOIN command with 0 in the middle failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_jointoomanytargets(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN #one,#two,#three,#four,#five,#six,#seven,#eigth,#nine\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_TOOMANYTARGETS) {
		printf("JOIN command with too many targets failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_joineighttargets(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN #one,#two,#three,#four,#five,#six,#seven,#eight key\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_JOIN &&
	    c.args.cmd_join.num_channels == 8 &&
	    strcmp(c.args.cmd_join.channels[0], "#one") == 0 &&
	    strcmp(c.args.cmd_join.channels[1], "#two") == 0 &&
	    strcmp(c.args.cmd_join.channels[2], "#three") == 0 &&
	    strcmp(c.args.cmd_join.channels[3], "#four") == 0 &&
	    strcmp(c.args.cmd_join.channels[4], "#five") == 0 &&
	    strcmp(c.args.cmd_join.channels[5], "#six") == 0 &&
	    strcmp(c.args.cmd_join.channels[6], "#seven") == 0 &&
	    strcmp(c.args.cmd_join.channels[7], "#eight") == 0 &&
	    c.args.cmd_join.num_keys == 1 &&
	    strcmp(c.args.cmd_join.keys[0], "key") == 0) {
		++tests_passed;
	} else {
		printf("Correct JOIN command with eight targets failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_jointoomanykeys(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN #foo 1,2,3,4,5,6,7,8,9\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_TOOMANYTARGETS) {
		printf("JOIN command with too many keys failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_joineigthkeys(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN #foo 1,2,3,4,5,6,7,8\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_JOIN &&
	    c.args.cmd_join.num_channels == 1 &&
	    strcmp(c.args.cmd_join.channels[0], "#foo") == 0 &&
	    c.args.cmd_join.num_keys == 8 &&
	    strcmp(c.args.cmd_join.keys[0], "1") == 0 &&
	    strcmp(c.args.cmd_join.keys[1], "2") == 0 &&
	    strcmp(c.args.cmd_join.keys[2], "3") == 0 &&
	    strcmp(c.args.cmd_join.keys[3], "4") == 0 &&
	    strcmp(c.args.cmd_join.keys[4], "5") == 0 &&
	    strcmp(c.args.cmd_join.keys[5], "6") == 0 &&
	    strcmp(c.args.cmd_join.keys[6], "7") == 0 &&
	    strcmp(c.args.cmd_join.keys[7], "8") == 0) {
		++tests_passed;
	} else {
		printf("Correct JOIN command with eight keys failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_joinkey(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("JOIN key\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("JOIN command with no channels and a key failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_partempty(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PART\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Empty PART command failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_partinvalid(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PART foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Invalid PART command failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_partsingle(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PART #foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_PART &&
	    c.args.cmd_part.num_channels == 1 &&
	    strcmp(c.args.cmd_part.channels[0], "#foo") == 0 &&
	    strlen(c.args.cmd_part.message) == 0) {
		++tests_passed;
	} else {
		printf("PART command with single channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_partmultiwithreason(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PART #foo,,#bar :Baz reason\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_PART &&
	    c.args.cmd_part.num_channels == 2 &&
	    strcmp(c.args.cmd_part.channels[0], "#foo") == 0 &&
	    strcmp(c.args.cmd_part.channels[1], "#bar") == 0 &&
	    strcmp(c.args.cmd_part.message, "Baz reason") == 0) {
		++tests_passed;
	} else {
		printf("PART command with multiple channels and reason failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_partemptyweirdlist(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PART ,,,\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Invalid PART command failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_topicempty(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TOPIC\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Invalid TOPIC command failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_topiclongchanname(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TOPIC #thenameofthischannelistoolongtobeparsedproperly123\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_TOPIC &&
	    strcmp(c.args.cmd_topic.channel, "#thenameofthischannelistoolongtobeparsedproperly123") == 0 &&
	    c.args.cmd_topic.topic_given == 0 &&
	    strlen(c.args.cmd_topic.topic) == 0) {
		++tests_passed;
	} else {
		printf("Correct TOPIC command with very long channel name failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_topicmaxchanlength(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TOPIC #the_name_of_this_channel_is_fifty_chars_long_____\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_TOPIC &&
	    strcmp(c.args.cmd_topic.channel, "#the_name_of_this_channel_is_fifty_chars_long_____") == 0 &&
	    c.args.cmd_topic.topic_given == 0 &&
	    strlen(c.args.cmd_topic.topic) == 0) {
		++tests_passed;
	} else {
		printf("Correct TOPIC command with maximum length channel name failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_topicwithtopic(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TOPIC #foo :This is the new channel topic!\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_TOPIC &&
	    strcmp(c.args.cmd_topic.channel, "#foo") == 0 &&
	    c.args.cmd_topic.topic_given == 1 &&
	    strcmp(c.args.cmd_topic.topic, "This is the new channel topic!") == 0) {
		++tests_passed;
	} else {
		printf("Correct TOPIC command with topic failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_topicemptytopic(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TOPIC #foo :\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_TOPIC &&
	    strcmp(c.args.cmd_topic.channel, "#foo") == 0 &&
	    c.args.cmd_topic.topic_given == 1 &&
	    strlen(c.args.cmd_topic.topic) == 0) {
		++tests_passed;
	} else {
		printf("Correct TOPIC command with topic failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_namesonechannel(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NAMES #foo server.example.com\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_NAMES &&
	    c.args.cmd_names_list.num_channels == 1 &&
	    strcmp(c.args.cmd_names_list.channels[0], "#foo") == 0 &&
	    strcmp(c.args.cmd_names_list.target, "server.example.com") == 0) {
		++tests_passed;
	} else {
		printf("Correct NAMES command with one channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_namesseveralchannels(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NAMES #foo,#bar,#baz :Target Server\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_NAMES &&
	    c.args.cmd_names_list.num_channels == 3 &&
	    strcmp(c.args.cmd_names_list.channels[0], "#foo") == 0 &&
	    strcmp(c.args.cmd_names_list.channels[1], "#bar") == 0 &&
	    strcmp(c.args.cmd_names_list.channels[2], "#baz") == 0 &&
	    strcmp(c.args.cmd_names_list.target, "Target Server") == 0) {
		++tests_passed;
	} else {
		printf("Correct NAMES command with several channels failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_namestoomanychans(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NAMES #a,#b,#c,#d,#e,#f,#g,#h,#i\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect NAMES command with too many channels failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_listonechannel(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LIST #foo server.example.com\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_LIST &&
	    c.args.cmd_names_list.num_channels == 1 &&
	    strcmp(c.args.cmd_names_list.channels[0], "#foo") == 0 &&
	    strcmp(c.args.cmd_names_list.target, "server.example.com") == 0) {
		++tests_passed;
	} else {
		printf("Correct LIST command with one channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_listseveralchannels(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LIST #foo,#bar,#baz :Target Server\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_LIST &&
	    c.args.cmd_names_list.num_channels == 3 &&
	    strcmp(c.args.cmd_names_list.channels[0], "#foo") == 0 &&
	    strcmp(c.args.cmd_names_list.channels[1], "#bar") == 0 &&
	    strcmp(c.args.cmd_names_list.channels[2], "#baz") == 0 &&
	    strcmp(c.args.cmd_names_list.target, "Target Server") == 0) {
		++tests_passed;
	} else {
		printf("Correct LIST command with several channels failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_listtoomanychans(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LIST #a,#b,#c,#d,#e,#f,#g,#h,#i\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect LIST command with too many channels failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invitenoargs(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INVITE\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect INVITE command with no arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invitenickonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INVITE john\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect INVITE command with nickname only failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invitebadnick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INVITE 123abc #foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NOSUCHNICK) {
		printf("Incorrect INVITE command with bad nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invitebadchan(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INVITE lucy #\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect INVITE command with bad channel name failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_invitecommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INVITE anaku #java\r\n", &t) >= 0); /* Good ol' times. */
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_INVITE &&
	    strcmp(c.args.cmd_invite.nickname, "anaku") == 0 &&
	    strcmp(c.args.cmd_invite.channel, "#java") == 0) {
		++tests_passed;
	} else {
		printf("Correct INVITE command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_kickoneone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KICK #channel nickname :Stop spamming!\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_KICK &&
	    c.args.cmd_kick.num_channels == 1 &&
	    strcmp(c.args.cmd_kick.channels[0], "#channel") == 0 &&
	    c.args.cmd_kick.num_nicknames == 1 &&
	    strcmp(c.args.cmd_kick.nicknames[0], "nickname") == 0 &&
	    strcmp(c.args.cmd_kick.comment, "Stop spamming!") == 0) {
		++tests_passed;
	} else {
		printf("Correct KICK command with one nickname and one channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_kickmultiple(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KICK #a,#b,#c,#d,#e,#f,#g,#h a,b,c,d,e,f,g,h\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    strlen(c.prefix) == 0 &&
	    c.number == CMD_KICK &&
	    c.args.cmd_kick.num_channels == 8 &&
	    strcmp(c.args.cmd_kick.channels[0], "#a") == 0 &&
	    strcmp(c.args.cmd_kick.channels[1], "#b") == 0 &&
	    strcmp(c.args.cmd_kick.channels[2], "#c") == 0 &&
	    strcmp(c.args.cmd_kick.channels[3], "#d") == 0 &&
	    strcmp(c.args.cmd_kick.channels[4], "#e") == 0 &&
	    strcmp(c.args.cmd_kick.channels[5], "#f") == 0 &&
	    strcmp(c.args.cmd_kick.channels[6], "#g") == 0 &&
	    strcmp(c.args.cmd_kick.channels[7], "#h") == 0 &&
	    c.args.cmd_kick.num_nicknames == 8 &&
	    strcmp(c.args.cmd_kick.nicknames[0], "a") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[1], "b") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[2], "c") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[3], "d") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[4], "e") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[5], "f") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[6], "g") == 0 &&
	    strcmp(c.args.cmd_kick.nicknames[7], "h") == 0 &&
	    strlen(c.args.cmd_kick.comment) == 0) {
		++tests_passed;
	} else {
		printf("Correct KICK command with multiple nicknames and channels failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_kicktoofewchans(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KICK #a,#b,#c,#d,#e,#f,#g a,b,c,d,e,f,g,h\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect KICK command with too few channels failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_kicktoofewnicks(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KICK #a,#b,#c,#d,#e,#f,#g,#h a,b,c,d,e,f,g\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect KICK command with too few nicknames failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_kicktoomuchstuff(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KICK #a,#b,#c,#d,#e,#f,#g,#h,#i a,b,c,d,e,f,g,h,i\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect KICK command with too much stuff failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_privmsgnorecipient(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PRIVMSG\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NORECIPIENT) {
		printf("Incorrect PRIVMSG command with no target failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_privmsgnotext(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PRIVMSG scarlett\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NOTEXTTOSEND) {
		printf("Incorrect PRIVMSG command with no text failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_privmsgcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PRIVMSG scarlett :I hacked your cell phone! LOL\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PRIVMSG &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_privmsg.target_type == TYPE_NICK &&
	    strcmp(c.args.cmd_privmsg.target.nickname, "scarlett") == 0 &&
	    strcmp(c.args.cmd_privmsg.text, "I hacked your cell phone! LOL") == 0) {
		++tests_passed;
	} else {
		printf("Correct PRIVMSG command to nick failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_privmsgcommandchan(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PRIVMSG #blackhat :I hacked her cell phone! LOL\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PRIVMSG &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_privmsg.target_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_privmsg.target.channel, "#blackhat") == 0 &&
	    strcmp(c.args.cmd_privmsg.text, "I hacked her cell phone! LOL") == 0) {
		++tests_passed;
	} else {
		printf("Correct PRIVMSG command to channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_noticenorecipient(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NOTICE\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect NOTICE command with no target failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_noticenotext(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NOTICE scarlett\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect NOTICE command with no text failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_noticecommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NOTICE scarlett :I hacked your cell phone! LOL\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_NOTICE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_privmsg.target_type == TYPE_NICK &&
	    strcmp(c.args.cmd_privmsg.target.nickname, "scarlett") == 0 &&
	    strcmp(c.args.cmd_privmsg.text, "I hacked your cell phone! LOL") == 0) {
		++tests_passed;
	} else {
		printf("Correct NOTICE command to nick failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_noticecommandchan(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("NOTICE #blackhat :I hacked her cell phone! LOL\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_NOTICE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_privmsg.target_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_privmsg.target.channel, "#blackhat") == 0 &&
	    strcmp(c.args.cmd_privmsg.text, "I hacked her cell phone! LOL") == 0) {
		++tests_passed;
	} else {
		printf("Correct NOTICE command to channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_motdnotarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MOTD\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MOTD &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_motd.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct MOTD command with no target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_motdcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MOTD target.example.com\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MOTD &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_motd.target, "target.example.com") == 0) {
		++tests_passed;
	} else {
		printf("Correct MOTD command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_lusersalone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LUSERS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LUSERS &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_lusers.mask) == 0 &&
	    strlen(c.args.cmd_lusers.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct LUSERS empty command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_lusersmask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LUSERS *.es\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LUSERS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_lusers.mask, "*.es") == 0 &&
	    strlen(c.args.cmd_lusers.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct LUSERS command with mask failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_luserstarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LUSERS *.es target.example.com\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LUSERS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_lusers.mask, "*.es") == 0 &&
	    strcmp(c.args.cmd_lusers.target, "target.example.com") == 0) {
		++tests_passed;
	} else {
		printf("Correct LUSERS command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_versionalone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("VERSION\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_VERSION &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_version.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct VERSION empty command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_versiontarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("VERSION 10.10.210.1\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_VERSION &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_version.target, "10.10.210.1") == 0) {
		++tests_passed;
	} else {
		printf("Correct VERSION command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_statsalone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("STATS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_STATS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_stats.query == '\0' &&
	    strlen(c.args.cmd_stats.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct STATS empty command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_statsquery(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("STATS a\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_STATS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_stats.query == 'a' &&
	    strlen(c.args.cmd_stats.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct STATS query command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_statstarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("STATS a targetserver\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_STATS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_stats.query == 'a' &&
	    strcmp(c.args.cmd_stats.target, "targetserver") == 0) {
		++tests_passed;
	} else {
		printf("Correct STATS command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_statsmultiletter(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("STATS lol\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect STATS command with multiletter query failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_linksonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LINKS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LINKS &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_links.remote_server) == 0 &&
	    strlen(c.args.cmd_links.server_mask) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty LINKS command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_linksmask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LINKS *.time.gov\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LINKS &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_links.remote_server) == 0 &&
	    strcmp(c.args.cmd_links.server_mask, "*.time.gov") == 0) {
		++tests_passed;
	} else {
		printf("Correct LINKS command with mask failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_linksremote(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("LINKS 192.168.1.2 *.time.gov\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_LINKS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_links.remote_server, "192.168.1.2") == 0 &&
	    strcmp(c.args.cmd_links.server_mask, "*.time.gov") == 0) {
		++tests_passed;
	} else {
		printf("Correct LINKS command with remote server failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_timeonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TIME\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_TIME &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_time.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty TIME command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_timetarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TIME darkstar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_TIME &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_time.target, "darkstar") == 0) {
		++tests_passed;
	} else {
		printf("Correct TIME command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_connectonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect CONNECT command with no arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_connecttarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect CONNECT command with target only failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_connectbadport(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner FOO\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect CONNECT command with bad port failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_connectbadport2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner 123456\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect CONNECT command with too high port failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_connectbadport3(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner 0\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect CONNECT command with too low port failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_connectgoodport(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner 1\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_CONNECT &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_connect.target_server, "deckard.bladerunner") == 0 &&
	    strcmp(c.args.cmd_connect.remote_server, "") == 0 &&
	    c.args.cmd_connect.port == 1) {
		++tests_passed;
	} else {
		printf("Correct CONNECT command with port 1 failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_connectgoodport2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner 65535\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_CONNECT &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_connect.target_server, "deckard.bladerunner") == 0 &&
	    strcmp(c.args.cmd_connect.remote_server, "") == 0 &&
	    c.args.cmd_connect.port == 65535) {
		++tests_passed;
	} else {
		printf("Correct CONNECT command with port 65535 failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_connectremote(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("CONNECT deckard.bladerunner 6667 batty.bladerunner\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_CONNECT &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_connect.target_server, "deckard.bladerunner") == 0 &&
	    strcmp(c.args.cmd_connect.remote_server, "batty.bladerunner") == 0 &&
	    c.args.cmd_connect.port == 6667) {
		++tests_passed;
	} else {
		printf("Correct CONNECT command with remote server failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_traceonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TRACE\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_TRACE &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_trace.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty TRACE command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_tracetarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("TRACE darkstar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_TRACE &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_trace.target, "darkstar") == 0) {
		++tests_passed;
	} else {
		printf("Correct TRACE command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_adminonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ADMIN\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_ADMIN &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_admin.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty ADMIN command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_admintarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ADMIN darkstar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_ADMIN &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_admin.target, "darkstar") == 0) {
		++tests_passed;
	} else {
		printf("Correct ADMIN command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_infoonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INFO\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_INFO &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_info.target) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty INFO command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_infotarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("INFO darkstar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_INFO &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_info.target, "darkstar") == 0) {
		++tests_passed;
	} else {
		printf("Correct INFO command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_servlist(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVLIST\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SERVLIST &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_servlist.mask) == 0 &&
	    strlen(c.args.cmd_servlist.type) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty SERVLIST command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_servlistmask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVLIST foo*\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SERVLIST &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_servlist.mask, "foo*") == 0 &&
	    strcmp(c.args.cmd_servlist.type, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct SERVLIST command with mask failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_servlisttype(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SERVLIST foo* BLUE\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SERVLIST &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_servlist.mask, "foo*") == 0 &&
	    strcmp(c.args.cmd_servlist.type, "BLUE") == 0) {
		++tests_passed;
	} else {
		printf("Correct SERVLIST command with type failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_squery(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SQUERY\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NORECIPIENT) {
		printf("Incorrect empty SQUERY command failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_squeryservicename(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SQUERY ChanServ\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NOTEXTTOSEND) {
		printf("Incorrect SQUERY command with service name failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_squerycommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SQUERY NickServ :Help me get my password back\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SQUERY &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_squery.servicename, "NickServ") == 0 &&
	    strcmp(c.args.cmd_squery.text, "Help me get my password back") == 0) {
		++tests_passed;
	} else {
		printf("Correct SQUERY command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_who(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHO\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHO &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_who.o == 0 &&
	    c.args.cmd_who.target_type == TYPE_OTHER &&
	    strlen(c.args.cmd_who.target.mask) == 0) {
		++tests_passed;
	} else {
		printf("Correct empty WHO command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whonick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHO lol\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHO &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_who.target_type == TYPE_NICK &&
	    c.args.cmd_who.o == 0 &&
	    strcmp(c.args.cmd_who.target.nickname, "lol") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHO command with nickname failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whoo(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHO #roflcopter o\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHO &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_who.target_type == TYPE_CHAN &&
	    c.args.cmd_who.o == 1 &&
	    strcmp(c.args.cmd_who.target.channel, "#roflcopter") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHO command with O parameter failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whomask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHO *.es\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHO &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_who.target_type == TYPE_OTHER &&
	    c.args.cmd_who.o == 0 &&
	    strcmp(c.args.cmd_who.target.mask, "*.es") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHO command with mask failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whoisonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOIS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NONICKNAMEGIVEN) {
		printf("Incorrect WHOIS command without nickname failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_whoissingle(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOIS that_guy\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHOIS &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_whois.target) == 0 &&
	    c.args.cmd_whois.num_nicknames == 1 &&
	    strcmp(c.args.cmd_whois.nicknames[0], "that_guy") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHOIS command with one nickname failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whoistoomany(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOIS a,b,c,d,e,f,g,h,i\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect WHOIS command with too many nicknames failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_whoistargeteight(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOIS lu a,b,c,d,e,f,g,h\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHOIS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_whois.target, "lu") == 0 &&
	    c.args.cmd_whois.num_nicknames == 8 &&
	    strcmp(c.args.cmd_whois.nicknames[0], "a") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[1], "b") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[2], "c") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[3], "d") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[4], "e") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[5], "f") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[6], "g") == 0 &&
	    strcmp(c.args.cmd_whois.nicknames[7], "h") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHOIS command with eight nicknames failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whowasone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS wasp\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHOWAS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_whowas.num_nicknames == 1 &&
	    strcmp(c.args.cmd_whowas.nicknames[0], "wasp") == 0 &&
	    c.args.cmd_whowas.count == -1 &&
	    strcmp(c.args.cmd_whowas.target, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHOWAS command with one nickname failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whowaseight(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS a,b,c,d,e,f,g,h\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHOWAS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_whowas.num_nicknames == 8 &&
	    strcmp(c.args.cmd_whowas.nicknames[0], "a") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[1], "b") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[2], "c") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[3], "d") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[4], "e") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[5], "f") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[6], "g") == 0 &&
	    strcmp(c.args.cmd_whowas.nicknames[7], "h") == 0 &&
	    c.args.cmd_whowas.count == -1 &&
	    strcmp(c.args.cmd_whowas.target, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHOWAS command with eight nicknames failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_whowasnine(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS a,b,c,d,e,f,g,h,i\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect WHOWAS command with nine nicknames failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_whowasonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NONICKNAMEGIVEN) {
		printf("Incorrect WHOWAS command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_whowascount(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS foo bar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect WHOWAS command with invalid count failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_whowastarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WHOWAS foo 3 bar\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WHOWAS &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_whowas.num_nicknames == 1 &&
	    strcmp(c.args.cmd_whowas.nicknames[0], "foo") == 0 &&
	    c.args.cmd_whowas.count == 3 &&
	    strcmp(c.args.cmd_whowas.target, "bar") == 0) {
		++tests_passed;
	} else {
		printf("Correct WHOWAS command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_killonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KILL\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect KILL command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_killnick(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KILL nick\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect KILL command with nickname only failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_killcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("KILL foo :Stop your rude behavior!\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_KILL &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_kill.nickname, "foo") == 0 &&
	    strcmp(c.args.cmd_kill.comment, "Stop your rude behavior!") == 0) {
		++tests_passed;
	} else {
		printf("Correct KILL command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_pingonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PING\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NOORIGIN) {
		printf("Incorrect PING command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_pingserver(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PING tolsun.oulu.fi\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PING &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_ping_pong.server1, "tolsun.oulu.fi") == 0 &&
	    strcmp(c.args.cmd_ping_pong.server2, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct PING command with one server failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_pingserver2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PING WiZ tolsun.oulu.fi\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PING &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_ping_pong.server1, "WiZ") == 0 &&
	    strcmp(c.args.cmd_ping_pong.server2, "tolsun.oulu.fi") == 0) {
		++tests_passed;
	} else {
		printf("Correct PING command with two servers failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_pongonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PONG\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NOORIGIN) {
		printf("Incorrect PONG command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_pongserver(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PONG tolsun.oulu.fi\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PONG &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_ping_pong.server1, "tolsun.oulu.fi") == 0 &&
	    strcmp(c.args.cmd_ping_pong.server2, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct PONG command with one server failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_pongserver2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("PONG WiZ tolsun.oulu.fi\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_PONG &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_ping_pong.server1, "WiZ") == 0 &&
	    strcmp(c.args.cmd_ping_pong.server2, "tolsun.oulu.fi") == 0) {
		++tests_passed;
	} else {
		printf("Correct PONG command with two servers failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_erroronly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ERROR\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect ERROR command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_errorcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ERROR :The server is on fire\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_ERROR &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_error.error, "The server is on fire") == 0) {
		++tests_passed;
	} else {
		printf("Correct ERROR command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_awayonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("AWAY\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_AWAY &&
	    strlen(c.prefix) == 0 &&
	    strlen(c.args.cmd_away.text) == 0) {
		++tests_passed;
	} else {
		printf("Correct AWAY command with no text failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_awaytext(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("AWAY :afk, tornado\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_AWAY &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_away.text, "afk, tornado") == 0) {
		++tests_passed;
	} else {
		printf("Correct AWAY command with text failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_rehashcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("REHASH foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_REHASH &&
	    strlen(c.prefix) == 0) {
		++tests_passed;
	} else {
		printf("Correct REHASH command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_diecommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("DIE foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_DIE &&
	    strlen(c.prefix) == 0) {
		++tests_passed;
	} else {
		printf("Correct DIE command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_restartcommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("RESTART foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_RESTART &&
	    strlen(c.prefix) == 0) {
		++tests_passed;
	} else {
		printf("Correct RESTART command failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_summononly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SUMMON\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NORECIPIENT) {
		printf("Incorrect SUMMON command without arguments failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_summonuser(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SUMMON flynn\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SUMMON &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_summon.user, "flynn") == 0 &&
	    strcmp(c.args.cmd_summon.target, "") == 0 &&
	    strcmp(c.args.cmd_summon.channel, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct SUMMON command with user failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_summontarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SUMMON flynn localhost\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SUMMON &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_summon.user, "flynn") == 0 &&
	    strcmp(c.args.cmd_summon.target, "localhost") == 0 &&
	    strcmp(c.args.cmd_summon.channel, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct SUMMON command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_summonchannel(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("SUMMON flynn localhost #foo\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_SUMMON &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_summon.user, "flynn") == 0 &&
	    strcmp(c.args.cmd_summon.target, "localhost") == 0 &&
	    strcmp(c.args.cmd_summon.channel, "#foo") == 0) {
		++tests_passed;
	} else {
		printf("Correct SUMMON command with channel failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_usersonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_USERS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_users.target, "") == 0) {
		++tests_passed;
	} else {
		printf("Correct USERS command with no target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_userstarget(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERS target.example.com\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_USERS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_users.target, "target.example.com") == 0) {
		++tests_passed;
	} else {
		printf("Correct USERS command with target failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_wallopsonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WALLOPS\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect WALLOPS command with no text failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_wallopscommand(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("WALLOPS :It's time to kick ass and chew bubble gum\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_WALLOPS &&
	    strlen(c.prefix) == 0 &&
	    strcmp(c.args.cmd_wallops.text, "It's time to kick ass and chew bubble gum") == 0) {
		++tests_passed;
	} else {
		printf("Correct WALLOPS command with text failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_userhostonly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERHOST\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect USERHOST command with no nicknames failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_userhostone(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERHOST 23m foo 11s\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_USERHOST &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_userhost.num_nicknames == 1 &&
	    strcmp(c.args.cmd_userhost.nicknames[0], "foo") == 0) {
		++tests_passed;
	} else {
		printf("Correct USERHOST command with single nick failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_userhostfive(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERHOST foo bar baz big bang\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_USERHOST &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_userhost.num_nicknames == 5 &&
	    strcmp(c.args.cmd_userhost.nicknames[0], "foo") == 0 &&
	    strcmp(c.args.cmd_userhost.nicknames[1], "bar") == 0 &&
	    strcmp(c.args.cmd_userhost.nicknames[2], "baz") == 0 &&
	    strcmp(c.args.cmd_userhost.nicknames[3], "big") == 0 &&
	    strcmp(c.args.cmd_userhost.nicknames[4], "bang") == 0) {
		++tests_passed;
	} else {
		printf("Correct USERHOST command with five nicks failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_userhostsix(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("USERHOST foo bar baz big bang other\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect USERHOST command with six nicks failed to parse properly\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_isononly(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != ERR_NEEDMOREPARAMS) {
		printf("Incorrect ISON command with no nicks failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_isonall(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON a b c d e f g h i j k l m n o\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_ISON &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_ison.num_nicknames == 15 &&
	    strcmp(c.args.cmd_ison.nicknames[0], "a") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[1], "b") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[2], "c") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[3], "d") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[4], "e") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[5], "f") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[6], "g") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[7], "h") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[8], "i") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[9], "j") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[10], "k") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[11], "l") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[12], "m") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[13], "n") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[14], "o") == 0) {
		++tests_passed;
	} else {
		printf("Correct ISON command with maximum nicks failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_isonsome(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON a b c 11s e f g h i 23m k l m n o\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_ISON &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_ison.num_nicknames == 13 &&
	    strcmp(c.args.cmd_ison.nicknames[0], "a") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[1], "b") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[2], "c") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[3], "e") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[4], "f") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[5], "g") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[6], "h") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[7], "i") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[8], "k") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[9], "l") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[10], "m") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[11], "n") == 0 &&
	    strcmp(c.args.cmd_ison.nicknames[12], "o") == 0) {
		++tests_passed;
	} else {
		printf("Correct ISON command with a few wrong nicks failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_isontoomany(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("ISON a b c d e f g h i j k l m n o p\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect ISON command with too many nicks failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_cmodetoggle1(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan a-i+m-n+q-p+s-r+t\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.secret == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.topic == ACTION_ADD) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodetoggle2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan -a+i-m+n-q+p-s+r-t\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.secret == ACTION_REMOVE &&
	    c.args.cmd_mode.mode_args.type_chan.topic == ACTION_REMOVE) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (2) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodebadmask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan +b mask\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect MODE command due to bad mask failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_cmodemasks(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan b-e+I *!*@*.cn yaoming!*@* *!*@*.xxx\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 3 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_BANMASK &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "*!*@*.cn") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].mode == MODE_EXCEPTMASK &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].action == ACTION_REMOVE &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[1].param, "yaoming!*@*") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[2].mode == MODE_INVITEMASK &&
	    c.args.cmd_mode.mode_args.type_chan.others[2].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[2].param, "*!*@*.xxx") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (2) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodetoomanyargs(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan +oooo foo bar baz big\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) != PARSE_ERROR) {
		printf("Incorrect MODE command with too many args failed to return proper error\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_parse_cmodenicks(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan +oo-v foo bar baz\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 3 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_OPER &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "foo") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].mode == MODE_OPER &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[1].param, "bar") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[2].mode == MODE_VOICE &&
	    c.args.cmd_mode.mode_args.type_chan.others[2].action == ACTION_REMOVE &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[2].param, "baz") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (3) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodekeylimit1(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan -k+l key 50\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 2 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_KEY &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_REMOVE &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "key") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].mode == MODE_LIMIT &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[1].param, "50") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (4) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodekeylimit2(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #chan k-l secretpass\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#chan") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 2 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_KEY &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "secretpass") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].mode == MODE_LIMIT &&
	    c.args.cmd_mode.mode_args.type_chan.others[1].action == ACTION_REMOVE &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[1].param, "") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (5) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodeexample(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #Finnish +imI *!*@*.fi\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#Finnish") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 1 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_INVITEMASK &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "*!*@*.fi") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == ACTION_ADD &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command toggling modes (6) failed to parse properly\n");
		++tests_failed;
	}
}

void test_parse_cmodebanmask(void)
{
	init_structs();
	++tests_counter;
	assert(tokenize("MODE #Finnish b\r\n", &t) >= 0);
	if (parse_tokens(&t, &c) == 0 &&
	    c.number == CMD_MODE &&
	    strlen(c.prefix) == 0 &&
	    c.args.cmd_mode.mode_type == TYPE_CHAN &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.channel, "#Finnish") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.num_others == 1 &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].mode == MODE_BANMASK &&
	    c.args.cmd_mode.mode_args.type_chan.others[0].action == ACTION_ADD &&
	    strcmp(c.args.cmd_mode.mode_args.type_chan.others[0].param, "") == 0 &&
	    c.args.cmd_mode.mode_args.type_chan.anonymous == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.invite_only == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.moderated == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.no_outside == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.quiet == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.private_m == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.secret == NO_ACTION &&
	    c.args.cmd_mode.mode_args.type_chan.topic == NO_ACTION) {
		++tests_passed;
	} else {
		printf("Correct MODE command getting ban masks failed to parse properly\n");
		++tests_failed;
	}
}

int main()
{
	init_counters();

	test_empty();
	test_longline();
	test_notoks();
	test_prefixonly();
	test_suffixonly();
	test_nomiddlecommand();
	test_cmdonly();
	test_trailingspace();
	test_cronly();
	test_lfonly();
	test_prefixtok();
	test_prefixsuffix();
	test_singlewordsuffix();
	test_emptysuffix();
	test_nospacebeforesuffix();
	test_multispace();
	test_crinmiddle();
	test_lfinmiddle();
	test_17tokens();
	test_18tokens();

	test_parse_unknowncmd();
	test_parse_ison();
	test_parse_toomanyargs();
	test_parse_15args();
	test_parse_prefix15args();

	test_parse_passnopass();
	test_parse_passwithpassword();
	test_parse_passignoreextra();

	test_parse_nicknonick();
	test_parse_nickdigit();
	test_parse_nickdash();
	test_parse_nickpercent();
	test_parse_nicktoolong();
	test_parse_propernick1();
	test_parse_propernick2();
	test_parse_singlecharnick();

	test_parse_userneedmoreparams();
	test_parse_userinvaliduser();
	test_parse_userinvalidmode1();
	test_parse_userinvalidmode2();
	test_parse_usercommand();

	test_parse_invalidoper1();
	test_parse_invalidoper2();
	test_parse_opercommand();

	test_parse_modeargs();
	test_parse_modetarget();
	test_parse_umode();
	test_parse_umodeargs();

	test_parse_serviceneedmoreparams();
	test_parse_serviceinvalidnick();
	test_parse_servicecommand();

	test_parse_emptyquit();
	test_parse_singlewordquit();
	test_parse_multiwordquit();

	test_parse_squitbad();
	test_parse_squitcommand();

	test_parse_emptyjoin();
	test_parse_joinzero();
	test_parse_joinzerowithkey();
	test_parse_joinzerointhemiddle();
	test_parse_jointoomanytargets();
	test_parse_joineighttargets();
	test_parse_jointoomanykeys();
	test_parse_joineigthkeys();
	test_parse_joinkey();

	test_parse_partempty();
	test_parse_partinvalid();
	test_parse_partsingle();
	test_parse_partmultiwithreason();
	test_parse_partemptyweirdlist();

	test_parse_topicempty();
	test_parse_topiclongchanname();
	test_parse_topicmaxchanlength();
	test_parse_topicwithtopic();
	test_parse_topicemptytopic();

	test_parse_namesonechannel();
	test_parse_namesseveralchannels();
	test_parse_namestoomanychans();

	test_parse_listonechannel();
	test_parse_listseveralchannels();
	test_parse_listtoomanychans();

	test_parse_invitenoargs();
	test_parse_invitenickonly();
	test_parse_invitebadnick();
	test_parse_invitebadchan();
	test_parse_invitecommand();

	test_parse_kickoneone();
	test_parse_kickmultiple();
	test_parse_kicktoofewchans();
	test_parse_kicktoofewnicks();
	test_parse_kicktoomuchstuff();

	test_parse_privmsgnorecipient();
	test_parse_privmsgnotext();
	test_parse_privmsgcommand();
	test_parse_privmsgcommandchan();

	test_parse_noticenorecipient();
	test_parse_noticenotext();
	test_parse_noticecommand();
	test_parse_noticecommandchan();

	test_parse_motdnotarget();
	test_parse_motdcommand();

	test_parse_lusersalone();
	test_parse_lusersmask();
	test_parse_luserstarget();

	test_parse_versionalone();
	test_parse_versiontarget();

	test_parse_statsalone();
	test_parse_statsquery();
	test_parse_statstarget();
	test_parse_statsmultiletter();

	test_parse_linksonly();
	test_parse_linksmask();
	test_parse_linksremote();

	test_parse_timeonly();
	test_parse_timetarget();

	test_parse_connectonly();
	test_parse_connecttarget();
	test_parse_connectbadport();
	test_parse_connectbadport2();
	test_parse_connectbadport3();
	test_parse_connectgoodport();
	test_parse_connectgoodport2();
	test_parse_connectremote();

	test_parse_traceonly();
	test_parse_tracetarget();

	test_parse_adminonly();
	test_parse_admintarget();

	test_parse_infoonly();
	test_parse_infotarget();

	test_parse_servlist();
	test_parse_servlistmask();
	test_parse_servlisttype();

	test_parse_squery();
	test_parse_squeryservicename();
	test_parse_squerycommand();

	test_parse_who();
	test_parse_whonick();
	test_parse_whoo();
	test_parse_whomask();

	test_parse_whoisonly();
	test_parse_whoissingle();
	test_parse_whoistoomany();
	test_parse_whoistargeteight();

	test_parse_whowasone();
	test_parse_whowaseight();
	test_parse_whowasnine();
	test_parse_whowasonly();
	test_parse_whowascount();
	test_parse_whowastarget();

	test_parse_killonly();
	test_parse_killnick();
	test_parse_killcommand();

	test_parse_pingonly();
	test_parse_pingserver();
	test_parse_pingserver2();

	test_parse_pongonly();
	test_parse_pongserver();
	test_parse_pongserver2();

	test_parse_erroronly();
	test_parse_errorcommand();

	test_parse_awayonly();
	test_parse_awaytext();

	test_parse_rehashcommand();
	test_parse_diecommand();
	test_parse_restartcommand();

	test_parse_summononly();
	test_parse_summonuser();
	test_parse_summontarget();
	test_parse_summonchannel();

	test_parse_usersonly();
	test_parse_userstarget();
	
	test_parse_wallopsonly();
	test_parse_wallopscommand();

	test_parse_userhostonly();
	test_parse_userhostone();
	test_parse_userhostfive();
	test_parse_userhostsix();

	test_parse_isononly();
	test_parse_isonall();
	test_parse_isonsome();
	test_parse_isontoomany();

	test_parse_cmodetoggle1();
	test_parse_cmodetoggle2();
	test_parse_cmodebadmask();
	test_parse_cmodemasks();
	test_parse_cmodetoomanyargs();
	test_parse_cmodenicks();
	test_parse_cmodekeylimit1();
	test_parse_cmodekeylimit2();
	test_parse_cmodeexample();
	test_parse_cmodebanmask();

	return tests_summary();
}
