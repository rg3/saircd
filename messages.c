/*
 * Copyright 2012,2015 Ricardo Garcia Gonzalez
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
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include <pcre.h>

#include "messages.h"
#include "util.h"

/* Static functions. */
static int tokenize_callout(pcre_callout_block *b);

static int copy_trailing_token_to(const struct tokens *t, int tok, char *dst, size_t size);

static int valid_nickname(const char *nick);

static int valid_channel_name(const char *channel);

static int valid_user_name(const char *user);

static int valid_channel_mask(const char *mask);

static int parse_cmd_nick(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_user(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_oper(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_service(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_squit(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_topic(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_invite(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_privmsg(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_notice(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_stats(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_links(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_connect(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_squery(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_kill(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_ping_pong(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_summon(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_userhost(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_ison(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_join(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_part(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_names_list(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_kick(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_lusers(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_who(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_whois(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_whowas(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_servlist(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_mode(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_mode_nick(const struct tokens *t, int tok, struct command *c);

static int parse_cmd_mode_chan(const struct tokens *t, int tok, struct command *c);



void init_tokens(struct tokens *t)
{
	int i;

	t->counter = 0;
	for (i = 0; i < MAX_TOKENS; ++i)
		t->token[i][0] = '\0';
}

static int tokenize_callout(pcre_callout_block *b)
{
	struct tokens *t;
	int ret;
       
	t = (struct tokens *)(b->callout_data);

	/* Too many tokens. */
	if (t->counter >= MAX_TOKENS)
		return PCRE_ERROR_CALLOUT;

	ret = pcre_copy_substring(b->subject, b->offset_vector,
				  b->callout_number + 1, b->callout_number,
				  t->token[t->counter], MESSAGE_BUFFER_SIZE);
	assert(ret >= 0);
	t->counter += 1;
	return 0;
}

int tokenize(const char *line, struct tokens *t)
{
	static const char *re_str =
		"^"					/* SOL. */
		"(?:(:[^\\0\\r\\n\\ :]+)(?C1) +)?"	/* Optional prefix. */
		"([^\\0\\r\\n\\ :]+)(?C2)"		/* Command. */
		"(?: +([^\\0\\r\\n\\ :]+)(?C3))*"	/* Parameters. */
		"(?: +:([^\\0\\r\\n]*)(?C4))?"		/* Optional trailing. */
		" *?\r?\n$";				/* Opt SP and EOL. */
	static pcre *regexp = NULL;

	int ovector[5*3];
	int ret;
	int len;
	pcre_extra extra;

	/* Free memory if requested. */
	if (line == NULL && t == NULL) {
		if (regexp != NULL) {
			pcre_free(regexp);
			regexp = NULL;
		}
		return -3;
	}

	/* Compile expression. */
	if (regexp == NULL) {
		const char *errmsg;
		int erroffset;
		regexp = pcre_compile(re_str, 0, &errmsg, &erroffset, NULL);
		assert(regexp != NULL);
	}

	/* Check line length. */
	len = strlen(line);
	if (len > MAX_MESSAGE_LEN)
		return -1;

	/* Prepare for matching. */
	pcre_callout = tokenize_callout;
	extra.flags = PCRE_EXTRA_CALLOUT_DATA;
	extra.callout_data = (void *)(t);

	/* Matching. */
	ret = pcre_exec(regexp, &extra, line, len, 0, 0,
			ovector, sizeof(ovector) / sizeof(int));
	if (ret < 0)
		return -2;
	return t->counter;
}

void init_command(struct command *c)
{
	memset(c, 0, sizeof(struct command));
}

static int copy_trailing_token_to(const struct tokens *t, int tok, char *dst, size_t size)
{
	if (tok >= t->counter)
		return 0;
	xstrlcpy(dst, t->token[tok], size);
	return 1;
}

static int valid_nickname(const char *nick)
{
	static const char *re_str = "^[a-zA-Z\\\\\\[\\]`_^{\\|}][a-zA-Z0-9\\\\\\[\\]`_^{\\|}\\-]{0,8}$";
	static pcre *regexp = NULL;

	int ovector[3];

	/* Free memory if requested. */
	if (nick == NULL) {
		if (regexp != NULL) {
			pcre_free(regexp);
			regexp = NULL;
		}
		return 0;
	}

	/* Compile expression. */
	if (regexp == NULL) {
		const char *errmsg;
		int erroffset;
		regexp = pcre_compile(re_str, 0, &errmsg, &erroffset, NULL);
		assert(regexp != NULL);
	}

	/* Try match. */
	return (pcre_exec(regexp, NULL, nick, strlen(nick), 0, 0,
			  ovector, sizeof(ovector) / sizeof(int)) >= 0);
}

static int valid_channel_name(const char *channel)
{
	static const char *re_str = "^[&#][^\\ \\007,:]{1,49}$";
	static pcre *regexp = NULL;

	int ovector[3];

	/* Free memory if requested. */
	if (channel == NULL) {
		if (regexp != NULL) {
			pcre_free(regexp);
			regexp = NULL;
		}
		return 0;
	}

	/* Compile expression. */
	if (regexp == NULL) {
		const char *errmsg;
		int erroffset;
		regexp = pcre_compile(re_str, 0, &errmsg, &erroffset, NULL);
		assert(regexp != NULL);
	}

	/* Try match. */
	return (pcre_exec(regexp, NULL, channel, strlen(channel), 0, 0,
			  ovector, sizeof(ovector) / sizeof(int)) >= 0);
}

static int valid_user_name(const char *user)
{
	static const char *re_str = "^[^\\000\\r\\n\\ @%!]+$";
	static pcre *regexp = NULL;

	int ovector[3];

	/* Free memory if requested. */
	if (user == NULL) {
		if (regexp != NULL) {
			pcre_free(regexp);
			regexp = NULL;
		}
		return 0;
	}

	/* Compile expression. */
	if (regexp == NULL) {
		const char *errmsg;
		int erroffset;
		regexp = pcre_compile(re_str, 0, &errmsg, &erroffset, NULL);
		assert(regexp != NULL);
	}

	/* Try match. */
	return (pcre_exec(regexp, NULL, user, strlen(user), 0, 0,
			  ovector, sizeof(ovector) / sizeof(int)) >= 0);
}

static int valid_channel_mask(const char *mask)
{
	static const char *re_str = "^"
		"[^\\000\\r\\n\\ !]+!" /* Nickname. */
		"[^\\000\\r\\n\\ @]+@" /* User (ident). */
		"[^\\000\\r\\n\\ ]+"   /* Hostname. */
		"$";
	static pcre *regexp = NULL;

	int ovector[3];

	/* Free memory if requested. */
	if (mask == NULL) {
		if (regexp != NULL) {
			pcre_free(regexp);
			regexp = NULL;
		}
		return 0;
	}

	/* Compile expression. */
	if (regexp == NULL) {
		const char *errmsg;
		int erroffset;
		regexp = pcre_compile(re_str, 0, &errmsg, &erroffset, NULL);
		assert(regexp != NULL);
	}

	/* Try match. */
	return (pcre_exec(regexp, NULL, mask, strlen(mask), 0, 0,
			  ovector, sizeof(ovector) / sizeof(int)) >= 0);
}

static int parse_cmd_nick(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok <= 0)
		return ERR_NONICKNAMEGIVEN;

	xstrlcpy(c->args.cmd_nick.nickname, t->token[tok], sizeof(c->args.cmd_nick.nickname));

	if (! valid_nickname(t->token[tok]))
		return ERR_ERRONEUSNICKNAME;

	return 0;
}

static int parse_cmd_user(const struct tokens *t, int tok, struct command *c)
{
	long value;
	char *endptr;

	if (t->counter - tok < 4) /* 4 arguments are needed. */
		return ERR_NEEDMOREPARAMS;

	/* user */
	if (! valid_user_name(t->token[tok]))
		return PARSE_ERROR;
	xstrlcpy(c->args.cmd_user.user, t->token[tok], sizeof(c->args.cmd_user.user));

	/* mode */
	value = strtol(t->token[tok+1], &endptr, 10);
	if (value < 0 || value > INT_MAX || endptr != t->token[tok+1] + strlen(t->token[tok+1]))
		value = 0;

	c->args.cmd_user.mode = (int)value;

	/* Third argument is ignored. */

	/* realname */
	xstrlcpy(c->args.cmd_user.realname, t->token[tok+3], sizeof(c->args.cmd_user.realname));

	return 0;
}

static int parse_cmd_oper(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 2) /* 2 arguments are needed. */
		return ERR_NEEDMOREPARAMS;

	xstrlcpy(c->args.cmd_oper.name, t->token[tok], sizeof(c->args.cmd_oper.name));
	xstrlcpy(c->args.cmd_oper.password, t->token[tok+1], sizeof(c->args.cmd_oper.password));

	return 0;
}

static int parse_cmd_service(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 6) /* 6 arguments are needed. */
		return ERR_NEEDMOREPARAMS;

	if (! valid_nickname(t->token[tok]))
		return ERR_ERRONEUSNICKNAME;

	/* Arguments 1 and 4 are reserved and unused. */
	xstrlcpy(c->args.cmd_service.nickname, t->token[tok], sizeof(c->args.cmd_service.nickname));
	xstrlcpy(c->args.cmd_service.distribution, t->token[tok+2], sizeof(c->args.cmd_service.distribution));
	xstrlcpy(c->args.cmd_service.type, t->token[tok+3], sizeof(c->args.cmd_service.type));
	xstrlcpy(c->args.cmd_service.info, t->token[tok+5], sizeof(c->args.cmd_service.info));

	return 0;
}

static int parse_cmd_squit(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 2) /* 2 arguments are needed. */
		return ERR_NEEDMOREPARAMS;

	xstrlcpy(c->args.cmd_squit.server, t->token[tok], sizeof(c->args.cmd_squit.server));
	xstrlcpy(c->args.cmd_squit.comment, t->token[tok+1], sizeof(c->args.cmd_squit.comment));

	return 0;
}

static int parse_cmd_topic(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1) /* At least one argument. */
		return ERR_NEEDMOREPARAMS;

	xstrlcpy(c->args.cmd_topic.channel, t->token[tok], sizeof(c->args.cmd_topic.channel));

	if (t->counter - tok >= 2) { /* Topic message was given. */
		xstrlcpy(c->args.cmd_topic.topic, t->token[tok+1], sizeof(c->args.cmd_topic.topic));
		c->args.cmd_topic.topic_given = 1;
	} else {
		c->args.cmd_topic.topic[0] = '\0';
		c->args.cmd_topic.topic_given = 0;
	}

	return 0;
}

static int parse_cmd_invite(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 2) /* 2 arguments are needed. */
		return ERR_NEEDMOREPARAMS;

	if (! valid_nickname(t->token[tok]))
		return ERR_NOSUCHNICK;

	if (! valid_channel_name(t->token[tok+1]))
		return PARSE_ERROR;

	xstrlcpy(c->args.cmd_invite.nickname, t->token[tok], sizeof(c->args.cmd_invite.nickname));
	xstrlcpy(c->args.cmd_invite.channel, t->token[tok+1], sizeof(c->args.cmd_invite.channel));

	return 0;
}

static int parse_cmd_privmsg(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1)
		return ERR_NORECIPIENT;
	if (t->counter - tok < 2)
		return ERR_NOTEXTTOSEND;

	/* Message target. */
	if (valid_nickname(t->token[tok])) {
		c->args.cmd_privmsg.target_type = TYPE_NICK;
		xstrlcpy(c->args.cmd_privmsg.target.nickname, t->token[tok], sizeof(c->args.cmd_privmsg.target.nickname));
	} else if (valid_channel_name(t->token[tok])) {
		c->args.cmd_privmsg.target_type = TYPE_CHAN;
		xstrlcpy(c->args.cmd_privmsg.target.channel, t->token[tok], sizeof(c->args.cmd_privmsg.target.channel));
	} else {
		return PARSE_ERROR;
	}

	/* Message text. */
	xstrlcpy(c->args.cmd_privmsg.text, t->token[tok+1], sizeof(c->args.cmd_privmsg.text));

	return 0;
}

static int parse_cmd_notice(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 2)
		return PARSE_ERROR;

	/* Notice target. */
	if (valid_nickname(t->token[tok])) {
		c->args.cmd_notice.target_type = TYPE_NICK;
		xstrlcpy(c->args.cmd_notice.target.nickname, t->token[tok], sizeof(c->args.cmd_notice.target.nickname));
	} else if (valid_channel_name(t->token[tok])) {
		c->args.cmd_notice.target_type = TYPE_CHAN;
		xstrlcpy(c->args.cmd_notice.target.channel, t->token[tok], sizeof(c->args.cmd_notice.target.channel));
	} else {
		return PARSE_ERROR;
	}

	/* Notice text. */
	xstrlcpy(c->args.cmd_notice.text, t->token[tok+1], sizeof(c->args.cmd_notice.text));

	return 0;
}

static int parse_cmd_stats(const struct tokens *t, int tok, struct command *c)
{
	/* Default values. */
	c->args.cmd_stats.query = '\0';
	c->args.cmd_stats.target[0] = '\0';

	if (t->counter - tok < 1)
		return 0;

	if (strlen(t->token[tok]) > 1)
		return PARSE_ERROR;

	/* Single query character. */
	c->args.cmd_stats.query = t->token[tok][0];

	if (t->counter - tok < 2)
		return 0;

	/* Target argument. */
	xstrlcpy(c->args.cmd_stats.target, t->token[tok+1], sizeof(c->args.cmd_stats.target));

	return 0;
}

static int parse_cmd_links(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok <= 0) {
		c->args.cmd_links.remote_server[0] = '\0';
		c->args.cmd_links.server_mask[0] = '\0';
	} else if (t->counter - tok == 1) {
		c->args.cmd_links.remote_server[0] = '\0';
		xstrlcpy(c->args.cmd_links.server_mask, t->token[tok], sizeof(c->args.cmd_links.server_mask));
	} else {
		xstrlcpy(c->args.cmd_links.remote_server, t->token[tok], sizeof(c->args.cmd_links.remote_server));
		xstrlcpy(c->args.cmd_links.server_mask, t->token[tok+1], sizeof(c->args.cmd_links.server_mask));
	}

	return 0;
}

static int parse_cmd_connect(const struct tokens *t, int tok, struct command *c)
{
	long port;
	char *endptr;

	if (t->counter - tok < 2)
		return ERR_NEEDMOREPARAMS;

	/* Parse port. */
	port = strtol(t->token[tok+1], &endptr, 10);
	if (endptr != t->token[tok+1] + strlen(t->token[tok+1]))
		return PARSE_ERROR;

	if (port <= 0 || port > 65535) /* 65535 is the highest port number. */
		return PARSE_ERROR;

	/* Target server and port. */
	xstrlcpy(c->args.cmd_connect.target_server, t->token[tok], sizeof(c->args.cmd_connect.target_server));
	c->args.cmd_connect.port = (int)port;

	/* Remote server if present. */
	if (t->counter - tok >= 3)
		xstrlcpy(c->args.cmd_connect.remote_server, t->token[tok+2], sizeof(c->args.cmd_connect.remote_server));
	else
		c->args.cmd_connect.remote_server[0] = '\0';
	return 0;
}

static int parse_cmd_squery(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1)
		return ERR_NORECIPIENT;

	if (! valid_nickname(t->token[tok]))
		return ERR_NORECIPIENT;

	if (t->counter - tok < 2)
		return ERR_NOTEXTTOSEND;

	xstrlcpy(c->args.cmd_squery.servicename, t->token[tok], sizeof(c->args.cmd_squery.servicename));
	xstrlcpy(c->args.cmd_squery.text, t->token[tok+1], sizeof(c->args.cmd_squery.text));

	return 0;
}

static int parse_cmd_kill(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 2)
		return ERR_NEEDMOREPARAMS;

	xstrlcpy(c->args.cmd_kill.nickname, t->token[tok], sizeof(c->args.cmd_kill.nickname));
	xstrlcpy(c->args.cmd_kill.comment, t->token[tok+1], sizeof(c->args.cmd_kill.comment));

	return 0;
}

static int parse_cmd_ping_pong(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1)
		return ERR_NOORIGIN;

	/* server1 */
	xstrlcpy(c->args.cmd_ping_pong.server1, t->token[tok], sizeof(c->args.cmd_ping_pong.server1));

	/* server2 if present. */
	if (t->counter - tok >= 2)
		xstrlcpy(c->args.cmd_ping_pong.server2, t->token[tok+1], sizeof(c->args.cmd_ping_pong.server2));
	else
		c->args.cmd_ping_pong.server2[0] = '\0';

	return 0;
}

static int parse_cmd_summon(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1)
		return ERR_NORECIPIENT;

	xstrlcpy(c->args.cmd_summon.user, t->token[tok], sizeof(c->args.cmd_summon.user));

	if (t->counter - tok >= 2) {
		xstrlcpy(c->args.cmd_summon.target, t->token[tok+1], sizeof(c->args.cmd_summon.target));
		if (t->counter - tok >= 3) {
			if (! valid_channel_name(t->token[tok+2]))
				return PARSE_ERROR;
			xstrlcpy(c->args.cmd_summon.channel, t->token[tok+2], sizeof(c->args.cmd_summon.channel));
		} else {
			c->args.cmd_summon.channel[0] = '\0';
		}
	} else {
		c->args.cmd_summon.target[0] = '\0';
		c->args.cmd_summon.channel[0] = '\0';
	}

	return 0;
}

static int parse_cmd_userhost(const struct tokens *t, int tok, struct command *c)
{
	int num_nicks;
	int num_args;
	int i;

	num_args = t->counter - tok;

	if (num_args < 1)
		return ERR_NEEDMOREPARAMS;

	if (num_args > MAX_USERHOST_NICKNAMES)
		return PARSE_ERROR;

	num_nicks = 0;
	for (i = 0; i < num_args; ++i) {
		if (! valid_nickname(t->token[tok+i]))
			continue;
		xstrlcpy(c->args.cmd_userhost.nicknames[num_nicks],
			 t->token[tok+i],
			 sizeof(c->args.cmd_userhost.nicknames[num_nicks]));
		++num_nicks;
	}
	c->args.cmd_userhost.num_nicknames = num_nicks;

	return 0;
}

static int parse_cmd_ison(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *nick;

	int num_args;
	int num_nicks;
	int i;

	num_args = t->counter - tok;

	if (num_args < 1)
		return ERR_NEEDMOREPARAMS;

	for (num_nicks = 0, i = 0; i < num_args; ++i) {
		xstrlcpy(token, t->token[tok+i], sizeof(token));
		nick = strtok_r(token, " ", &saveptr);
		while (nick != NULL) {
			if (num_nicks < MAX_MESSAGE_PARAMS && valid_nickname(nick)) {
				xstrlcpy(c->args.cmd_ison.nicknames[num_nicks], nick, sizeof(c->args.cmd_ison.nicknames[num_nicks]));
				++num_nicks;
			}

			nick = strtok_r(NULL, " ", &saveptr);
		}
	}
	c->args.cmd_ison.num_nicknames = num_nicks;

	return 0;
}

static int parse_cmd_join(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *chan;
	char *key;
	int i;

	if (t->counter - tok < 1)
		return ERR_NEEDMOREPARAMS;

	/* JOIN 0 */
	if (t->counter - tok == 1 && strcmp(t->token[tok], "0") == 0) {
		c->args.cmd_join.num_channels = 1;
		xstrlcpy(c->args.cmd_join.channels[0], "0", sizeof(c->args.cmd_join.channels[0]));
		c->args.cmd_join.num_keys = 0;
		return 0;
	}

	c->args.cmd_join.num_channels = 0;
	c->args.cmd_join.num_keys = 0;

	/* Parse channel list. */
	i = 0;
	xstrlcpy(token, t->token[tok], sizeof(token));
	chan = strtok_r(token, ",", &saveptr);

	while (chan != NULL) {
		if (! valid_channel_name(chan))
			return PARSE_ERROR;

		if (i >= MAX_TARGETS)
			return ERR_TOOMANYTARGETS;

		xstrlcpy(c->args.cmd_join.channels[i], chan, sizeof(c->args.cmd_join.channels[i]));
		++i;

		chan = strtok_r(NULL, ",", &saveptr);
	}
	c->args.cmd_join.num_channels = i;

	if (i == 0)
		return PARSE_ERROR;

	/* No keys. */
	if (t->counter - tok == 1)
		return 0;

	/* Parse key list. */
	i = 0;
	xstrlcpy(token, t->token[tok+1], sizeof(token));
	key = strtok_r(token, ",", &saveptr);

	while (key != NULL) {
		if (strlen(key) > MAX_MESSAGE_LEN)
			return PARSE_ERROR;

		if (i >= MAX_TARGETS)
			return ERR_TOOMANYTARGETS;

		xstrlcpy(c->args.cmd_join.keys[i], key, sizeof(c->args.cmd_join.keys[i]));
		++i;

		key = strtok_r(NULL, ",", &saveptr);
	}
	c->args.cmd_join.num_keys = i;

	return 0;
}

static int parse_cmd_part(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *chan;
	int i;

	if (t->counter - tok < 1)
		return ERR_NEEDMOREPARAMS;

	/* Parse channel list. */
	i = 0;
	xstrlcpy(token, t->token[tok], sizeof(token));
	chan = strtok_r(token, ",", &saveptr);

	while (chan != NULL) {
		if (valid_channel_name(chan)) {
			if (i >= MAX_TARGETS)
				return ERR_TOOMANYTARGETS;
			xstrlcpy(c->args.cmd_part.channels[i], chan, sizeof(c->args.cmd_part.channels[i]));
			++i;
		}
		chan = strtok_r(NULL, ",", &saveptr);
	}
	c->args.cmd_part.num_channels = i;

	if (i == 0)
		return PARSE_ERROR;

	/* Part message. */
	if (t->counter - tok >= 2)
		xstrlcpy(c->args.cmd_part.message, t->token[tok+1], sizeof(c->args.cmd_part.message));
	else
		c->args.cmd_part.message[0] = '\0';

	return 0;
}

static int parse_cmd_names_list(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *chan;
	int i;

	/* No arguments. */
	if (t->counter - tok <= 0) {
		c->args.cmd_names_list.num_channels = 0;
		c->args.cmd_names_list.target[0] = '\0';
		return 0;
	}

	/* Parse channel list. */
	i = 0;
	xstrlcpy(token, t->token[tok], sizeof(token));
	chan = strtok_r(token, ",", &saveptr);

	while (chan != NULL) {
		if (valid_channel_name(chan)) {
			if (i >= MAX_TARGETS)
				return PARSE_ERROR;
			xstrlcpy(c->args.cmd_names_list.channels[i], chan, sizeof(c->args.cmd_names_list.channels[i]));
			++i;
		}
		chan = strtok_r(NULL, ",", &saveptr);
	}
	c->args.cmd_names_list.num_channels = i;

	if (i == 0)
		return PARSE_ERROR;

	/* Target. */
	if (t->counter - tok >= 2)
		xstrlcpy(c->args.cmd_names_list.target, t->token[tok+1], sizeof(c->args.cmd_names_list.target));
	else
		c->args.cmd_names_list.target[0] = '\0';

	return 0;
}

static int parse_cmd_kick(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *chan;
	char *nick;
	int i;

	if (t->counter - tok < 2)
		return ERR_NEEDMOREPARAMS;

	c->args.cmd_kick.num_channels = 0;
	c->args.cmd_kick.num_nicknames = 0;

	/* Parse channel list. */
	i = 0;
	xstrlcpy(token, t->token[tok], sizeof(token));
	chan = strtok_r(token, ",", &saveptr);

	while (chan != NULL) {
		if (! valid_channel_name(chan))
			return PARSE_ERROR;

		if (i >= MAX_TARGETS)
			return PARSE_ERROR;

		xstrlcpy(c->args.cmd_kick.channels[i], chan, sizeof(c->args.cmd_kick.channels[i]));
		c->args.cmd_kick.num_channels = ++i;

		chan = strtok_r(NULL, ",", &saveptr);
	}

	if (i == 0)
		return PARSE_ERROR;

	/* Parse nickname list. */
	i = 0;
	xstrlcpy(token, t->token[tok+1], sizeof(token));
	nick = strtok_r(token, ",", &saveptr);

	while (nick != NULL) {
		if (! valid_nickname(nick))
			return PARSE_ERROR;

		if (i >= MAX_TARGETS)
			return PARSE_ERROR;

		xstrlcpy(c->args.cmd_kick.nicknames[i], nick, sizeof(c->args.cmd_kick.nicknames[i]));
		c->args.cmd_kick.num_nicknames = ++i;

		nick = strtok_r(NULL, ",", &saveptr);
	}
	
	if (i == 0)
		return PARSE_ERROR;

	/* Either one channel and multiple nicknames, or as many nicknames as
	 * channels. */
	if (c->args.cmd_kick.num_channels != 1 &&
	    c->args.cmd_kick.num_channels != c->args.cmd_kick.num_nicknames)
		return PARSE_ERROR;

	/* Kick comment. */
	if (t->counter - tok >= 3)
		xstrlcpy(c->args.cmd_kick.comment, t->token[tok+2], sizeof(c->args.cmd_kick.comment));
	else
		c->args.cmd_kick.comment[0] = '\0';

	return 0;
}

static int parse_cmd_lusers(const struct tokens *t, int tok, struct command *c)
{
	/* Mask. */
	if (t->counter - tok >= 1)
		xstrlcpy(c->args.cmd_lusers.mask, t->token[tok], sizeof(c->args.cmd_lusers.mask));
	else {
		c->args.cmd_lusers.mask[0] = '\0';
		c->args.cmd_lusers.target[0] = '\0';
	}

	/* Target. */
	if (t->counter - tok >= 2)
		xstrlcpy(c->args.cmd_lusers.target, t->token[tok+1], sizeof(c->args.cmd_lusers.target));
	else
		c->args.cmd_lusers.target[0] = '\0';

	return 0;
}

static int parse_cmd_who(const struct tokens *t, int tok, struct command *c)
{
	/* Default values. */
	c->args.cmd_who.target_type = TYPE_OTHER;
	c->args.cmd_who.target.nickname[0] = '\0';
	c->args.cmd_who.target.channel[0] = '\0';
	c->args.cmd_who.target.mask[0] = '\0';
	c->args.cmd_who.o = 0;

	if (t->counter - tok < 1)
		return 0;

	/* Mask. */
	if (valid_channel_name(t->token[tok])) {
		c->args.cmd_who.target_type = TYPE_CHAN;
		xstrlcpy(c->args.cmd_who.target.channel, t->token[tok], sizeof(c->args.cmd_who.target.channel));
	} else if (valid_nickname(t->token[tok])) {
		c->args.cmd_who.target_type = TYPE_NICK;
		xstrlcpy(c->args.cmd_who.target.nickname, t->token[tok], sizeof(c->args.cmd_who.target.nickname));
	} else
		xstrlcpy(c->args.cmd_who.target.mask, t->token[tok], sizeof(c->args.cmd_who.target.mask));

	/* Possible second "o" argument. */
	if (t->counter - tok >= 2) {
		if (strcmp(t->token[tok+1], "o") == 0)
			c->args.cmd_who.o = 1;
		else
			return PARSE_ERROR;
	} else
		c->args.cmd_who.o = 0;

	return 0;
}

static int parse_cmd_whois(const struct tokens *t, int tok, struct command *c)
{
	int list_token;
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *nick;
	int i;

	if (t->counter - tok < 1)
		return ERR_NONICKNAMEGIVEN;

	/* Possible "target" in between. */
	if (t->counter - tok >= 2) {
		list_token = tok + 1;
		xstrlcpy(c->args.cmd_whois.target, t->token[tok], sizeof(c->args.cmd_whois.target));
	} else {
		list_token = tok;
		c->args.cmd_whois.target[0] = '\0';
	}

	/* Save original query string. */
	xstrlcpy(c->args.cmd_whois.orig_query, t->token[list_token], sizeof(c->args.cmd_whois.orig_query));

	/* Parse nickname list. */
	i = 0;
	xstrlcpy(token, t->token[list_token], sizeof(token));
	nick = strtok_r(token, ",", &saveptr);

	while (nick != NULL) {
		if (i >= MAX_TARGETS)
			return PARSE_ERROR;

		xstrlcpy(c->args.cmd_whois.nicknames[i], nick, sizeof(c->args.cmd_whois.nicknames[i]));
		++i;

		nick = strtok_r(NULL, ",", &saveptr);
	}
	c->args.cmd_whois.num_nicknames = i;
	
	if (i == 0)
		return ERR_NONICKNAMEGIVEN;

	return 0;
}

static int parse_cmd_whowas(const struct tokens *t, int tok, struct command *c)
{
	char token[MESSAGE_BUFFER_SIZE];
	char *saveptr;
	char *nick;
	int i;

	if (t->counter - tok < 1)
		return ERR_NONICKNAMEGIVEN;

	/* Parse nickname list. */
	i = 0;
	xstrlcpy(token, t->token[tok], sizeof(token));
	nick = strtok_r(token, ",", &saveptr);

	while (nick != NULL) {
		if (i >= MAX_TARGETS)
			return PARSE_ERROR;

		xstrlcpy(c->args.cmd_whowas.nicknames[i], nick, sizeof(c->args.cmd_whowas.nicknames[i]));
		c->args.cmd_whowas.num_nicknames = ++i;

		nick = strtok_r(NULL, ",", &saveptr);
	}
	
	if (i == 0)
		return ERR_NONICKNAMEGIVEN;

	/* Possible "count" argument. */
	if (t->counter - tok >= 2) {
		long aux;
		char *endptr;

		aux = strtol(t->token[tok+1], &endptr, 10);
		if (endptr != t->token[tok+1] + strlen(t->token[tok+1]))
			return PARSE_ERROR;

		if (aux < INT_MIN || aux > INT_MAX)
			return PARSE_ERROR;

		c->args.cmd_whowas.count = (int)aux;

	} else {
		c->args.cmd_whowas.count = -1;
		c->args.cmd_whowas.target[0] = '\0';
	}

	/* Possible "target" argument. */
	if (t->counter - tok >= 3)
		xstrlcpy(c->args.cmd_whowas.target, t->token[tok+2], sizeof(c->args.cmd_whowas.target));
	else
		c->args.cmd_whowas.target[0] = '\0';

	return 0;
}

static int parse_cmd_servlist(const struct tokens *t, int tok, struct command *c)
{
	/* Mask. */
	if (t->counter - tok >= 1)
		xstrlcpy(c->args.cmd_servlist.mask, t->token[tok], sizeof(c->args.cmd_servlist.mask));
	else {
		c->args.cmd_servlist.mask[0] = '\0';
		c->args.cmd_servlist.type[0] = '\0';
	}

	/* Type. */
	if (t->counter - tok >= 2)
		xstrlcpy(c->args.cmd_servlist.type, t->token[tok+1], sizeof(c->args.cmd_servlist.type));
	else
		c->args.cmd_servlist.type[0] = '\0';

	return 0;
}

static int parse_cmd_mode(const struct tokens *t, int tok, struct command *c)
{
	if (t->counter - tok < 1)
		return ERR_NEEDMOREPARAMS;

	if (valid_nickname(t->token[tok])) {
		/* User mode. */
		c->args.cmd_mode.mode_type = TYPE_NICK;
		return parse_cmd_mode_nick(t, tok, c);
	}

	if (valid_channel_name(t->token[tok])) {
		/* Channel mode. */
		c->args.cmd_mode.mode_type = TYPE_CHAN;
		return parse_cmd_mode_chan(t, tok, c);
	}

	return PARSE_ERROR;
}

static int parse_cmd_mode_nick(const struct tokens *t, int tok, struct command *c)
{
	enum action_flag ca; /* Current action. */
	int len;
	int i;
	int retcode;

	if (t->counter - tok < 1)
		return ERR_NEEDMOREPARAMS;
	if (! valid_nickname(t->token[tok]))
		return PARSE_ERROR;

	/* Copy the nickname. */
	xstrlcpy(c->args.cmd_mode.mode_args.type_nick.nickname, t->token[tok], sizeof(c->args.cmd_mode.mode_args.type_nick.nickname));

	/* Disable all action flags up-front. */
	c->args.cmd_mode.mode_args.type_nick.away = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.invisible = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.wallops = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.restricted = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.net_operator = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.local_operator = NO_ACTION;
	c->args.cmd_mode.mode_args.type_nick.notices = NO_ACTION;

	/* Parse the mode string. */
	if (t->counter - tok < 2) {
		return 0;
	}

	retcode = 0;
	ca = ACTION_ADD;
	len = strlen(t->token[tok+1]);
	for (i = 0; i < len; ++i) {
		switch (t->token[tok+1][i]) {
		case '+':
			ca = ACTION_ADD;
			break;
		case '-':
			ca = ACTION_REMOVE;
			break;
		case 'a':
			c->args.cmd_mode.mode_args.type_nick.away = ca;
			break;
		case 'i':
			c->args.cmd_mode.mode_args.type_nick.invisible = ca;
			break;
		case 'w':
			c->args.cmd_mode.mode_args.type_nick.wallops = ca;
			break;
		case 'r':
			c->args.cmd_mode.mode_args.type_nick.restricted = ca;
			break;
		case 'o':
			c->args.cmd_mode.mode_args.type_nick.net_operator = ca;
			break;
		case 'O':
			c->args.cmd_mode.mode_args.type_nick.local_operator = ca;
			break;
		case 's':
			c->args.cmd_mode.mode_args.type_nick.notices = ca;
			break;
		default:
			retcode = ERR_UMODEUNKNOWNFLAG;
			break;
		}
	}

	return retcode;
}

static int parse_cmd_mode_chan(const struct tokens *t, int tok, struct command *c)
{
	int modetok; /* Current token we are extracting mode chars from. */
	int nexttok; /* Token to be consumed next. */
	int len;
	enum action_flag ca; /* Current action. */

	int i;
	int j;
	int i_unk;

	long aux;
	char *endptr;

	if (t->counter - tok < 1)
		return PARSE_ERROR;

	if (! valid_channel_name(t->token[tok]))
		return PARSE_ERROR;

	/* Extract channel name and disable everything by default. */
	xstrlcpy(c->args.cmd_mode.mode_args.type_chan.channel, t->token[tok], sizeof(c->args.cmd_mode.mode_args.type_chan.channel));
	c->args.cmd_mode.mode_args.type_chan.anonymous = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.invite_only = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.moderated = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.no_outside = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.quiet = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.private_m = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.secret = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.topic = NO_ACTION;
	c->args.cmd_mode.mode_args.type_chan.num_others = 0;
	c->args.cmd_mode.mode_args.type_chan.unknown_modes[0] = '\0';

	/* No more arguments. */
	if (t->counter - tok < 2)
		return 0;

	i_unk = 0;
	modetok = tok + 1;
	nexttok = modetok + 1;

	while (modetok < t->counter) {
		ca = ACTION_ADD;
		len = strlen(t->token[modetok]);
		for (i = 0; i < len; ++i) {
			switch (t->token[modetok][i]) {
			case '+':
				ca = ACTION_ADD;
				break;
			case '-':
				ca = ACTION_REMOVE;
				break;
			case 'a':
				c->args.cmd_mode.mode_args.type_chan.anonymous = ca;
				break;
			case 'i':
				c->args.cmd_mode.mode_args.type_chan.invite_only = ca;
				break;
			case 'm':
				c->args.cmd_mode.mode_args.type_chan.moderated = ca;
				break;
			case 'n':
				c->args.cmd_mode.mode_args.type_chan.no_outside = ca;
				break;
			case 'q':
				c->args.cmd_mode.mode_args.type_chan.quiet = ca;
				break;
			case 'p':
				c->args.cmd_mode.mode_args.type_chan.private_m = ca;
				if (ca == ACTION_ADD)
					c->args.cmd_mode.mode_args.type_chan.secret = ACTION_REMOVE;
				break;
			case 's':
				c->args.cmd_mode.mode_args.type_chan.secret = ca;
				if (ca == ACTION_ADD)
					c->args.cmd_mode.mode_args.type_chan.private_m = ACTION_REMOVE;
				break;
			case 't':
				c->args.cmd_mode.mode_args.type_chan.topic = ca;
				break;

				/*
				 * The following modes may consume a new token
				 * and make nexttok advance.
				 */
			case 'o':
				/* Ignore if its required argument is missing. */
				if (nexttok >= t->counter)
					break;

				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;
				if (! valid_nickname(t->token[nexttok]))
					return PARSE_ERROR;

				/* All tests passed. */
				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_OPER;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;
				xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;
				++nexttok;

				break;
			case 'v':
				/* Ignore if its required argument is missing. */
				if (nexttok >= t->counter)
					break;

				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;
				if (! valid_nickname(t->token[nexttok]))
					return PARSE_ERROR;

				/* All tests passed. */
				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_VOICE;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;
				xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;
				++nexttok;

				break;
			case 'k':
				/* Ignore if its required argument is missing. */
				if (nexttok >= t->counter)
					break;

				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;

				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_KEY;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;
				xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;
				++nexttok;

				break;
			case 'l':
				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;

				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_LIMIT;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;

				/* If the limit is to be set, consume token. */
				if (ca == ACTION_ADD) {
					if (nexttok >= t->counter)
						return ERR_NEEDMOREPARAMS;

					/* Verify valid numeric limit. */
					aux = strtol(t->token[nexttok], &endptr, 10);
					if (aux < 1 || aux > INT_MAX)
						return PARSE_ERROR;
					if (endptr != t->token[nexttok] + strlen(t->token[nexttok]))
						return PARSE_ERROR;

					xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));
					++nexttok;
				} else
					c->args.cmd_mode.mode_args.type_chan.others[j].param[0] = '\0';

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;

				break;
			case 'b':
				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;

				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_BANMASK;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;

				/*
				 * Save the banmask if it was given. Otherwise,
				 * it will be a request to list the bans.
				 */
				if (nexttok < t->counter) {
					if (! valid_channel_mask(t->token[nexttok]))
						return PARSE_ERROR;
					xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));
					++nexttok;
				} else
					c->args.cmd_mode.mode_args.type_chan.others[j].param[0] = '\0';

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;

				break;
			case 'e':
				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;

				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_EXCEPTMASK;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;

				/* Same as the 'b' mode. */
				if (nexttok < t->counter) {
					if (! valid_channel_mask(t->token[nexttok]))
						return PARSE_ERROR;
					xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));
					++nexttok;
				} else
					c->args.cmd_mode.mode_args.type_chan.others[j].param[0] = '\0';

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;

				break;
			case 'I':
				if (c->args.cmd_mode.mode_args.type_chan.num_others >= MAX_CHAN_MODE_PARAMS)
					return PARSE_ERROR;

				j = c->args.cmd_mode.mode_args.type_chan.num_others;
				c->args.cmd_mode.mode_args.type_chan.others[j].mode = MODE_INVITEMASK;
				c->args.cmd_mode.mode_args.type_chan.others[j].action = ca;

				/* Same as the 'b' mode. */
				if (nexttok < t->counter) {
					if (! valid_channel_mask(t->token[nexttok]))
						return PARSE_ERROR;
					xstrlcpy(c->args.cmd_mode.mode_args.type_chan.others[j].param, t->token[nexttok], sizeof(c->args.cmd_mode.mode_args.type_chan.others[j].param));
					++nexttok;
				} else
					c->args.cmd_mode.mode_args.type_chan.others[j].param[0] = '\0';

				c->args.cmd_mode.mode_args.type_chan.num_others = j+1;

				break;
			default:
				c->args.cmd_mode.mode_args.type_chan.unknown_modes[i_unk++] = t->token[modetok][i];
				break;
			}
		}

		modetok = nexttok;
		nexttok = modetok + 1;
	}
	
	c->args.cmd_mode.mode_args.type_chan.unknown_modes[i_unk] = '\0';

	return 0;
}

int parse_tokens(const struct tokens *t, struct command *c)
{
	int tok;
	int ret;

	int i;
	char cmd_name[MESSAGE_BUFFER_SIZE];
	int len;

	if (t->counter <= 0)
		return PARSE_ERROR;

	/* Command prefix. */
	tok = 0;
	if (t->token[tok][0] == ':') {
		xstrlcpy(c->prefix, t->token[tok], sizeof(c->prefix));
		++tok;
	}

	/* Number of arguments. */
	if (t->counter - tok <= 0)
		return PARSE_ERROR;
	if (t->counter - tok - 1 > MAX_MESSAGE_PARAMS)
		return PARSE_ERROR;

	/* Command name. */
	len = strlen(t->token[tok]);
	for (i = 0; i < len; ++i)
		cmd_name[i] = toupper(t->token[tok][i]);
	cmd_name[len] = '\0';

	if (strcmp("PRIVMSG", cmd_name) == 0)
		c->number = CMD_PRIVMSG;
	else if (strcmp("JOIN", cmd_name) == 0)
		c->number = CMD_JOIN;
	else if (strcmp("NOTICE", cmd_name) == 0)
		c->number = CMD_NOTICE;
	else if (strcmp("NICK", cmd_name) == 0)
		c->number = CMD_NICK;
	else if (strcmp("QUIT", cmd_name) == 0)
		c->number = CMD_QUIT;
	else if (strcmp("MODE", cmd_name) == 0)
		c->number = CMD_MODE;
	else if (strcmp("PART", cmd_name) == 0)
		c->number = CMD_PART;
	else if (strcmp("PING", cmd_name) == 0)
		c->number = CMD_PING;
	else if (strcmp("WHOIS", cmd_name) == 0)
		c->number = CMD_WHOIS;
	else if (strcmp("WHO", cmd_name) == 0)
		c->number = CMD_WHO;
	else if (strcmp("PONG", cmd_name) == 0)
		c->number = CMD_PONG;
	else if (strcmp("USER", cmd_name) == 0)
		c->number = CMD_USER;
	else if (strcmp("KICK", cmd_name) == 0)
		c->number = CMD_KICK;
	else if (strcmp("TOPIC", cmd_name) == 0)
		c->number = CMD_TOPIC;
	else if (strcmp("ISON", cmd_name) == 0)
		c->number = CMD_ISON;
	else if (strcmp("AWAY", cmd_name) == 0)
		c->number = CMD_AWAY;
	else if (strcmp("LUSERS", cmd_name) == 0)
		c->number = CMD_LUSERS;
	else if (strcmp("USERHOST", cmd_name) == 0)
		c->number = CMD_USERHOST;
	else if (strcmp("INVITE", cmd_name) == 0)
		c->number = CMD_INVITE;
	else if (strcmp("WHOWAS", cmd_name) == 0)
		c->number = CMD_WHOWAS;
	else if (strcmp("LIST", cmd_name) == 0)
		c->number = CMD_LIST;
	else if (strcmp("KILL", cmd_name) == 0)
		c->number = CMD_KILL;
	else if (strcmp("PASS", cmd_name) == 0)
		c->number = CMD_PASS;
	else if (strcmp("NAMES", cmd_name) == 0)
		c->number = CMD_NAMES;
	else if (strcmp("ERROR", cmd_name) == 0)
		c->number = CMD_ERROR;
	else if (strcmp("SQUIT", cmd_name) == 0)
		c->number = CMD_SQUIT;
	else if (strcmp("TIME", cmd_name) == 0)
		c->number = CMD_TIME;
	else if (strcmp("LINKS", cmd_name) == 0)
		c->number = CMD_LINKS;
	else if (strcmp("MOTD", cmd_name) == 0)
		c->number = CMD_MOTD;
	else if (strcmp("ADMIN", cmd_name) == 0)
		c->number = CMD_ADMIN;
	else if (strcmp("INFO", cmd_name) == 0)
		c->number = CMD_INFO;
	else if (strcmp("VERSION", cmd_name) == 0)
		c->number = CMD_VERSION;
	else if (strcmp("OPER", cmd_name) == 0)
		c->number = CMD_OPER;
	else if (strcmp("STATS", cmd_name) == 0)
		c->number = CMD_STATS;
	else if (strcmp("USERS", cmd_name) == 0)
		c->number = CMD_USERS;
	else if (strcmp("CONNECT", cmd_name) == 0)
		c->number = CMD_CONNECT;
	else if (strcmp("WALLOPS", cmd_name) == 0)
		c->number = CMD_WALLOPS;
	else if (strcmp("TRACE", cmd_name) == 0)
		c->number = CMD_TRACE;
	else if (strcmp("SERVICE", cmd_name) == 0)
		c->number = CMD_SERVICE;
	else if (strcmp("SERVLIST", cmd_name) == 0)
		c->number = CMD_SERVLIST;
	else if (strcmp("SQUERY", cmd_name) == 0)
		c->number = CMD_SQUERY;
	else if (strcmp("REHASH", cmd_name) == 0)
		c->number = CMD_REHASH;
	else if (strcmp("DIE", cmd_name) == 0)
		c->number = CMD_DIE;
	else if (strcmp("RESTART", cmd_name) == 0)
		c->number = CMD_RESTART;
	else if (strcmp("SUMMON", cmd_name) == 0)
		c->number = CMD_SUMMON;
	else
		return ERR_UNKNOWNCOMMAND;
	++tok;

	ret = 0; /* May be overwritten later. */
	switch (c->number) {
	case CMD_REHASH:
	case CMD_DIE:
	case CMD_RESTART:
		/* Instead of complaining about extra arguments, ignore them. */
		break;

		/* Commands receiving an optional "target" or "text". */
	case CMD_MOTD:
		copy_trailing_token_to(t, tok, c->args.cmd_motd.target, sizeof(c->args.cmd_motd.target));
		break;
	case CMD_VERSION:
		copy_trailing_token_to(t, tok, c->args.cmd_version.target, sizeof(c->args.cmd_version.target));
		break;
	case CMD_TIME:
		copy_trailing_token_to(t, tok, c->args.cmd_time.target, sizeof(c->args.cmd_time.target));
		break;
	case CMD_TRACE:
		copy_trailing_token_to(t, tok, c->args.cmd_trace.target, sizeof(c->args.cmd_trace.target));
		break;
	case CMD_ADMIN:
		copy_trailing_token_to(t, tok, c->args.cmd_admin.target, sizeof(c->args.cmd_admin.target));
		break;
	case CMD_INFO:
		copy_trailing_token_to(t, tok, c->args.cmd_info.target, sizeof(c->args.cmd_info.target));
		break;
	case CMD_USERS:
		copy_trailing_token_to(t, tok, c->args.cmd_users.target, sizeof(c->args.cmd_users.target));
		break;
	case CMD_AWAY:
		copy_trailing_token_to(t, tok, c->args.cmd_away.text, sizeof(c->args.cmd_away.text));
		break;
	case CMD_QUIT:
		copy_trailing_token_to(t, tok, c->args.cmd_quit.message, sizeof(c->args.cmd_quit.message));
		break;

		/* Requiring a single argument. */
	case CMD_WALLOPS:
		if (copy_trailing_token_to(t, tok, c->args.cmd_wallops.text, sizeof(c->args.cmd_wallops.text)) == 0)
			return ERR_NEEDMOREPARAMS;
		break;
	case CMD_ERROR:
		if (copy_trailing_token_to(t, tok, c->args.cmd_wallops.text, sizeof(c->args.cmd_wallops.text)) == 0)
			return PARSE_ERROR;
		break;
	case CMD_PASS:
		if (copy_trailing_token_to(t, tok, c->args.cmd_pass.password, sizeof(c->args.cmd_pass.password)) == 0)
			return ERR_NEEDMOREPARAMS;
		break;

		/* Commands with their own parsing functions. */
	case CMD_NICK:
		ret = parse_cmd_nick(t, tok, c);
		break;
	case CMD_USER:
		ret = parse_cmd_user(t, tok, c);
		break;
	case CMD_OPER:
		ret = parse_cmd_oper(t, tok, c);
		break;
	case CMD_SERVICE:
		ret = parse_cmd_service(t, tok, c);
		break;
	case CMD_SQUIT:
		ret = parse_cmd_squit(t, tok, c);
		break;
	case CMD_TOPIC:
		ret = parse_cmd_topic(t, tok, c);
		break;
	case CMD_INVITE:
		ret = parse_cmd_invite(t, tok, c);
		break;
	case CMD_PRIVMSG:
		ret = parse_cmd_privmsg(t, tok, c);
		break;
	case CMD_NOTICE:
		ret = parse_cmd_notice(t, tok, c);
		break;
	case CMD_STATS:
		ret = parse_cmd_stats(t, tok, c);
		break;
	case CMD_LINKS:
		ret = parse_cmd_links(t, tok, c);
		break;
	case CMD_CONNECT:
		ret = parse_cmd_connect(t, tok, c);
		break;
	case CMD_SQUERY:
		ret = parse_cmd_squery(t, tok, c);
		break;
	case CMD_KILL:
		ret = parse_cmd_kill(t, tok, c);
		break;
	case CMD_PING:
	case CMD_PONG:
		ret = parse_cmd_ping_pong(t, tok, c);
		break;
	case CMD_SUMMON:
		ret = parse_cmd_summon(t, tok, c);
		break;
	case CMD_USERHOST:
		ret = parse_cmd_userhost(t, tok, c);
		break;
	case CMD_ISON:
		ret = parse_cmd_ison(t, tok, c);
		break;
	case CMD_JOIN:
		ret = parse_cmd_join(t, tok, c);
		break;
	case CMD_PART:
		ret = parse_cmd_part(t, tok, c);
		break;
	case CMD_NAMES:
	case CMD_LIST:
		ret = parse_cmd_names_list(t, tok, c);
		break;
	case CMD_KICK:
		ret = parse_cmd_kick(t, tok, c);
		break;
	case CMD_LUSERS:
		ret = parse_cmd_lusers(t, tok, c);
		break;
	case CMD_WHO:
		ret = parse_cmd_who(t, tok, c);
		break;
	case CMD_WHOIS:
		ret = parse_cmd_whois(t, tok, c);
		break;
	case CMD_WHOWAS:
		ret = parse_cmd_whowas(t, tok, c);
		break;
	case CMD_SERVLIST:
		ret = parse_cmd_servlist(t, tok, c);
		break;
	case CMD_MODE:
		ret = parse_cmd_mode(t, tok, c);
		break;
	default:
		/* This would have been detected earlier, anyway. */
		return ERR_UNKNOWNCOMMAND;
	};

	return ret;
}

void messages_free(void)
{
	tokenize(NULL, NULL);
	valid_nickname(NULL);
	valid_channel_name(NULL);
	valid_user_name(NULL);
	valid_channel_mask(NULL);
}
