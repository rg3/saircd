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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sqlite3.h>

#include "messages.h"
#include "database.h"
#include "buffer.h"
#include "reader.h"
#include "server.h"
#include "util.h"
#include "build.h"

/*
 * Static function prototypes.
 */

/* Allocate memory. */
static char *srv_malloc(size_t sz);

/* Allocate MESSAGE_BUFFER_SIZE bytes. */
static char *srv_malloc_msg(void);

/* Free memory. */
static void srv_free(char **ptr);

/* Caps IRC message to the given length. */
static int srv_fix_message(char *msg, int max, int snprintfret);

/* Returns @, + or the empty string. */
static const char *srv_memb_symbol(const struct db_membership *m);

/* Returns =, * or @ depending on the channel flags. */
static const char *srv_chan_symbol(const struct db_channel *chan);

/* Like snprintf + srv_fix_message, in a single function. */
static int srv_vfmt(char *msg, int max, const char *fmt, va_list ap);
static int srv_fmt(char *msg, int max, const char *fmt, ...);

/* Returns answer to the question "Are all the client slots in use?" */
static int srv_full(const struct server *srv);

/* Returns -1 if the server is full. */
static int srv_get_client_slot(struct server *srv);

/* This callback will be called from read_and_callback(). */
static void srv_reader_cb(int fd, const char *msg, int msglen, void *srv_);

/* Database maintenance (remove expired entries). */
static void srv_db_maintenance(struct server *srv);

/* Send message to log channel. */
static void srv_log(struct server *srv, const char *msg);

static void srv_enqueue_cb(void *cli_, void *msg_);
static void srv_anon_neighbor_cb(void *clichan_, void *args_);
static void srv_ping_timeout_cb(void *cli_, void *args_);
static void srv_poll_sockets(struct server *srv);
static void srv_accept_new_clients(struct server *srv);
static void srv_make_new_client(struct db_client *cli, int slot, int fd, const char *ip, int port);
static void srv_poll_cb(void *cli_, void *pollfds_);
static void srv_free_client_slot(struct server *srv, int cli);
static void srv_clear_client_slot(struct server_client *srvcli);
static void srv_disconnect_client(struct server *srv, struct db_client *cli);
static void srv_client_quit(struct server *srv, struct db_client *cli, const char *reason);
static void srv_enqueue_client_data(struct server *srv, struct db_client *cli, const char *in, int count);
static void srv_inactive_cb(void *cli_, void *srv_);
static void srv_process_cmd(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_error(struct server *srv, struct db_client *cli, struct command *c, struct tokens *t, int pret);
static const char *srv_dest_nick(const struct db_client *cli);

/* srv_fmt and srv_enqueue_client_data combined for ease of use. */
static void srv_vfmt_enq(struct server *srv, struct db_client *cli, const char *fmt, va_list ap);
static void srv_fmt_enq(struct server *srv, struct db_client *cli, const char *fmt, ...);

/* Command-processing functions. */
static void srv_process_nick(struct server *srv, struct db_client *cli, struct command *c);
static void srv_nickname_change(struct server *srv, struct db_client *cli, const char *old_fullname);
static void srv_process_user(struct server *srv, struct db_client *cli, struct command *c);
static void srv_rebuild_cli_fullname(struct server *srv, struct db_client *cli);
static void srv_registration_complete(struct server *srv, struct db_client *cli);
static void srv_process_pong(struct db_client *cli);
static void srv_process_quit(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_ping(struct server *srv, struct db_client *cli, struct command *c);
static void srv_send_error(struct server *srv, struct db_client *cli, const char *errmsg);
static void srv_process_lusers(struct server *srv, struct db_client *cli);
static void srv_process_motd(struct server *srv, struct db_client *cli);
static void srv_process_privmsg(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_notice(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_mode(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_away(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_who(struct server *srv, struct db_client *cli, struct command *c);
static void srv_who_chan_cb(void *cli_, void *args_);
static void srv_process_version(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_links(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_time(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_trace(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_admin(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_info(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_service(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_userhost(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_ison(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_oper(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_whowas(struct server *srv, struct db_client *cli, struct command *c);
static void srv_whowas_cb(void *whowas_, void *args_);
static void srv_process_whois(struct server *srv, struct db_client *cli, struct command *c);
static void srv_whois_cb(void *chan_, void *args_);
static void srv_process_kill(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_stats(struct server *srv, struct db_client *cli, struct command *c);
static void srv_report_cmd_stats(struct server *srv, struct db_client *cli);
static void srv_process_join(struct server *srv, struct db_client *cli, struct command *c);
static void srv_one_names_cb(void *cli_, void *args_);
static void srv_process_one_names(struct server *srv, struct db_client *cli, struct db_channel *chan, int all);
static void srv_process_one_join(struct server *srv, struct db_client *cli, const char *cname, const char *key);
static void srv_process_join(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_topic(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_names(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_list(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_part(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_one_part(struct server *srv, struct db_client *cli, const char *cname, const char *reason);
static void srv_join_zero_cb(void *chan_, void *args_);
static void srv_process_kick(struct server *srv, struct db_client *cli, struct command *c);
static void srv_process_invite(struct server *srv, struct db_client *cli, struct command *c);
static void srv_list_bans_cb(void *mask_, void *extra_);
static void srv_list_excepts_cb(void *mask_, void *extra_);
static void srv_list_invites_cb(void *mask_, void *extra_);
static void srv_list_bans(struct server *srv, struct db_client *cli, struct db_channel *chan);
static void srv_list_excepts(struct server *srv, struct db_client *cli, struct db_channel *chan);
static void srv_list_invites(struct server *srv, struct db_client *cli, struct db_channel *chan);
static void srv_process_die(struct server *srv, struct db_client *cli);

/* Reply-sending functions. */
static void srv_send_reply_welcome(struct server *srv, struct db_client *cli, const char *f);
static void srv_send_reply_yourhost(struct server *srv, struct db_client *cli);
static void srv_send_reply_created(struct server *srv, struct db_client *cli);
static void srv_send_reply_myinfo(struct server *srv, struct db_client *cli);
static void srv_send_reply_away(struct server *srv, struct db_client *cli, const char *nick, const char *text);
static void srv_send_reply_unaway(struct server *srv, struct db_client *cli);
static void srv_send_reply_nowaway(struct server *srv, struct db_client *cli);
static void srv_send_reply_servlistend(struct server *srv, struct db_client *cli, const char *mask, const char *type);
static void srv_send_reply_youreoper(struct server *srv, struct db_client *cli);
static void srv_send_reply_topic(struct server *srv, struct db_client *cli, const char *chan, const char *topic);
static void srv_send_reply_notopic(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_reply_endofnames(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_reply_inviting(struct server *srv, struct db_client *cli, const char *chan, const char *nick);

/* Error-sending functions. */
static void srv_send_error_restricted(struct server *srv, struct db_client *cli);
static void srv_send_error_alreadyregistred(struct server *srv, struct db_client *cli);
static void srv_send_error_nicknameinuse(struct server *srv, struct db_client *cli, const char *nick);
static void srv_send_error_unavailresource(struct server *srv, struct db_client *cli, const char *res);
static void srv_send_error_nonicknamegiven(struct server *srv, struct db_client *cli);
static void srv_send_error_erroneusnickname(struct server *srv, struct db_client *cli, const char *nick);
static void srv_send_error_needmoreparams(struct server *srv, struct db_client *cli, const char *cmd);
static void srv_send_error_noorigin(struct server *srv, struct db_client *cli);
static void srv_send_error_notregistered(struct server *srv, struct db_client *cli);
static void srv_send_error_norecipient(struct server *srv, struct db_client *cli, const char *cmd);
static void srv_send_error_notexttosend(struct server *srv, struct db_client *cli);
static void srv_send_error_nosuchnick(struct server *srv, struct db_client *cli, const char *nick);
static void srv_send_error_cannotsendtochan(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_summondisabled(struct server *srv, struct db_client *cli);
static void srv_send_error_usersdisabled(struct server *srv, struct db_client *cli);
static void srv_send_error_nosuchserver(struct server *srv, struct db_client *cli, const char *server);
static void srv_send_error_nosuchservice(struct server *srv, struct db_client *cli, const char *nick);
static void srv_send_error_umodeunknownflag(struct server *srv, struct db_client *cli);
static void srv_send_error_usersdontmatch(struct server *srv, struct db_client *cli);
static void srv_send_error_passwdmismatch(struct server *srv, struct db_client *cli);
static void srv_send_error_noprivileges(struct server *srv, struct db_client *cli);
static void srv_send_error_toomanychannels(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_badchannelkey(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_channelisfull(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_inviteonlychan(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_bannedfromchan(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_notonchannel(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_chanoprivsneeded(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_nosuchchannel(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_usernotinchannel(struct server *srv, struct db_client *cli, const char *n, const char *c);
static void srv_send_error_useronchannel(struct server *srv, struct db_client *cli, const char *n, const char *c);
static void srv_send_error_unknownmode(struct server *srv, struct db_client *cli, char m, const char *chan);
static void srv_send_error_keyset(struct server *srv, struct db_client *cli, const char *chan);
static void srv_send_error_unknowncommand(struct server *srv, struct db_client *cli, const char *cmd);
static void srv_send_error_toomanymatches(struct server *srv, struct db_client *cli, const char *chan);

/* Config-parsing functions. */
static int srv_cfg_parse_int(const char *str);
static int srv_cfg_verify_server_name(const char *value);
static int srv_cfg_verify_phrase(const char *value);
static int srv_cfg_parse_key_value(const char *key, const char *value, struct server_config *cfg);
static int srv_cfg_verify_operators_filename(const char *fn, const char **errmsg);

/* Operator loading functions. */
static void srv_load_operators(FILE *f, sqlite3 *db);
static int srv_op_user_pass_verify(const char *str);

struct srv_enqueue_cb_args {
	struct server *srv;
	const char *msg;
	int len;
};

struct srv_who_chan_cb_args {
	struct server *srv;
	struct db_client *cli;
	struct db_channel *chan;
	int all;
};

struct srv_whowas_cb_args {
	struct server *srv;
	struct db_client *cli;
	int results;
};

struct srv_whois_cb_args {
	struct server *srv;
	struct db_client *cli;
	struct db_client *wn;
};

struct srv_anon_neighbor_cb_args {
	struct server *srv;
	struct db_client *cli;
};

struct srv_one_names_cb_args {
	struct server *srv;
	struct db_client *cli;
	struct db_channel *chan;
	int all;
	char *buffer;
	int bufsize;
	int bufused;
	int accum;
};

struct srv_join_zero_cb_args {
	struct server *srv;
	struct db_client *cli;
};

struct srv_list_masks_args {
	struct server *srv;
	struct db_client *cli;
	struct db_channel *chan;
};

static char *srv_malloc(size_t sz)
{
	char *ret = malloc(sz);
	assert(ret != NULL);
	return ret;
}

static char *srv_malloc_msg(void)
{
	return srv_malloc(MESSAGE_BUFFER_SIZE);
}

static void srv_free(char **ptr)
{
	assert(ptr != NULL);
	assert(*ptr != NULL);
	free(*ptr);
	ptr = NULL;
}

static int srv_fix_message(char *msg, int size, int snprintfret)
{
	if (size < 3) /* Enough room for \r\n\0 at least. */
		return 0;

	if (snprintfret < size)
		return snprintfret;

	msg[size - 3] = '\r';
	msg[size - 2] = '\n';
	return (size - 1);
}

static const char *srv_memb_symbol(const struct db_membership *m)
{
	if (m->operator_flag)
		return "@";
	if (m->voice_flag)
		return "+";
	return "";
}

static const char *srv_chan_symbol(const struct db_channel *c)
{
	if (c->secret_flag)
		return "@";
	if (c->private_flag)
		return "*";
	return "=";
}

static int srv_vfmt(char *msg, int max, const char *fmt, va_list ap)
{
	int len;

	len = vsnprintf(msg, max, fmt, ap);
	return srv_fix_message(msg, max, len);
}

static int srv_fmt(char *msg, int max, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = srv_vfmt(msg, max, fmt, ap);
	va_end(ap);

	return ret;
}

static void srv_vfmt_enq(struct server *srv, struct db_client *cli, const char *fmt, va_list ap)
{
	char *msg = srv_malloc_msg();
	int len;

	len = srv_vfmt(msg, MESSAGE_BUFFER_SIZE, fmt, ap);
	srv_enqueue_client_data(srv, cli, msg, len);
	srv_free(&msg);
}

static void srv_fmt_enq(struct server *srv, struct db_client *cli, const char *fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	srv_vfmt_enq(srv, cli, fmt, ap);
	va_end(ap);
}

static const char *srv_dest_nick(const struct db_client *cli)
{
	return (cli->orig_nickname[0] == '\0')?"*":cli->orig_nickname;
}

static void srv_log(struct server *srv, const char *str)
{
	char *msg = srv_malloc_msg();
	int len;

	struct srv_enqueue_cb_args args;

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":root!root@root PRIVMSG %s :%s\r\n",
		      srv->dyndata.logchan.orig_name, str);
	args.srv = srv;
	args.msg = msg;
	args.len = len;
	assert(db_run_on_members(srv->db, srv->dyndata.logchan.id_channel,
				 srv_enqueue_cb, &args) == 0);
	srv_free(&msg);
}

static void srv_send_error_restricted(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Your connection is restricted!\r\n",
		    srv->config.server_name, ERR_RESTRICTED, srv_dest_nick(cli));
}

static void srv_send_error_alreadyregistred(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Unauthorized command (already registered)\r\n",
		    srv->config.server_name, ERR_ALREADYREGISTERED, srv_dest_nick(cli));
}

static void srv_send_error_nicknameinuse(struct server *srv, struct db_client *cli, const char *nick)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Nickname is already in use\r\n",
		    srv->config.server_name, ERR_NICKNAMEINUSE, srv_dest_nick(cli), nick);
}

static void srv_send_error_unavailresource(struct server *srv, struct db_client *cli, const char *res)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Nick/channel is temporarily unavailable\r\n",
		    srv->config.server_name, ERR_UNAVAILRESOURCE, srv_dest_nick(cli), res);
}

static void srv_send_error_nonicknamegiven(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :No nickname given\r\n",
		    srv->config.server_name, ERR_NONICKNAMEGIVEN, srv_dest_nick(cli));
}

static void srv_send_error_erroneusnickname(struct server *srv, struct db_client *cli, const char *nick)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Erroneous nickname\r\n",
		    srv->config.server_name, ERR_ERRONEUSNICKNAME, srv_dest_nick(cli), nick);
}

static void srv_send_error_needmoreparams(struct server *srv, struct db_client *cli, const char *cmd)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Not enough parameters\r\n",
		    srv->config.server_name, ERR_NEEDMOREPARAMS, srv_dest_nick(cli), cmd);
}

static void srv_send_error_noorigin(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :No origin specified\r\n",
		    srv->config.server_name, ERR_NOORIGIN, srv_dest_nick(cli));
}

static void srv_send_error_notregistered(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :You have not registered\r\n",
		    srv->config.server_name, ERR_NOTREGISTERED, srv_dest_nick(cli));
}

static void srv_send_error_norecipient(struct server *srv, struct db_client *cli, const char *cmd)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :No recipient given (%s)\r\n",
		    srv->config.server_name, ERR_NORECIPIENT, srv_dest_nick(cli), cmd);
}

static void srv_send_error_notexttosend(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :No text to send\r\n",
		    srv->config.server_name, ERR_NORECIPIENT, srv_dest_nick(cli));
}

static void srv_send_error_nosuchnick(struct server *srv, struct db_client *cli, const char *nick)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :No such nick/channel\r\n",
		    srv->config.server_name, ERR_NOSUCHNICK, srv_dest_nick(cli), nick);
}

static void srv_send_error_cannotsendtochan(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Cannot send to channel\r\n",
		    srv->config.server_name, ERR_CANNOTSENDTOCHAN, srv_dest_nick(cli), chan);
}

static void srv_send_error_summondisabled(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :SUMMON has been disabled\r\n",
		    srv->config.server_name, ERR_SUMMONDISABLED, srv_dest_nick(cli));
}

static void srv_send_error_usersdisabled(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :USERS has been disabled\r\n",
		    srv->config.server_name, ERR_USERSDISABLED, srv_dest_nick(cli));
}

static void srv_send_error_nosuchserver(struct server *srv, struct db_client *cli, const char *server)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :No such server\r\n",
		    srv->config.server_name, ERR_NOSUCHSERVER, srv_dest_nick(cli), server);
}

static void srv_send_error_nosuchservice(struct server *srv, struct db_client *cli, const char *nick)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :No such service\r\n",
		    srv->config.server_name, ERR_NOSUCHSERVICE, srv_dest_nick(cli), nick);
}

static void srv_send_error_umodeunknownflag(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Unknown MODE flag\r\n",
		    srv->config.server_name, ERR_UMODEUNKNOWNFLAG, srv_dest_nick(cli));
}

static void srv_send_error_usersdontmatch(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Cannot change mode for other users\r\n",
		    srv->config.server_name, ERR_USERSDONTMATCH, srv_dest_nick(cli));
}

static void srv_send_error_passwdmismatch(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Password incorrect\r\n",
		    srv->config.server_name, ERR_PASSWDMISMATCH, srv_dest_nick(cli));
}

static void srv_send_error_noprivileges(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Permission Denied- You're not an IRC operator\r\n",
		    srv->config.server_name, ERR_NOPRIVILEGES, srv_dest_nick(cli));
}

static void srv_send_error_toomanychannels(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :You have joined too many channels\r\n",
		    srv->config.server_name, ERR_TOOMANYCHANNELS, srv_dest_nick(cli), chan);
}

static void srv_send_error_badchannelkey(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Cannot join channel (+k)\r\n",
		    srv->config.server_name, ERR_BADCHANNELKEY, srv_dest_nick(cli), chan);
}

static void srv_send_error_channelisfull(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Cannot join channel (+l)\r\n",
		    srv->config.server_name, ERR_CHANNELISFULL, srv_dest_nick(cli), chan);
}

static void srv_send_error_inviteonlychan(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Cannot join channel (+i)\r\n",
		    srv->config.server_name, ERR_INVITEONLYCHAN, srv_dest_nick(cli), chan);
}

static void srv_send_error_bannedfromchan(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Cannot join channel (+b)\r\n",
		    srv->config.server_name, ERR_BANNEDFROMCHAN, srv_dest_nick(cli), chan);
}

static void srv_send_error_notonchannel(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :You're not on that channel\r\n",
		    srv->config.server_name, ERR_NOTONCHANNEL, srv_dest_nick(cli), chan);
}

static void srv_send_error_chanoprivsneeded(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :You're not channel operator\r\n",
		    srv->config.server_name, ERR_CHANOPRIVSNEEDED, srv_dest_nick(cli), chan);
}

static void srv_send_error_nosuchchannel(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :No such channel\r\n",
		    srv->config.server_name, ERR_NOSUCHCHANNEL, srv_dest_nick(cli), chan);
}

static void srv_send_error_usernotinchannel(struct server *srv, struct db_client *cli, const char *n, const char *c)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s %s :They aren't on that channel\r\n",
		    srv->config.server_name, ERR_USERNOTINCHANNEL, srv_dest_nick(cli), n, c);
}

static void srv_send_error_useronchannel(struct server *srv, struct db_client *cli, const char *n, const char *c)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s %s :is already on channel\r\n",
		    srv->config.server_name, ERR_USERONCHANNEL, srv_dest_nick(cli), n, c);
}

static void srv_send_error_unknownmode(struct server *srv, struct db_client *cli, char m, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %c :is unknown mode char to me for %s\r\n",
		    srv->config.server_name, ERR_UNKNOWNMODE, srv_dest_nick(cli), m, chan);
}

static void srv_send_error_keyset(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Channel key already set\r\n",
		    srv->config.server_name, ERR_KEYSET, srv_dest_nick(cli), chan);
}

static void srv_send_error_unknowncommand(struct server *srv, struct db_client *cli, const char *cmd)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Unknown command\r\n",
		    srv->config.server_name, ERR_UNKNOWNCOMMAND, srv_dest_nick(cli), cmd);
}

static void srv_send_error_toomanymatches(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :Output too long\r\n",
		    srv->config.server_name, ERR_TOOMANYMATCHES, srv_dest_nick(cli), chan);
}

static void srv_send_reply_welcome(struct server *srv, struct db_client *cli, const char *fullname)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Welcome to the Internet Relay Network %s\r\n",
		    srv->config.server_name, RPL_WELCOME, srv_dest_nick(cli), fullname);
}

static void srv_send_reply_yourhost(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :Your host is %s, running version " BUILD_VERSION "\r\n",
		    srv->config.server_name, RPL_YOURHOST, srv_dest_nick(cli), srv->config.server_name);
}

static void srv_send_reply_created(struct server *srv, struct db_client *cli)
{
	char datestr[32]; /* At least 26 according to the manual page. */

	ctime_r(&(srv->dyndata.start_time), datestr);
	srv_fmt_enq(srv, cli, ":%s %03d %s :This server was created %s\r\n",
		    srv->config.server_name, RPL_CREATED, srv_dest_nick(cli), datestr);
}

static void srv_send_reply_myinfo(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :%s " BUILD_VERSION " aiwroOs ovaimnqpstklbeI\r\n",
		    srv->config.server_name, RPL_MYINFO, srv_dest_nick(cli), srv->config.server_name);
}

static void srv_send_reply_away(struct server *srv, struct db_client *cli, const char *nick, const char *text)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :%s\r\n",
		    srv->config.server_name, RPL_AWAY, srv_dest_nick(cli), nick, text);
}

static void srv_send_reply_unaway(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :You are no longer marked as being away\r\n",
		    srv->config.server_name, RPL_UNAWAY, srv_dest_nick(cli));
}

static void srv_send_reply_nowaway(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :You have been marked as being away\r\n",
		    srv->config.server_name, RPL_NOWAWAY, srv_dest_nick(cli));
}

static void srv_send_reply_servlistend(struct server *srv, struct db_client *cli, const char *mask, const char *type)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s %s :End of service listing\r\n",
		    srv->config.server_name, RPL_SERVLISTEND, srv_dest_nick(cli),
		    (strlen(mask) == 0)?"*":mask, (strlen(type) == 0)?"*":type);
}

static void srv_send_reply_youreoper(struct server *srv, struct db_client *cli)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s :You are now an IRC operator\r\n",
		    srv->config.server_name, RPL_YOUREOPER, srv_dest_nick(cli));
}

static void srv_send_reply_topic(struct server *srv, struct db_client *cli, const char *chan, const char *topic)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :%s\r\n",
		    srv->config.server_name, RPL_TOPIC, srv_dest_nick(cli), chan, topic);
}

static void srv_send_reply_notopic(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :No topic is set\r\n",
		    srv->config.server_name, RPL_NOTOPIC, srv_dest_nick(cli), chan);
}

static void srv_send_reply_endofnames(struct server *srv, struct db_client *cli, const char *chan)
{
	srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of NAMES list\r\n",
		    srv->config.server_name, RPL_ENDOFNAMES, srv_dest_nick(cli), chan);
}

static void srv_send_reply_inviting(struct server *srv, struct db_client *cli, const char *chan, const char *nick)
{
	/*
	 * RFC errata. It suggests chan,nick order and nick,chan order is what
	 * seems to be expected by everyone.
	 */
	srv_fmt_enq(srv, cli, ":%s %03d %s %s %s\r\n",
		    srv->config.server_name, RPL_INVITING, srv_dest_nick(cli), nick, chan);
}

static void srv_rebuild_cli_fullname(struct server *srv, struct db_client *cli)
{
	char *aux = srv_malloc_msg();

	strcpy(aux, cli->username);
	irclower(aux);

	snprintf(cli->orig_fullname, MESSAGE_BUFFER_SIZE, "%s!%s@%s", cli->orig_nickname, cli->username, cli->ip);
	snprintf(cli->fullname, MESSAGE_BUFFER_SIZE, "%s!%s@%s", cli->nickname, aux, cli->ip);

	/* Log client identification. */
	snprintf(aux, MESSAGE_BUFFER_SIZE, "CLID_%lld is now %s",
		 (long long)(cli->id_client), cli->fullname);
	srv_log(srv, aux);

	srv_free(&aux);
}

static void srv_registration_complete(struct server *srv, struct db_client *cli)
{
	srv_rebuild_cli_fullname(srv, cli);
	srv_send_reply_welcome(srv, cli, cli->orig_fullname);
	srv_send_reply_yourhost(srv, cli);
	srv_send_reply_created(srv, cli);
	srv_send_reply_myinfo(srv, cli);
	srv_process_lusers(srv, cli);
	srv_process_motd(srv, cli);
}

static void srv_nickname_change(struct server *srv, struct db_client *cli, const char *old_fullname)
{
	char *msg = srv_malloc_msg();
	struct srv_enqueue_cb_args cbargs;
	int len;

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s NICK %s\r\n", old_fullname, cli->orig_nickname);
	srv_enqueue_client_data(srv, cli, msg, len);

	cbargs.srv = srv;
	cbargs.msg = msg;
	cbargs.len = len;
	assert(db_run_on_neighbors(srv->db, cli->id_client, srv_enqueue_cb, &cbargs) == 0); 
	srv_free(&msg);
}

static void srv_process_nick(struct server *srv, struct db_client *cli, struct command *c)
{
	char *ofn;
	struct db_client other;
	char lnick[NICKNAME_BUFFER_SIZE];

	if (cli->restricted_flag) {
		srv_send_error_restricted(srv, cli);
		return;
	}

	strcpy(lnick, c->args.cmd_nick.nickname);
	irclower(lnick);

	if (db_get_client_by_nick(srv->db, lnick, &other) == 0 &&
	    other.id_client != cli->id_client) {
		srv_send_error_nicknameinuse(srv, cli, c->args.cmd_nick.nickname);
		return;
	}

	if (db_nickname_is_forbidden(srv->db, lnick)) {
		srv_send_error_unavailresource(srv, cli, c->args.cmd_nick.nickname);
		return;
	}

	strcpy(cli->nickname, lnick);
	strcpy(cli->orig_nickname, c->args.cmd_nick.nickname);

	if (! (cli->regstate & REGSTATE_NICK)) {
		/* Registration process. */
		cli->regstate |= REGSTATE_NICK;
		if (cli->regstate & REGSTATE_USER)
			srv_registration_complete(srv, cli);
	} else if (cli->regstate & REGSTATE_USER) {
		/* Nickname change. */
		ofn = srv_malloc_msg();
		strcpy(ofn, cli->orig_fullname);
		srv_rebuild_cli_fullname(srv, cli);
		srv_nickname_change(srv, cli, ofn);
		srv_free(&ofn);
	}
}

static void srv_process_user(struct server *srv, struct db_client *cli, struct command *c)
{
	if (cli->regstate & REGSTATE_USER) {
		srv_send_error_alreadyregistred(srv, cli);
		return;
	}
	cli->regstate |= REGSTATE_USER;

	strcpy(cli->username, c->args.cmd_user.user);
	strcpy(cli->realname, c->args.cmd_user.realname);

	if (c->args.cmd_user.mode & 4)
		cli->wallops_flag = 1;

	if (c->args.cmd_user.mode & 8)
		cli->invisible_flag = 1;

	if (cli->regstate & REGSTATE_NICK)
		srv_registration_complete(srv, cli);
}

static void srv_process_pong(struct db_client *cli)
{
	cli->last_ping = 0;
}

static void srv_process_quit(struct server *srv, struct db_client *cli, struct command *c)
{
	char *msg = srv_malloc_msg();

	srv_fmt(msg, MESSAGE_BUFFER_SIZE, "User quit: %s", c->args.cmd_quit.message);
	srv_client_quit(srv, cli, msg);
	srv_free(&msg);
}

static void srv_process_ping(struct server *srv, struct db_client *cli, struct command *c)
{
	srv_fmt_enq(srv, cli, ":%s PONG %s :%s\r\n",
		    srv->config.server_name,
		    srv->config.server_name,
		    c->args.cmd_ping_pong.server1);
}

static void srv_send_error(struct server *srv, struct db_client *cli, const char *errmsg)
{
	srv_fmt_enq(srv, cli, "ERROR :%s\r\n", errmsg);
}

static void srv_process_lusers(struct server *srv, struct db_client *cli)
{
	int numcli;
	int numops;
	int numnop;
	int numchan;
	const char *nick;

	numcli = db_count_clients(srv->db);
	numops = db_count_client_operators(srv->db);
	numnop = numcli - numops;
	numchan = db_count_channels(srv->db);
	nick = srv_dest_nick(cli);

	srv_fmt_enq(srv, cli,
		    ":%s %03d %s :There are %d users and 0 services on 1 servers\r\n"
		    ":%s %03d %s %d :operator(s) online\r\n"
		    ":%s %03d %s 0 :unknown connection(s)\r\n"
		    ":%s %03d %s %d :channels formed\r\n"
		    ":%s %03d %s :I have %d clients and 0 servers\r\n",
		    srv->config.server_name, RPL_LUSERCLIENT, nick, numnop,
		    srv->config.server_name, RPL_LUSEROP, nick, numops,
		    srv->config.server_name, RPL_LUSERUNKNOWN, nick,
		    srv->config.server_name, RPL_LUSERCHANNELS, nick, numchan,
		    srv->config.server_name, RPL_LUSERME, nick, numcli);
}

static void srv_process_motd(struct server *srv, struct db_client *cli)
{
	const char *n;

	n = srv_dest_nick(cli);

	if (strlen(srv->config.motd) == 0) {
		srv_fmt_enq(srv, cli, ":%s %03d %s :MOTD File is missing\r\n",
			    srv->config.server_name, ERR_NOMOTD, srv_dest_nick(cli));
	} else {
		srv_fmt_enq(srv, cli,
			    ":%s %03d %s :- %s Message of the day - \r\n"
			    ":%s %03d %s :- %s\r\n"
			    ":%s %03d %s :End of MOTD command\r\n",
			    srv->config.server_name, RPL_MOTDSTART, n, srv->config.server_name,
			    srv->config.server_name, RPL_MOTD, n, srv->config.motd,
			    srv->config.server_name, RPL_ENDOFMOTD, n);
	}
}

static void srv_process_privmsg(struct server *srv, struct db_client *cli, struct command *c)
{
	char *lnick;
	char *lchan;
	char *msg;
	int len;

	struct db_client tcli;
	struct db_channel tchan;
	struct srv_enqueue_cb_args args;
	const char *nick;
	const char *chan;
	const char *origin;

	switch (c->args.cmd_privmsg.target_type) {
	case TYPE_NICK:
		lnick = srv_malloc_msg();
		nick = c->args.cmd_privmsg.target.nickname;

		strcpy(lnick, nick);
		irclower(lnick);

		if (db_get_client_by_nick(srv->db, lnick, &tcli) != 0) {
			srv_send_error_nosuchnick(srv, cli, nick);
			srv_free(&lnick);
			return;
		}

		srv_free(&lnick);

		srv_fmt_enq(srv, &tcli, ":%s PRIVMSG %s :%s\r\n",
			    cli->orig_fullname, tcli.orig_nickname, c->args.cmd_privmsg.text);

		if (tcli.away_flag)
			srv_send_reply_away(srv, cli, nick, tcli.away_text);

		break;
	case TYPE_CHAN:
		lchan = srv_malloc_msg();
		chan = c->args.cmd_privmsg.target.channel;

		strcpy(lchan, chan);
		irclower(lchan);

		if (db_get_channel_by_name(srv->db, lchan, &tchan) != 0) {
			srv_send_error_nosuchnick(srv, cli, chan);
			srv_free(&lchan);
			return;
		}

		srv_free(&lchan);

		if (!db_client_may_talk(srv->db, cli, &tchan)) {
			srv_send_error_cannotsendtochan(srv, cli, tchan.orig_name);
			return;
		}

		msg = srv_malloc_msg();
		origin = (tchan.anonymous_flag)?"anonymous!anonymous@anonymous":cli->orig_fullname;
		len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s PRIVMSG %s :%s\r\n",
			      origin, tchan.orig_name, c->args.cmd_privmsg.text);

		args.srv = srv;
		args.msg = msg;
		args.len = len;
		db_run_on_members_except(srv->db, tchan.id_channel, cli->id_client, srv_enqueue_cb, &args);

		srv_free(&msg);
		break;
	}
}

static void srv_process_notice(struct server *srv, struct db_client *cli, struct command *c)
{
	char lc[NICKNAME_BUFFER_SIZE];
	char *msg = srv_malloc_msg();
	int len;

	struct db_client tcli;
	struct db_channel tchan;
	struct srv_enqueue_cb_args args;
	const char *nick;
	const char *chan;
	const char *origin;

	switch (c->args.cmd_notice.target_type) {
	case TYPE_NICK:
		nick = c->args.cmd_notice.target.nickname;

		strcpy(lc, nick);
		irclower(lc);

		if (db_get_client_by_nick(srv->db, lc, &tcli) != 0)
			goto out;

		len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s NOTICE %s :%s\r\n",
			      cli->orig_fullname, tcli.orig_nickname, c->args.cmd_notice.text);
		srv_enqueue_client_data(srv, &tcli, msg, len);

		break;

	case TYPE_CHAN:
		chan = c->args.cmd_notice.target.channel;
		if (db_get_channel_by_name(srv->db, chan, &tchan) != 0)
			goto out;

		if (!db_client_may_talk(srv->db, cli, &tchan))
			goto out;

		origin = (tchan.anonymous_flag)?"anonymous!anonymous@anonymous":cli->orig_fullname;
		len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s NOTICE %s :%s\r\n",
			      origin, tchan.orig_name, c->args.cmd_notice.text);
		args.srv = srv;
		args.msg = msg;
		args.len = len;
		db_run_on_members_except(srv->db, tchan.id_channel, cli->id_client, srv_enqueue_cb, &args);
		break;
	}

out:
	srv_free(&msg);
}

struct srv_chan_mode_action_reply {
	const char *anonymous;
	const char *invite_only;
	const char *moderated;
	const char *no_outside;
	const char *quiet;
	const char *private_m;
	const char *secret;
	const char *topic;
	int num_others;
	struct _other {
		const char *other_str;
		const char *arg_str;
	} others[MAX_CHAN_MODE_PARAMS];
};

/* XXX This function is waaay too long. It should be split in two, at least. */
static void srv_process_mode(struct server *srv, struct db_client *cli, struct command *c)
{
	char lnick[NICKNAME_BUFFER_SIZE];
	char lchan[CHANNEL_BUFFER_SIZE];
	char *msg = srv_malloc_msg();
	int len;
	struct _type_nick *p;
	struct _type_chan *ptc;

	char aux[9]; /* 7 mode chars, '+' and '\0'. */
	int i;

	struct db_channel chan;
	struct db_membership m;
	int is_oper;
	int error_chanop;
	int um_len;
	const char *chan_name;
	char integer[24]; /* Enough for a 64-bit value. */

	struct srv_chan_mode_action_reply areply;
	struct db_client target;
	struct db_membership m2;
	struct srv_enqueue_cb_args args;

	struct db_banmask bm;
	struct db_exceptmask em;
	struct db_invitemask im;

	switch (c->args.cmd_mode.mode_type) {
	case TYPE_NICK:
		strcpy(lnick, c->args.cmd_mode.mode_args.type_nick.nickname);
		irclower(lnick);

		if (strcmp(lnick, cli->nickname) != 0) {
			srv_send_error_usersdontmatch(srv, cli);
			goto out;
		}

		p = &(c->args.cmd_mode.mode_args.type_nick);

		if (p->invisible == ACTION_ADD)
			cli->invisible_flag = 1;
		else if (p->invisible == ACTION_REMOVE)
			cli->invisible_flag = 0;

		if (p->wallops == ACTION_ADD)
			cli->wallops_flag = 1;
		else if (p->wallops == ACTION_REMOVE)
			cli->wallops_flag = 0;

		if (p->restricted == ACTION_ADD)
			cli->restricted_flag = 1;

		if (p->net_operator == ACTION_REMOVE) {
			cli->operator_flag = 0;
			cli->id_oper = 0;
		}

		if (p->local_operator == ACTION_REMOVE)
			cli->local_operator_flag = 0;

		if (p->notices == ACTION_ADD)
			cli->server_notices_flag = 1;
		else if (p->notices == ACTION_REMOVE)
			cli->server_notices_flag = 0;

		/* Prepare UMODEIS string. */
		aux[0] = '+';
		i = 1;

		if (cli->away_flag)
			aux[i++] = 'a';
		if (cli->invisible_flag)
			aux[i++] = 'i';
		if (cli->wallops_flag)
			aux[i++] = 'w';
		if (cli->restricted_flag)
			aux[i++] = 'r';
		if (cli->operator_flag)
			aux[i++] = 'o';
		if (cli->local_operator_flag)
			aux[i++] = 'O';
		if (cli->server_notices_flag)
			aux[i++] = 's';

		aux[i] = '\0';

		len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s %03d %s %s\r\n",
			      srv->config.server_name, RPL_UMODEIS, srv_dest_nick(cli), aux);
		srv_enqueue_client_data(srv, cli, msg, len);

		break;
	case TYPE_CHAN:
		chan_name = c->args.cmd_mode.mode_args.type_chan.channel;
		strcpy(lchan, chan_name);
		irclower(lchan);

		if (db_get_channel_by_name(srv->db, lchan, &chan) != 0) {
			/*
			 * This error is not listed in the RFC, but it makes
			 * sense to report it and some servers do.
			 */
			srv_send_error_nosuchchannel(srv, cli, chan_name);
			break;
		}

		ptc = &(c->args.cmd_mode.mode_args.type_chan);

		/* Report unknown modes. */
		um_len = (int)strlen(ptc->unknown_modes);
		if (um_len != 0) {
			for (i = 0; i < um_len; ++i)
				srv_send_error_unknownmode(srv, cli, ptc->unknown_modes[i], chan_name);
		}

		/* User is in channel or not. */
		is_oper = (db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) == 0 &&
			   m.operator_flag)?1:0;

		if (ptc->num_others == 0 &&
		    ptc->anonymous == NO_ACTION &&
		    ptc->invite_only == NO_ACTION &&
		    ptc->moderated == NO_ACTION &&
		    ptc->no_outside == NO_ACTION &&
		    ptc->quiet == NO_ACTION &&
		    ptc->private_m == NO_ACTION &&
		    ptc->secret == NO_ACTION &&
		    ptc->topic == NO_ACTION) {
			/* Asking for channel modes: RPL_CHANNELMODEIS */
			snprintf(integer, sizeof(integer), "%d", chan.limit_v);

			/* My eyes! The goggles do nothing! */
			len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s %03d %s %s"
				      "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\r\n",
				      srv->config.server_name, RPL_CHANNELMODEIS,
				      srv_dest_nick(cli), chan_name,
				      (chan.key_flag ||
				       chan.limit_flag ||
				       chan.anonymous_flag ||
				       chan.invite_only_flag ||
				       chan.moderated_flag ||
				       chan.no_outside_flag ||
				       chan.quiet_flag ||
				       chan.private_flag ||
				       chan.secret_flag ||
				       chan.oper_topic_flag)?" +":"",
				       chan.anonymous_flag?"a":"",
				       chan.invite_only_flag?"i":"",
				       chan.moderated_flag?"m":"",
				       chan.no_outside_flag?"n":"",
				       chan.quiet_flag?"q":"",
				       chan.private_flag?"p":"",
				       chan.secret_flag?"s":"",
				       chan.oper_topic_flag?"t":"",
				       chan.key_flag?"k":"",
				       chan.limit_flag?"l":"",
				       chan.key_flag?" ":"",
				       chan.key_flag?chan.key:"",
				       chan.limit_flag?" ":"",
				       chan.limit_flag?integer:"");
			srv_enqueue_client_data(srv, cli, msg, len);
		} else {
			/* Report mask lists. */
			for (i = 0; i < ptc->num_others; ++i) {
				if (ptc->others[i].param[0] != '\0')
					continue;

				if (ptc->others[i].mode == MODE_BANMASK)
					srv_list_bans(srv, cli, &chan);
				else if (ptc->others[i].mode == MODE_EXCEPTMASK)
					srv_list_excepts(srv, cli, &chan);
				else if (ptc->others[i].mode == MODE_INVITEMASK)
					srv_list_invites(srv, cli, &chan);
			}

			/* Initialize the action reply structure. */
			areply.anonymous = NULL;
			areply.invite_only = NULL;
			areply.moderated = NULL;
			areply.no_outside = NULL;
			areply.quiet = NULL;
			areply.private_m = NULL;
			areply.secret = NULL;
			areply.topic = NULL;
			areply.num_others = 0;
			for (i = 0; i < MAX_CHAN_MODE_PARAMS; ++i) {
				areply.others[i].other_str = NULL;
				areply.others[i].arg_str = NULL;
			}

			/* Check channel operator status. */
			if (!is_oper) {
				error_chanop = 0;

				if (ptc->anonymous != NO_ACTION ||
				    ptc->invite_only != NO_ACTION ||
				    ptc->moderated != NO_ACTION ||
				    ptc->no_outside != NO_ACTION ||
				    ptc->quiet != NO_ACTION ||
				    ptc->private_m != NO_ACTION ||
				    ptc->secret != NO_ACTION ||
				    ptc->topic != NO_ACTION)
					error_chanop = 1;

				for (i = 0; i < ptc->num_others; ++i) {
					if (ptc->others[i].mode == MODE_OPER ||
					    ptc->others[i].mode == MODE_VOICE ||
					    ptc->others[i].mode == MODE_KEY ||
					    ptc->others[i].mode == MODE_LIMIT ||
					    (ptc->others[i].mode == MODE_BANMASK && ptc->others[i].param[0] != '\0') ||
					    (ptc->others[i].mode == MODE_EXCEPTMASK && ptc->others[i].param[0] != '\0') ||
					    (ptc->others[i].mode == MODE_INVITEMASK && ptc->others[i].param[0] != '\0'))
						error_chanop = 1;
				}

				if (error_chanop) {
					srv_send_error_chanoprivsneeded(srv, cli, chan_name);
					break;
				}
			}

			if (ptc->anonymous == ACTION_ADD && !chan.anonymous_flag) {
				chan.anonymous_flag = 1;
				areply.anonymous = "+a";
			} else if (ptc->anonymous == ACTION_REMOVE && chan.anonymous_flag) {
				chan.anonymous_flag = 0;
				areply.anonymous = "-a";
			}

			if (ptc->invite_only == ACTION_ADD && !chan.invite_only_flag) {
				chan.invite_only_flag = 1;
				areply.invite_only = "+i";
			} else if (ptc->invite_only == ACTION_REMOVE && chan.invite_only_flag) {
				chan.invite_only_flag = 0;
				areply.invite_only = "-i";
			}

			if (ptc->moderated == ACTION_ADD && !chan.moderated_flag) {
				chan.moderated_flag = 1;
				areply.moderated = "+m";
			} else if (ptc->moderated == ACTION_REMOVE && chan.moderated_flag) {
				chan.moderated_flag = 0;
				areply.moderated = "-m";
			}

			if (ptc->no_outside == ACTION_ADD && !chan.no_outside_flag) {
				chan.no_outside_flag = 1;
				areply.no_outside = "+n";
			} else if (ptc->no_outside == ACTION_REMOVE && chan.no_outside_flag) {
				chan.no_outside_flag = 0;
				areply.no_outside = "-n";
			}

			if (ptc->quiet == ACTION_ADD && !chan.quiet_flag) {
				chan.quiet_flag = 1;
				areply.quiet = "+q";
			} else if (ptc->quiet == ACTION_REMOVE && chan.quiet_flag) {
				chan.quiet_flag = 0;
				areply.quiet = "-q";
			}

			if (ptc->private_m == ACTION_ADD && !chan.private_flag) {
				chan.private_flag = 1;
				areply.private_m = "+p";
			} else if (ptc->private_m == ACTION_REMOVE && chan.private_flag) {
				chan.private_flag = 0;
				areply.private_m = "-p";
			}

			if (ptc->secret == ACTION_ADD && !chan.secret_flag) {
				chan.secret_flag = 1;
				areply.secret = "+s";
			} else if (ptc->secret == ACTION_REMOVE && chan.secret_flag) {
				chan.secret_flag = 0;
				areply.secret = "-s";
			}

			if (ptc->topic == ACTION_ADD && !chan.oper_topic_flag) {
				chan.oper_topic_flag = 1;
				areply.topic = "+t";
			} else if (ptc->topic == ACTION_REMOVE && chan.oper_topic_flag) {
				chan.oper_topic_flag = 0;
				areply.topic = "-t";
			}

			for (i = 0; i < ptc->num_others; ++i) {
				/* MODE_KEY */
				if (ptc->others[i].mode == MODE_KEY) {
					if (ptc->others[i].action == ACTION_ADD &&
					    chan.key_flag &&
					    strcmp(chan.key, ptc->others[i].param) != 0) {
						srv_send_error_keyset(srv, cli, chan_name);
					} else if (ptc->others[i].action == ACTION_ADD && !chan.key_flag) {
						chan.key_flag = 1;
						strcpy(chan.key, ptc->others[i].param);

						areply.others[areply.num_others].other_str = "+k";
						areply.others[areply.num_others].arg_str = chan.key;
						++areply.num_others;
					} else if (ptc->others[i].action == ACTION_REMOVE &&
						   chan.key_flag &&
						   strcmp(chan.key, ptc->others[i].param) == 0) {
						chan.key_flag = 0;
						chan.key[0] = '\0';

						areply.others[areply.num_others].other_str = "-k";
						areply.others[areply.num_others].arg_str = ptc->others[i].param;
						++areply.num_others;
					}
				/* MODE_LIMIT */
				} else if (ptc->others[i].mode == MODE_LIMIT) {
					if (ptc->others[i].action == ACTION_ADD) {
						chan.limit_flag = 1;
						sscanf(ptc->others[i].param, "%d", &(chan.limit_v));

						areply.others[areply.num_others].other_str = "+l";
						areply.others[areply.num_others].arg_str = ptc->others[i].param;
						++areply.num_others;
					} else if (ptc->others[i].action == ACTION_REMOVE && chan.limit_flag) {
						chan.limit_flag = 0;
						chan.limit_v = 0;

						areply.others[areply.num_others].other_str = "-l";
						++areply.num_others;
					}
				/* MODE_OPER and MODE_VOICE */
				} else if (ptc->others[i].mode == MODE_OPER || ptc->others[i].mode == MODE_VOICE) {
					strcpy(lnick, ptc->others[i].param);
					irclower(lnick);

					if (db_get_client_by_nick(srv->db, lnick, &target) == 0 &&
					    db_get_membership(srv->db, chan.id_channel, target.id_client, &m2) == 0) {
						/* MODE_OPER */
						if (ptc->others[i].mode == MODE_OPER) {
							if (ptc->others[i].action == ACTION_ADD && !m2.operator_flag) {
								m2.operator_flag = 1;

								areply.others[areply.num_others].other_str = "+o";
								areply.others[areply.num_others].arg_str = ptc->others[i].param;
								++areply.num_others;
							} else if (ptc->others[i].action == ACTION_REMOVE && m2.operator_flag) {
								m2.operator_flag = 0;

								areply.others[areply.num_others].other_str = "-o";
								areply.others[areply.num_others].arg_str = ptc->others[i].param;
								++areply.num_others;
							}
						} else { /* MODE_VOICE */
							if (ptc->others[i].action == ACTION_ADD && !m2.voice_flag) {
								m2.voice_flag = 1;

								areply.others[areply.num_others].other_str = "+v";
								areply.others[areply.num_others].arg_str = ptc->others[i].param;
								++areply.num_others;
							} else if (ptc->others[i].action == ACTION_REMOVE && m2.voice_flag) {
								m2.voice_flag = 0;

								areply.others[areply.num_others].other_str = "-v";
								areply.others[areply.num_others].arg_str = ptc->others[i].param;
								++areply.num_others;
							}
						}

						/* Modify membership in database. */
						assert(db_modify_membership(srv->db, &m2) == 0);
					} else 
						srv_send_error_usernotinchannel(srv, cli, ptc->others[i].param, chan.orig_name);
				/* MODE_BANMASK */
				} else if (ptc->others[i].mode == MODE_BANMASK && ptc->others[i].param[0] != '\0') {
					if (ptc->others[i].action == ACTION_ADD &&
					    db_count_banmasks(srv->db, chan.id_channel) < srv->config.max_bans) {
						bm.id_channel = chan.id_channel;
						strcpy(bm.orig_mask, ptc->others[i].param);
						strcpy(bm.mask, bm.orig_mask);
						irclower(bm.mask);

						if (db_get_banmask_by_mask(srv->db, bm.id_channel, bm.mask, &bm) != 0)
							assert(db_add_banmask(srv->db, &bm) == 0);

						areply.others[areply.num_others].other_str = "+b";
						areply.others[areply.num_others].arg_str = ptc->others[i].param;
						++areply.num_others;

					} else if (ptc->others[i].action == ACTION_REMOVE) {
						/* Exceptionally, we're going to normalize in place. */
						irclower(ptc->others[i].param);

						if (db_get_banmask_by_mask(srv->db, chan.id_channel,
									   ptc->others[i].param, &bm) == 0) {
							/* Delete banmask and accumulate reply. */
							assert(db_del_banmask(srv->db, &bm) == 0);
							areply.others[areply.num_others].other_str = "-b";
							areply.others[areply.num_others].arg_str = ptc->others[i].param;
							++areply.num_others;
						}
					}
				/* MODE_EXCEPTMASK */
				} else if (ptc->others[i].mode == MODE_EXCEPTMASK && ptc->others[i].param[0] != '\0') {
					if (ptc->others[i].action == ACTION_ADD &&
					    db_count_exceptmasks(srv->db, chan.id_channel) < srv->config.max_excepts) {
						em.id_channel = chan.id_channel;
						strcpy(em.orig_mask, ptc->others[i].param);
						strcpy(em.mask, em.orig_mask);
						irclower(em.mask);

						if (db_get_exceptmask_by_mask(srv->db, em.id_channel, em.mask, &em) != 0)
							assert(db_add_exceptmask(srv->db, &em) == 0);

						areply.others[areply.num_others].other_str = "+e";
						areply.others[areply.num_others].arg_str = ptc->others[i].param;
						++areply.num_others;

					} else if (ptc->others[i].action == ACTION_REMOVE) {
						/* Exceptionally, we're going to normalize in place. */
						irclower(ptc->others[i].param);

						if (db_get_exceptmask_by_mask(srv->db, chan.id_channel,
									      ptc->others[i].param, &em) == 0) {
							/* Delete exceptmask and accumulate reply. */
							assert(db_del_exceptmask(srv->db, &em) == 0);
							areply.others[areply.num_others].other_str = "-e";
							areply.others[areply.num_others].arg_str = ptc->others[i].param;
							++areply.num_others;
						}
					}
				/* MODE_INVITEMASK */
				} else if (ptc->others[i].mode == MODE_INVITEMASK && ptc->others[i].param[0] != '\0') {
					if (ptc->others[i].action == ACTION_ADD &&
					    db_count_invitemasks(srv->db, chan.id_channel) < srv->config.max_invites) {
						im.id_channel = chan.id_channel;
						strcpy(im.orig_mask, ptc->others[i].param);
						strcpy(im.mask, im.orig_mask);
						irclower(im.mask);

						if (db_get_invitemask_by_mask(srv->db, im.id_channel, im.mask, &im) != 0)
							assert(db_add_invitemask(srv->db, &im) == 0);

						areply.others[areply.num_others].other_str = "+I";
						areply.others[areply.num_others].arg_str = ptc->others[i].param;
						++areply.num_others;

					} else if (ptc->others[i].action == ACTION_REMOVE) {
						/* Exceptionally, we're going to normalize in place. */
						irclower(ptc->others[i].param);

						if (db_get_invitemask_by_mask(srv->db, chan.id_channel,
									      ptc->others[i].param, &im) == 0) {
							/* Delete invitemask and accumulate reply. */
							assert(db_del_invitemask(srv->db, &im) == 0);
							areply.others[areply.num_others].other_str = "-I";
							areply.others[areply.num_others].arg_str = ptc->others[i].param;
							++areply.num_others;
						}
					}
				}
			}

			/* Save channel modifications to database. */
			assert(db_modify_channel(srv->db, &chan) == 0);

			if (areply.anonymous == NULL &&
			    areply.invite_only == NULL &&
			    areply.moderated == NULL &&
			    areply.no_outside == NULL &&
			    areply.quiet == NULL &&
			    areply.private_m == NULL &&
			    areply.secret == NULL &&
			    areply.topic == NULL &&
			    areply.num_others == 0)
				/*
				 * No mode changes, no reply needed (e.g: the
				 * user only requested the ban list).
				 */
				break;

			/* Prepare reply. */
			len = srv_fmt(msg, MESSAGE_BUFFER_SIZE,
				      ":%s MODE %s %s%s%s%s%s%s%s%s",
				      cli->orig_fullname,
				      chan.orig_name,
				      (areply.anonymous != NULL)?areply.anonymous:"",
				      (areply.invite_only != NULL)?areply.invite_only:"",
				      (areply.moderated != NULL)?areply.moderated:"",
				      (areply.no_outside != NULL)?areply.no_outside:"",
				      (areply.quiet != NULL)?areply.quiet:"",
				      (areply.private_m != NULL)?areply.private_m:"",
				      (areply.secret != NULL)?areply.secret:"",
				      (areply.topic != NULL)?areply.topic:"");

			for (i = 0; i < areply.num_others; ++i) {
				len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "%s",
					       (areply.others[i].other_str != NULL)?areply.others[i].other_str:"");
			}

			for (i = 0; i < areply.num_others; ++i) {
				len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "%s%s",
					       (areply.others[i].arg_str != NULL)?" ":"",
					       (areply.others[i].arg_str != NULL)?areply.others[i].arg_str:"");
			}

			len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "\r\n");
			/* Just in case we ran out of space previously. */
			msg[MESSAGE_BUFFER_SIZE - 1] = '\0';
			msg[MESSAGE_BUFFER_SIZE - 2] = '\n';
			msg[MESSAGE_BUFFER_SIZE - 3] = '\r';

			/* Send MODE command to every channel member. */
			args.srv = srv;
			args.msg = msg;
			args.len = len;
			assert(db_run_on_members(srv->db, chan.id_channel, srv_enqueue_cb, &args) == 0);
		}
		break;
	}

out:
	srv_free(&msg);
}

static void srv_list_bans_cb(void *mask_, void *args_)
{
	struct db_banmask *mask;
	struct srv_list_masks_args *args;

	mask = mask_;
	args = args_;

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s\r\n",
		    args->srv->config.server_name, RPL_BANLIST, srv_dest_nick(args->cli),
		    args->chan->orig_name, mask->orig_mask);
}

static void srv_list_excepts_cb(void *mask_, void *args_)
{
	struct db_exceptmask *mask;
	struct srv_list_masks_args *args;

	mask = mask_;
	args = args_;

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s\r\n",
		    args->srv->config.server_name, RPL_EXCEPTLIST, srv_dest_nick(args->cli),
		    args->chan->orig_name, mask->orig_mask);
}

static void srv_list_invites_cb(void *mask_, void *args_)
{
	struct db_invitemask *mask;
	struct srv_list_masks_args *args;

	mask = mask_;
	args = args_;

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s\r\n",
		    args->srv->config.server_name, RPL_INVITELIST, srv_dest_nick(args->cli),
		    args->chan->orig_name, mask->orig_mask);
}

static void srv_list_bans(struct server *srv, struct db_client *cli, struct db_channel *chan)
{
	struct srv_list_masks_args args;

	args.srv = srv;
	args.cli = cli;
	args.chan = chan;
	assert(db_run_on_banmasks(srv->db, chan->id_channel, srv_list_bans_cb, &args) == 0);

	srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of channel ban list\r\n",
		    srv->config.server_name, RPL_ENDOFBANLIST, srv_dest_nick(cli), chan->orig_name);
}

static void srv_list_excepts(struct server *srv, struct db_client *cli, struct db_channel *chan)
{
	struct srv_list_masks_args args;

	args.srv = srv;
	args.cli = cli;
	args.chan = chan;
	assert(db_run_on_exceptmasks(srv->db, chan->id_channel, srv_list_excepts_cb, &args) == 0);

	srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of channel exception list\r\n",
		    srv->config.server_name, RPL_ENDOFEXCEPTLIST, srv_dest_nick(cli), chan->orig_name);
}

static void srv_list_invites(struct server *srv, struct db_client *cli, struct db_channel *chan)
{
	struct srv_list_masks_args args;

	args.srv = srv;
	args.cli = cli;
	args.chan = chan;
	assert(db_run_on_invitemasks(srv->db, chan->id_channel, srv_list_invites_cb, &args) == 0);

	srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of channel invite list\r\n",
		    srv->config.server_name, RPL_ENDOFINVITELIST, srv_dest_nick(cli), chan->orig_name);
}

static void srv_process_away(struct server *srv, struct db_client *cli, struct command *c)
{
	if (strlen(c->args.cmd_away.text) == 0) {
		cli->away_text[0] = '\0';
		if (! cli->away_flag)
			return;
		cli->away_flag = 0;
		srv_send_reply_unaway(srv, cli);
	} else {
		cli->away_flag = 1;
		strcpy(cli->away_text, c->args.cmd_away.text);
		srv_send_reply_nowaway(srv, cli);
	}
}

static void srv_who_chan_cb(void *cli_, void *args_)
{
	struct db_client *curcli;
	struct srv_who_chan_cb_args *args;
	struct db_membership m;

	curcli = cli_;
	args = args_;

	if (curcli->invisible_flag && ! args->all)
		return;

	assert(db_get_membership(args->srv->db, args->chan->id_channel, curcli->id_client, &m) == 0);

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s %s %s %s %s%s%s :0 %s\r\n",
		    args->srv->config.server_name, RPL_WHOREPLY, srv_dest_nick(args->cli),
		    args->chan->orig_name, curcli->username, curcli->ip, args->srv->config.server_name,
		    curcli->orig_nickname, curcli->away_flag?"G":"H",
		    (curcli->operator_flag || curcli->local_operator_flag)?"*":"", srv_memb_symbol(&m),
		    curcli->realname);
}

static void srv_process_who(struct server *srv, struct db_client *cli, struct command *c)
{
	/*
	 * I had to look at the ircd source code to know how to build part of
	 * the WHO response. In particular, the [HG]\*?[@+]? string. G or H is
	 * chosen according to the client's away state (mnemonics: Gone or
	 * Here), the asterisk is present if the user is a network operator and
	 * the @ or + signs in case the reply conveys channel membership
	 * information, to indicate channel operator or voice flags.
	 */
	struct db_client tcli;
	struct db_channel tchan;
	struct db_membership m;
	struct srv_who_chan_cb_args args;
	char ln[NICKNAME_BUFFER_SIZE];
	char lc[CHANNEL_BUFFER_SIZE];

	if (c->args.cmd_who.target_type != TYPE_NICK &&
	    c->args.cmd_who.target_type != TYPE_CHAN)
		return;

	if (c->args.cmd_who.target_type == TYPE_NICK) {
		strcpy(ln, c->args.cmd_who.target.nickname);
		irclower(ln);

		if (db_get_client_by_nick(srv->db, ln, &tcli) == 0) {
			srv_fmt_enq(srv, cli, ":%s %03d %s * %s %s %s %s %s%s :0 %s\r\n",
				    srv->config.server_name, RPL_WHOREPLY, srv_dest_nick(cli),
				    tcli.username, tcli.ip, srv->config.server_name, tcli.orig_nickname,
				    tcli.away_flag?"G":"H", (tcli.operator_flag || tcli.local_operator_flag)?"*":"",
				    tcli.realname);
		}

	} else if (c->args.cmd_who.target_type == TYPE_CHAN) {
		strcpy(lc, c->args.cmd_who.target.channel);
		irclower(lc);

		if (db_get_channel_by_name(srv->db, lc, &tchan) == 0 && !(tchan.quiet_flag || tchan.secret_flag)) {
			args.srv = srv;
			args.cli = cli;
			args.chan = &tchan;
			args.all = (cli->operator_flag || cli->local_operator_flag ||
				    db_get_membership(srv->db, tchan.id_channel, cli->id_client, &m) == 0);
			db_run_on_members(srv->db, tchan.id_channel, srv_who_chan_cb, &args);
		}
	}

	srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of WHO list\r\n",
		    srv->config.server_name, RPL_ENDOFWHO, srv_dest_nick(cli),
		    c->args.cmd_who.target.nickname);
}

static void srv_process_version(struct server *srv, struct db_client *cli, struct command *c)
{
	if (strlen(c->args.cmd_version.target) > 0 && strcmp(c->args.cmd_version.target, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_version.target);
	else {
		srv_fmt_enq(srv, cli, ":%s %03d %s " BUILD_VERSION ".- %s :-\r\n",
			    srv->config.server_name, RPL_VERSION, srv_dest_nick(cli), srv->config.server_name);
	}
}

static void srv_process_links(struct server *srv, struct db_client *cli, struct command *c)
{
	if (strlen(c->args.cmd_links.remote_server) > 0 && strcmp(c->args.cmd_links.remote_server, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_links.remote_server);
	else {
		srv_fmt_enq(srv, cli, ":%s %03d %s :End of LINKS list\r\n",
			    srv->config.server_name, RPL_ENDOFLINKS, srv_dest_nick(cli));
	}
}

static void srv_process_time(struct server *srv, struct db_client *cli, struct command *c)
{
	time_t now;
	char datestr[32]; /* At least 26 according to the manual page. */

	if (strlen(c->args.cmd_time.target) > 0 && strcmp(c->args.cmd_time.target, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_time.target);
	else {
		now = time(NULL);
		ctime_r(&now, datestr);

		srv_fmt_enq(srv, cli, ":%s %03d %s %s :%s\r\n",
			    srv->config.server_name, RPL_TIME, srv_dest_nick(cli),
			    srv->config.server_name, datestr);
	}
}

static void srv_process_admin(struct server *srv, struct db_client *cli, struct command *c)
{
	const char *s;
	const char *n;

	if (strlen(c->args.cmd_trace.target) > 0 && strcmp(c->args.cmd_trace.target, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_trace.target);
	else {
		s = srv->config.server_name;
		n = srv_dest_nick(cli);
		srv_fmt_enq(srv, cli,
			    ":%s %03d %s %s :Administrative info\r\n"
			    ":%s %03d %s :%s\r\n"
			    ":%s %03d %s :%s\r\n"
			    ":%s %03d %s :%s\r\n",
			    s, RPL_ADMINME, n, srv->config.server_name,
			    s, RPL_ADMINLOC1, n, srv->config.location,
			    s, RPL_ADMINLOC2, n, srv->config.entity,
			    s, RPL_ADMINEMAIL, n, srv->config.email);
	}
}

static void srv_process_trace(struct server *srv, struct db_client *cli, struct command *c)
{
	if (strlen(c->args.cmd_admin.target) > 0 && strcmp(c->args.cmd_admin.target, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_admin.target);
	else {
		srv_fmt_enq(srv, cli, ":%s %03d %s %s " BUILD_VERSION ".- :End of TRACE\r\n",
			    srv->config.server_name, RPL_TRACEEND, srv_dest_nick(cli), srv->config.server_name);
	}
}

static void srv_process_info(struct server *srv, struct db_client *cli, struct command *c)
{
	char datestr[32]; /* At least 26 according to the manual page. */
	const char *s;
	const char *n;

	if (strlen(c->args.cmd_info.target) > 0 && strcmp(c->args.cmd_info.target, srv->config.server_name) != 0)
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_info.target);
	else {
		ctime_r(&(srv->dyndata.start_time), datestr);
		s = srv->config.server_name;
		n = srv_dest_nick(cli);

		srv_fmt_enq(srv, cli,
			    ":%s %03d %s :" BUILD_NAME " " BUILD_VERSION "\r\n"
			    ":%s %03d %s :Server start date: %s\r\n"
			    ":%s %03d %s :Server build date: " BUILD_DATE "\r\n"
			    ":%s %03d %s :Server build system: " BUILD_SYSTEM "\r\n"
			    ":%s %03d %s :End of INFO list\r\n",
			    s, RPL_INFO, n,
			    s, RPL_INFO, n, datestr,
			    s, RPL_INFO, n,
			    s, RPL_INFO, n,
			    s, RPL_ENDOFINFO, n);
	}
}

static void srv_process_service(struct server *srv, struct db_client *cli, struct command *c)
{
	if ((cli->regstate & REGSTATE_USER) != 0 &&
	    (cli->regstate & REGSTATE_NICK) != 0) {
		srv_send_error_alreadyregistred(srv, cli);
		return;
	}

	/*
	 * As services are not supported, the most sensible option is to send
	 * them an erroneous nickname error every time.
	 */
	srv_send_error_erroneusnickname(srv, cli, c->args.cmd_service.nickname);
}

static void srv_process_userhost(struct server *srv, struct db_client *cli, struct command *c)
{
	struct db_client other;
	char l[NICKNAME_BUFFER_SIZE];
	int i;
	int used;

	char *msg = srv_malloc_msg();
	int len;

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s %03d %s ",
		      srv->config.server_name, RPL_USERHOST, srv_dest_nick(cli));

	for (used = 0, i = 0; i < c->args.cmd_userhost.num_nicknames; ++i) {
		strcpy(l, c->args.cmd_userhost.nicknames[i]);
		irclower(l);

		if (db_get_client_by_nick(srv->db, l, &other) != 0)
			continue;

		len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "%s%s%s=%s%s",
			       (used == 0)?":":" ", other.orig_nickname,
			       (other.local_operator_flag || other.operator_flag)?"*":"",
			       other.away_flag?"-":"+", other.ip);
		++used;
	}

	if (used != 0) {
		len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "\r\n");
		msg[MESSAGE_BUFFER_SIZE - 1] = '\0';
		msg[MESSAGE_BUFFER_SIZE - 2] = '\n';
		msg[MESSAGE_BUFFER_SIZE - 3] = '\r';
		srv_enqueue_client_data(srv, cli, msg, len);
	}

	srv_free(&msg);
}

static void srv_process_ison(struct server *srv, struct db_client *cli, struct command *c)
{
	/* Very similar to USERHOST, but simpler. */
	struct db_client other;
	char l[NICKNAME_BUFFER_SIZE];
	int i;
	int used;

	char *msg = srv_malloc_msg();
	int len;

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s %03d %s ",
		      srv->config.server_name, RPL_ISON, srv_dest_nick(cli));

	for (used = 0, i = 0; i < c->args.cmd_ison.num_nicknames; ++i) {
		strcpy(l, c->args.cmd_ison.nicknames[i]);
		irclower(l);

		if (db_get_client_by_nick(srv->db, l, &other) != 0)
			continue;

		len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "%s%s",
			       (used == 0)?":":" ", other.orig_nickname);
		++used;
	}

	if (used != 0) {
		len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "\r\n");
		msg[MESSAGE_BUFFER_SIZE - 1] = '\0';
		msg[MESSAGE_BUFFER_SIZE - 2] = '\n';
		msg[MESSAGE_BUFFER_SIZE - 3] = '\r';
		srv_enqueue_client_data(srv, cli, msg, len);
	}
	
	srv_free(&msg);
}

static void srv_process_oper(struct server *srv, struct db_client *cli, struct command *c)
{
	char *msg = srv_malloc_msg();

	struct db_client other;
	sqlite3_int64 id_oper;

	if (db_get_operator_id(srv->db, c->args.cmd_oper.name,
			       c->args.cmd_oper.password, &id_oper) != 0 ||
	    /*
	     * We are not allowing two operators authenticated with the same
	     * account, but this may change in the future.
	     */
	    db_get_client_by_opid(srv->db, id_oper, &other) == 0) {
		srv_send_error_passwdmismatch(srv, cli);

		/* Log failed authentication attempt. */
		snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld OPER failed for name %s",
			 (long long)(cli->id_client), c->args.cmd_oper.name);
		srv_log(srv, msg);

		goto out;
	}

	cli->id_oper = id_oper;
	cli->operator_flag = 1;
	srv_send_reply_youreoper(srv, cli);

	/* Log successful authentication attempt. */
	snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld OPER succeeded for name %s",
		 (long long)(cli->id_client), c->args.cmd_oper.name);
	srv_log(srv, msg);

out:
	srv_free(&msg);
}

static void srv_whowas_cb(void *whowas_, void *args_)
{
	struct db_whowas *whowas;
	struct srv_whowas_cb_args *args;

	whowas = whowas_;
	args = args_;

	args->results += 1;

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s %s * :%s\r\n",
		    args->srv->config.server_name, RPL_WHOWASUSER, srv_dest_nick(args->cli),
		    whowas->orig_nickname, whowas->username, whowas->ip, whowas->realname);
}

static void srv_process_whowas(struct server *srv, struct db_client *cli, struct command *c)
{
	char *lnick = srv_malloc_msg();
	int i;
	const char *nick;
	struct srv_whowas_cb_args args;

	for (i = 0; i < c->args.cmd_whowas.num_nicknames; ++i) {
		nick = c->args.cmd_whowas.nicknames[i];
		strcpy(lnick, nick);
		irclower(lnick);

		args.srv = srv;
		args.cli = cli;
		args.results = 0;

		assert(db_run_on_whowas(srv->db, lnick, c->args.cmd_whowas.count, srv_whowas_cb, &args) == 0);
		if (args.results == 0) {
			srv_fmt_enq(srv, cli, ":%s %03d %s %s :There was no such nickname\r\n",
				    srv->config.server_name, ERR_WASNOSUCHNICK, srv_dest_nick(cli), nick);
		}

		srv_fmt_enq(srv, cli, ":%s %03d %s %s :End of WHOWAS\r\n",
			    srv->config.server_name, RPL_ENDOFWHOWAS, srv_dest_nick(cli), nick);
	}

	srv_free(&lnick);
}

static void srv_whois_cb(void *chan_, void *args_)
{
	struct db_channel *chan;
	struct srv_whois_cb_args *args;

	struct db_membership w_memb;
	struct db_membership c_memb;

	chan = chan_;
	args = args_;

	if ((chan->secret_flag || chan->private_flag) &&
	    (! args->cli->operator_flag && ! args->cli->local_operator_flag) &&
	    (db_get_membership(args->srv->db, chan->id_channel, args->cli->id_client, &c_memb) != 0))
		/*
		 * Private and secret channels are hidden from the response
		 * unless the requesting client is also a member of the
		 * channel or an operator.
		 */
		return;

	assert(db_get_membership(args->srv->db, chan->id_channel, args->wn->id_client, &w_memb) == 0);

	srv_fmt_enq(args->srv, args->cli, ":%s %03d %s %s %s%s\r\n",
		    args->srv->config.server_name, RPL_WHOISCHANNELS,
		    srv_dest_nick(args->cli), args->wn->orig_nickname,
		    srv_memb_symbol(&w_memb), chan->orig_name);
}

static void srv_process_whois(struct server *srv, struct db_client *cli, struct command *c)
{
	char *lnick = srv_malloc_msg();
	struct db_client wn;
	const char *nick;
	int i;

	const char *s;
	const char *n;

	struct srv_whois_cb_args args;

	/*
	 * Ignore the target argument, as some clients tend to send "WHOIS nick
	 * nick" in order to make sure the idle time is returned, and it is not
	 * relevant anyway.
	 */
#if 0
	if (strlen(c->args.cmd_whois.target) != 0 &&
	    strcmp(c->args.cmd_whois.target, srv->config.server_name) != 0) {
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_whois.target);
		return;
	}
#endif

	s = srv->config.server_name;
	n = srv_dest_nick(cli);

	for (i = 0; i < c->args.cmd_whois.num_nicknames; ++i) {
		nick = c->args.cmd_whois.nicknames[i];
		strcpy(lnick, nick);
		irclower(lnick);

		if (db_get_client_by_nick(srv->db, lnick, &wn) != 0) {
			srv_send_error_nosuchnick(srv, cli, nick);
			continue;
		}

		srv_fmt_enq(srv, cli,
			    ":%s %03d %s %s %s %s * :%s\r\n"
			    ":%s %03d %s %s %s :\r\n"
			    /*
			     * The signon time is not standard in either the
			     * old RFC or the new one, but some clients
			     * expect it to be present as the most prominent
			     * IRC networks do return it.
			     */
			    ":%s %03d %s %s %ld %ld :seconds idle, signon time\r\n",
			    s, RPL_WHOISUSER, n, wn.orig_nickname, wn.username, wn.ip, wn.realname,
			    s, RPL_WHOISSERVER, n, wn.orig_nickname, s,
			    s, RPL_WHOISIDLE, n, wn.orig_nickname,
			    (long)(time(NULL) - wn.last_talk),
			    (long)(wn.signon_time));

		if (wn.operator_flag || wn.local_operator_flag) {
			srv_fmt_enq(srv, cli, ":%s %03d %s %s :is an IRC operator\r\n",
				    s, RPL_WHOISOPERATOR, n, wn.orig_nickname);
		}

		args.srv = srv;
		args.cli = cli;
		args.wn = &wn;
		assert(db_run_on_client_channels(srv->db, wn.id_client, srv_whois_cb, &args) == 0);
	}

	srv_fmt_enq(srv, cli,
		    ":%s %03d %s %s :End of WHOIS list\r\n",
		    srv->config.server_name, RPL_ENDOFWHOIS,
		    srv_dest_nick(cli), c->args.cmd_whois.orig_query);

	srv_free(&lnick);
}

static void srv_process_kill(struct server *srv, struct db_client *cli, struct command *c)
{
	char *lnick = srv_malloc_msg();
	char *msg = srv_malloc_msg();
	struct db_client killed;


	if (! cli->operator_flag && ! cli->local_operator_flag) {
		srv_send_error_noprivileges(srv, cli);
		goto out;
	}

	strcpy(lnick, c->args.cmd_kill.nickname);
	irclower(lnick);

	if (db_get_client_by_nick(srv->db, lnick, &killed) != 0) {
		srv_send_error_nosuchnick(srv, cli, c->args.cmd_kill.nickname);
		goto out;
	}

	/* Add the nick to the list of forbidden nicks for some time. */
	assert(db_add_expiring_forbidden_nick(srv->db, killed.nickname, srv->config.kill_timeout_seconds) == 0);

	/* Generate the QUIT message for everyone. */
	srv_fmt(msg, MESSAGE_BUFFER_SIZE, "Killed: %s",
		(c->args.cmd_kill.comment[0] != '\0')?c->args.cmd_kill.comment:"<no reason given>");
	srv_client_quit(srv, &killed, msg);

out:
	srv_free(&lnick);
	srv_free(&msg);
}

static void srv_report_cmd_stats(struct server *srv, struct db_client *cli)
{
	/*
	 * These names must be totally related to CMD_BASE_NUMBER,
	 * CMD_TOP_NUMBER and other CMD_* constants.
	 */
	static const char *cmd_names[] = {
		"*", "PASS", "NICK", "USER", "OPER", "MODE", "SERVICE", "QUIT",
		"SQUIT", "JOIN", "PART", "*", "TOPIC", "NAMES", "LIST",
		"INVITE", "KICK", "PRIVMSG", "NOTICE", "MOTD", "LUSERS",
		"VERSION", "STATS", "LINKS", "TIME", "CONNECT", "TRACE",
		"ADMIN", "INFO", "SERVLIST", "SQUERY", "WHO", "WHOIS",
		"WHOWAS", "KILL", "PING", "PONG", "ERROR", "AWAY", "REHASH",
		"DIE", "RESTART", "SUMMON", "USERS", "WALLOPS", "USERHOST",
		"ISON", "*", "*", "*",
		NULL
	};

	int i;
	for (i = 0; cmd_names[i] != NULL; ++i) {
		if (cmd_names[i][0] == '*')
			continue;

		srv_fmt_enq(srv, cli, ":%s %03d %s %s %lld %lld *\r\n",
			    srv->config.server_name, RPL_STATSCOMMANDS, srv_dest_nick(cli),
			    cmd_names[i], srv->dyndata.cmd_counters[i].number,
			    srv->dyndata.cmd_counters[i].bytes);
	}
}

static void srv_process_stats(struct server *srv, struct db_client *cli, struct command *c)
{
	int t, d, h, m, s;

	if (strlen(c->args.cmd_stats.target) > 0 &&
	    strcmp(c->args.cmd_stats.target, srv->config.server_name) != 0) {
		srv_send_error_nosuchserver(srv, cli, c->args.cmd_stats.target);
		return;
	}

	switch (c->args.cmd_stats.query) {
	case 'l':
		/* Requested numbers cannot be reported. */
		srv_fmt_enq(srv, cli, ":%s %03d %s * * * * * * *\r\n",
			    srv->config.server_name, RPL_STATSLINKINFO, srv_dest_nick(cli));
		break;
	case 'm':
		srv_report_cmd_stats(srv, cli);
		break;
	case 'o':
		srv_fmt_enq(srv, cli, ":%s %03d %s 0 * * *\r\n",
			    srv->config.server_name, RPL_STATSOLINE, srv_dest_nick(cli));
		break;
	case 'u':
		t = (int)(time(NULL) - srv->dyndata.start_time);
		d = t / 86400; t %= 86400;
		h = t / 3600; t %= 3600;
		m = t / 60;
		s = t % 60;

		srv_fmt_enq(srv, cli, ":%s %03d %s :Server Up %d days %d:%02d:%02d\r\n",
			    srv->config.server_name, RPL_STATSUPTIME, srv_dest_nick(cli), d, h, m, s);
		break;
	}

	srv_fmt_enq(srv, cli, ":%s %03d %s %c :End of STATS report\r\n",
		    srv->config.server_name, RPL_ENDOFSTATS, srv_dest_nick(cli),
		    (c->args.cmd_stats.query == '\0')?'*':c->args.cmd_stats.query);
}

static void srv_one_names_cb(void *cli_, void *args_)
{
	/*
	 * This callback proceeds to accumulate nicks in the NAMES reply buffer
	 * until it reaches a maximum. At that point, it sends out the
	 * accumulated reply. If the buffer is empty, it prepares the reply
	 * with its reply prefix and the first nick. If it's not empty, it
	 * concatenates the next nick to the reply.
	 */
	char minibuffer[NICKNAME_BUFFER_SIZE + 2];
	struct db_client *cli;
	struct srv_one_names_cb_args *args;

	struct db_membership m;

	int minilen;

	cli = cli_;
	args = args_;

	assert(db_get_membership(args->srv->db, args->chan->id_channel, cli->id_client, &m) == 0);

	if (!args->all && cli->invisible_flag)
		return;

	if (args->accum == 0) {
		args->bufused = snprintf(args->buffer, args->bufsize, ":%s %03d %s %s %s :%s%s",
					 args->srv->config.server_name, RPL_NAMREPLY, srv_dest_nick(args->cli),
					 srv_chan_symbol(args->chan), args->chan->orig_name, srv_memb_symbol(&m),
					 cli->orig_nickname);
		assert(args->bufused < args->bufsize - 3);
		args->accum += 1;
	} else {
		snprintf(minibuffer, sizeof(minibuffer), " %s%s", srv_memb_symbol(&m), cli->orig_nickname);
		minilen = strlen(minibuffer);
		assert(args->bufused + minilen < args->bufsize - 3);

		strcpy(args->buffer + args->bufused, minibuffer);
		args->bufused += minilen;
		args->accum += 1;
	}

	if (args->accum < MAX_NAMREPLY_NICKS)
		return;

	strcpy(args->buffer + args->bufused, "\r\n");
	args->bufused += 2;

	srv_enqueue_client_data(args->srv, args->cli, args->buffer, args->bufused);
	args->buffer[0] = '\0';
	args->bufused = 0;
	args->accum = 0;
}

static void srv_process_one_names(struct server *srv, struct db_client *cli, struct db_channel *chan, int all)
{
	char *msg = srv_malloc_msg();
	int len;

	struct srv_one_names_cb_args args;

	if (! chan->quiet_flag) {
		msg[0] = '\0';
		args.srv = srv;
		args.cli = cli;
		args.chan = chan;
		args.all = all;
		args.buffer = msg;
		args.bufsize = MESSAGE_BUFFER_SIZE;
		args.bufused = 0;
		args.accum = 0;

		assert(db_run_on_members(srv->db, chan->id_channel, srv_one_names_cb, &args) == 0);

		/* Send possible remaining unsent reply line. */
		len = (int)strlen(msg);
		if (len > 0) {
			len += srv_fmt(msg + len, MESSAGE_BUFFER_SIZE - len, "\r\n");
			srv_enqueue_client_data(srv, cli, msg, len);
		}
	}

	srv_send_reply_endofnames(srv, cli, chan->orig_name);
	srv_free(&msg);
}

static void srv_process_one_join(struct server *srv, struct db_client *cli, const char *cname, const char *key)
{
	struct srv_enqueue_cb_args args;
	char *msg = srv_malloc_msg();
	int len;

	char *lchan = srv_malloc_msg();
	struct db_channel chan;
	struct db_membership memb;
	int ret;

	strcpy(lchan, cname);
	irclower(lchan);

	if (db_count_client_channels(srv->db, cli->id_client) >= srv->config.max_client_channels) {
		srv_send_error_toomanychannels(srv, cli, cname);
		goto out;
	}

	if (db_get_channel_by_name(srv->db, lchan, &chan) != 0) {
		/* Channel does not exist. */

		if (db_count_channels(srv->db) >= srv->config.max_channels) {
			srv_send_error_unavailresource(srv, cli, cname);
			goto out;
		}

		memset(&chan, 0, sizeof(chan));
		strcpy(chan.orig_name, cname);
		strcpy(chan.name, lchan);

		assert(db_add_channel(srv->db, &chan) == 0);

		/* Log channel creation. */
		snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld created channel %s",
			 (long long)(cli->id_client), lchan);
		srv_log(srv, msg);

		memb.id_channel = chan.id_channel;
		memb.id_client = cli->id_client;
		memb.operator_flag = 1;
		memb.voice_flag = 0;

	} else {
		/* Channel exists. */

		if (db_count_channel_members(srv->db, chan.id_channel) >=
		    srv->config.max_channel_members) {
			srv_send_error_unavailresource(srv, cli, cname);
			goto out;
		}

		ret = db_client_may_join(srv->db, cli, &chan, key);
		switch(ret) {
		case ERR_BADCHANNELKEY:
			srv_send_error_badchannelkey(srv, cli, cname);
			goto out;
		case ERR_CHANNELISFULL:
			srv_send_error_channelisfull(srv, cli, cname);
			goto out;
		case ERR_INVITEONLYCHAN:
			srv_send_error_inviteonlychan(srv, cli, cname);
			goto out;
		case ERR_BANNEDFROMCHAN:
			srv_send_error_bannedfromchan(srv, cli, cname);
			goto out;
		case ERR_NOPRIVILEGES:
			/*
			 * According to the RFC, this is not one of the allowed
			 * replies for a JOIN command, but the special channels
			 * is a specific feature for this server.
			 */
			srv_send_error_noprivileges(srv, cli);
			goto out;
		case -1:
			/* Client is already on the channel. */
			goto out;
		default:
			break;
		}

		/* No errors. Client may join. */
		memb.id_channel = chan.id_channel;
		memb.id_client = cli->id_client;
		memb.operator_flag = 0;
		memb.voice_flag = 0;
	}

	assert(db_add_membership(srv->db, &memb) == 0);

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s JOIN %s\r\n", cli->orig_fullname, chan.orig_name);
	srv_enqueue_client_data(srv, cli, msg, len);

	if (! chan.quiet_flag) {
		args.srv = srv;
		args.msg = msg;
		args.len = len;
		assert(db_run_on_members_except(srv->db, chan.id_channel, cli->id_client, srv_enqueue_cb, &args) == 0);
	}

	srv_send_reply_topic(srv, cli, chan.orig_name, chan.topic);
	srv_process_one_names(srv, cli, &chan, 1);

	/* Log client join. */
	snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld joins channel %s",
		 (long long)(cli->id_client), chan.name);
	srv_log(srv, msg);

out:
	srv_free(&msg);
	srv_free(&lchan);
}

static void srv_join_zero_cb(void *chan_, void *args_)
{
	struct db_channel *chan;
	struct srv_join_zero_cb_args *args;

	chan = chan_;
	args = args_;

	srv_process_one_part(args->srv, args->cli, chan->orig_name, args->cli->orig_nickname);
}

static void srv_process_join(struct server *srv, struct db_client *cli, struct command *c)
{
	struct srv_join_zero_cb_args args;
	int i;

	if (c->args.cmd_join.num_channels == 1 &&
	    strcmp(c->args.cmd_join.channels[0], "0") == 0) {
		args.srv = srv;
		args.cli = cli;
		assert(db_run_on_client_channels(srv->db, cli->id_client, srv_join_zero_cb, &args) == 0);
		return;
	}

	for (i = 0; i < c->args.cmd_join.num_channels; ++i) {
		srv_process_one_join(srv, cli, c->args.cmd_join.channels[i],
				     (i >= c->args.cmd_join.num_keys)?NULL:c->args.cmd_join.keys[i]);
	}
}

static void srv_process_topic(struct server *srv, struct db_client *cli, struct command *c)
{
	struct srv_enqueue_cb_args args;
	char *msg = srv_malloc_msg();
	int len;

	char *lchan = srv_malloc_msg();
	struct db_channel chan;
	struct db_membership m;

	strcpy(lchan, c->args.cmd_topic.channel);
	irclower(lchan);

	if (db_get_channel_by_name(srv->db, lchan, &chan) != 0 || chan.secret_flag) {
		srv_send_error_notonchannel(srv, cli, c->args.cmd_topic.channel);
		goto out;
	}
	
	if (c->args.cmd_topic.topic_given) {
		if (db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) != 0) {
			srv_send_error_notonchannel(srv, cli, c->args.cmd_topic.channel);
			goto out;
		} else if (chan.oper_topic_flag && !m.operator_flag) {
			srv_send_error_chanoprivsneeded(srv, cli, c->args.cmd_topic.channel);
			goto out;
		}

		strcpy(chan.topic, c->args.cmd_topic.topic);
		assert(db_modify_channel(srv->db, &chan) == 0);

		len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s TOPIC %s :%s\r\n",
			      cli->orig_fullname, chan.orig_name, c->args.cmd_topic.topic);

		args.srv = srv;
		args.msg = msg;
		args.len = len;
		assert(db_run_on_members_except(srv->db, chan.id_channel, cli->id_client, srv_enqueue_cb, &args) == 0);
	}

	if (strlen(chan.topic) != 0)
		srv_send_reply_topic(srv, cli, chan.orig_name, chan.topic);
	else
		srv_send_reply_notopic(srv, cli, chan.orig_name);

out:
	srv_free(&msg);
	srv_free(&lchan);
}

static void srv_process_names(struct server *srv, struct db_client *cli, struct command *c)
{
	struct db_channel chan;
	struct db_membership m;
	char *lchan;
	int all;
	int i;

	const char *target;

	target = c->args.cmd_names_list.target;
	if (strlen(target) > 0 && strcmp(target, srv->config.server_name) != 0) {
		srv_send_error_nosuchserver(srv, cli, target);
		return;
	}

	if (c->args.cmd_names_list.num_channels == 0) {
		srv_send_error_toomanymatches(srv, cli, "*");
		return;
	}

	lchan = srv_malloc_msg();
	for (i = 0; i < c->args.cmd_names_list.num_channels; ++i) {
		strcpy(lchan, c->args.cmd_names_list.channels[i]);
		irclower(lchan);

		if (db_get_channel_by_name(srv->db, lchan, &chan) == 0 && !chan.secret_flag) {
			/* Channel appears to exist. */
			all = (cli->operator_flag || cli->local_operator_flag ||
			       db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) == 0);
			srv_process_one_names(srv, cli, &chan, all);
		} else
			srv_send_reply_endofnames(srv, cli, c->args.cmd_names_list.channels[i]);
	}
	srv_free(&lchan);
}

static void srv_process_list(struct server *srv, struct db_client *cli, struct command *c)
{
	char lchan[CHANNEL_BUFFER_SIZE];
	struct db_channel chan;

	const char *server;
	int i;
	
	if (c->args.cmd_names_list.num_channels == 0) {
		srv_send_error_toomanymatches(srv, cli, "*");
		return;
	}

	server = c->args.cmd_names_list.target;
	if (server[0] != '\0' && strcmp(server, srv->config.server_name) != 0) {
		srv_send_error_nosuchserver(srv, cli, server);
		return;
	}

	for (i = 0; i < c->args.cmd_names_list.num_channels; ++i) {
		strcpy(lchan, c->args.cmd_names_list.channels[i]);
		irclower(lchan);

		if (db_get_channel_by_name(srv->db, lchan, &chan) != 0 || chan.secret_flag)
			continue;

		srv_fmt_enq(srv, cli, ":%s %03d %s %s %d :%s\r\n",
			    srv->config.server_name, RPL_LIST, srv_dest_nick(cli),
			    chan.orig_name,
			    db_count_visible_members(srv->db, chan.id_channel),
			    chan.topic);
	}

	srv_fmt_enq(srv, cli, ":%s %03d %s :End of LIST\r\n",
		    srv->config.server_name, RPL_LISTEND, srv_dest_nick(cli));
}

static void srv_process_one_part(struct server *srv, struct db_client *cli, const char *cname, const char *reason)
{
	char lchan[CHANNEL_BUFFER_SIZE];

	struct db_channel chan;
	struct db_membership m;

	char *msg;
	int len;
	struct srv_enqueue_cb_args args;

	strcpy(lchan, cname);
	irclower(lchan);

	if (db_get_channel_by_name(srv->db, lchan, &chan) != 0) {
		srv_send_error_nosuchchannel(srv, cli, cname);
		return;
	}

	if (db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) != 0) {
		srv_send_error_notonchannel(srv, cli, chan.orig_name);
		return;
	}

	assert(db_delete_membership(srv->db, chan.id_channel, cli->id_client) == 0);
	msg = srv_malloc_msg();

	/* Log channel part. */
	snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld leaves channel %s",
		 (long long)(cli->id_client), chan.name);
	srv_log(srv, msg);

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s PART %s :%s\r\n",
		      cli->orig_fullname, chan.orig_name, reason);
	srv_enqueue_client_data(srv, cli, msg, len);

	/* Do not send PART messages to quiet channels. */
	if (! chan.quiet_flag) {
		args.srv = srv;
		args.msg = msg;
		args.len = len;
		assert(db_run_on_members(srv->db, chan.id_channel, srv_enqueue_cb, &args) == 0);
	}

	srv_free(&msg);
}

static void srv_process_part(struct server *srv, struct db_client *cli, struct command *c)
{
	int i;

	for (i = 0; i < c->args.cmd_part.num_channels; ++i) {
		srv_process_one_part(srv, cli, c->args.cmd_part.channels[i],
				     (c->args.cmd_part.message[0] == '\0')?
				     cli->orig_nickname:c->args.cmd_part.message);
	}
}

static void srv_process_one_kick(struct server *srv, struct db_client *cli, const char *n, const char *c, const char *r)
{
	char *msg;
	int len;

	struct db_channel chan;
	struct db_membership m;
	struct db_membership aux;
	struct db_client kicked;
	struct srv_enqueue_cb_args args;

	char lchan[CHANNEL_BUFFER_SIZE];
	char lnick[NICKNAME_BUFFER_SIZE];

	strcpy(lchan, c);
	irclower(lchan);

	if (db_get_channel_by_name(srv->db, lchan, &chan) != 0) {
		srv_send_error_nosuchchannel(srv, cli, c);
		return;
	}

	if (db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) != 0) {
		srv_send_error_notonchannel(srv, cli, c);
		return;
	}

	if (! m.operator_flag) {
		srv_send_error_chanoprivsneeded(srv, cli, c);
		return;
	}

	strcpy(lnick, n);
	irclower(lnick);

	if (db_get_client_by_nick(srv->db, lnick, &kicked) != 0
	    || db_get_membership(srv->db, chan.id_channel, kicked.id_client, &aux) != 0) {
		srv_send_error_usernotinchannel(srv, cli, n, c);
		return;
	}

	msg = srv_malloc_msg();

	/* Log kick. */
	srv_fmt(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld kicked CLID_%lld out of %s",
		(long long)(cli->id_client), (long long)(kicked.id_client), chan.name);
	srv_log(srv, msg);

	len = srv_fmt(msg, MESSAGE_BUFFER_SIZE, ":%s KICK %s %s :%s\r\n",
		      cli->orig_fullname, chan.orig_name, kicked.orig_nickname,
		      (strlen(r) == 0)?cli->orig_nickname:r);

	args.srv = srv;
	args.msg = msg;
	args.len = len;
	assert(db_run_on_members(srv->db, chan.id_channel, srv_enqueue_cb, &args) == 0);
	assert(db_delete_membership(srv->db, chan.id_channel, kicked.id_client) == 0);

	srv_free(&msg);
}

static void srv_process_kick(struct server *srv, struct db_client *cli, struct command *c)
{
	int i, j;
	int chan_delta;

	chan_delta = (c->args.cmd_kick.num_channels == 1)?0:1;

	for (i = 0, j = 0; i < c->args.cmd_kick.num_nicknames; ++i, j += chan_delta)
		srv_process_one_kick(srv, cli,
				     c->args.cmd_kick.nicknames[i],
				     c->args.cmd_kick.channels[j],
				     c->args.cmd_kick.comment);
}

static void srv_process_invite(struct server *srv, struct db_client *cli, struct command *c)
{
	struct db_client guest;
	struct db_channel chan;
	struct db_membership m;
	struct db_membership aux;
	struct db_invite in;

	char lnick[NICKNAME_BUFFER_SIZE];
	char lchan[CHANNEL_BUFFER_SIZE];

	strcpy(lnick, c->args.cmd_invite.nickname);
	irclower(lnick);

	if (db_get_client_by_nick(srv->db, lnick, &guest) != 0) {
		srv_send_error_nosuchnick(srv, cli, c->args.cmd_invite.nickname);
		return;
	}

	strcpy(lchan, c->args.cmd_invite.channel);
	irclower(lchan);

	if (db_get_channel_by_name(srv->db, lchan, &chan) == 0) {
		if (db_get_membership(srv->db, chan.id_channel, guest.id_client, &aux) == 0) {
			srv_send_error_useronchannel(srv, cli, c->args.cmd_invite.nickname, c->args.cmd_invite.channel);
			return;
		}

		if (db_get_membership(srv->db, chan.id_channel, cli->id_client, &m) != 0) {
			srv_send_error_notonchannel(srv, cli, c->args.cmd_invite.channel);
			return;
		}

		if (chan.invite_only_flag && ! m.operator_flag) {
			srv_send_error_chanoprivsneeded(srv, cli, c->args.cmd_invite.channel);
			return;
		}

		if (m.operator_flag && db_get_invite(srv->db, chan.id_channel, guest.id_client, &in) != 0) {
			/* Save invitation in database. */
			assert(db_invite_client(srv->db, chan.id_channel, guest.id_client) == 0);
		}
	}

	srv_send_reply_inviting(srv, cli, c->args.cmd_invite.channel, c->args.cmd_invite.nickname);
	if (guest.away_flag)
		srv_send_reply_away(srv, cli, c->args.cmd_invite.nickname, guest.away_text);

	srv_fmt_enq(srv, &guest, ":%s INVITE %s %s\r\n",
		    cli->orig_fullname, c->args.cmd_invite.nickname, c->args.cmd_invite.channel);
}

static void srv_process_die(struct server *srv, struct db_client *cli)
{
	if (! (cli->operator_flag || cli->local_operator_flag)) {
		srv_send_error_noprivileges(srv, cli);
		return;
	}

	srv->dyndata.die_flag = 1;
}

static void srv_process_cmd(struct server *srv, struct db_client *cli, struct command *c)
{
	/*
	 * Relative order in command groups tries to observe a real-world
	 * scenario, with the most frequently used commands first.
	 */

	switch (c->number) {
	case CMD_NICK:
		srv_process_nick(srv, cli, c);
		return;
	case CMD_QUIT:
		srv_process_quit(srv, cli, c);
		return;
	case CMD_PING:
		srv_process_ping(srv, cli, c);
		return;
	case CMD_PONG:
		srv_process_pong(cli);
		return;
	case CMD_USER:
		srv_process_user(srv, cli, c);
		return;
	case CMD_PASS:
		/* PASS command is conveniently ignored for now. */
		return;
	case CMD_SERVICE:
		srv_process_service(srv, cli, c);
		return;
	}

	if ((cli->regstate & REGSTATE_NICK) == 0 ||
	    (cli->regstate & REGSTATE_USER) == 0) {
		srv_send_error_notregistered(srv, cli);
		return;
	}

	switch (c->number) {
	case CMD_PRIVMSG:
		srv_process_privmsg(srv, cli, c);
		return;
	case CMD_JOIN:
		srv_process_join(srv, cli, c);
		return;
	case CMD_NOTICE:
		srv_process_notice(srv, cli, c);
		return;
	case CMD_MODE:
		srv_process_mode(srv, cli, c);
		return;
	case CMD_PART:
		srv_process_part(srv, cli, c);
		return;
	case CMD_WHOIS:
		srv_process_whois(srv, cli, c);
		return;
	case CMD_WHO:
		srv_process_who(srv, cli, c);
		return;
	case CMD_KICK:
		srv_process_kick(srv, cli, c);
		return;
	case CMD_TOPIC:
		srv_process_topic(srv, cli, c);
		return;
	case CMD_ISON:
		srv_process_ison(srv, cli, c);
		return;
	case CMD_AWAY:
		srv_process_away(srv, cli, c);
		return;
	case CMD_LUSERS:
		srv_process_lusers(srv, cli);
		return;
	case CMD_USERHOST:
		srv_process_userhost(srv, cli, c);
		return;
	case CMD_INVITE:
		srv_process_invite(srv, cli, c);
		return;
	case CMD_WHOWAS:
		srv_process_whowas(srv, cli, c);
		return;
	case CMD_LIST:
		srv_process_list(srv, cli, c);
		return;
	case CMD_NAMES:
		srv_process_names(srv, cli, c);
		return;
	case CMD_KILL:
		srv_process_kill(srv, cli, c);
		return;
	case CMD_TIME:
		srv_process_time(srv, cli, c);
		return;
	case CMD_LINKS:
		srv_process_links(srv, cli, c);
		return;
	case CMD_MOTD:
		srv_process_motd(srv, cli);
		return;
	case CMD_ADMIN:
		srv_process_admin(srv, cli, c);
		return;
	case CMD_INFO:
		srv_process_info(srv, cli, c);
		return;
	case CMD_VERSION:
		srv_process_version(srv, cli, c);
		return;
	case CMD_OPER:
		srv_process_oper(srv, cli, c);
		return;
	case CMD_STATS:
		srv_process_stats(srv, cli, c);
		return;
	case CMD_USERS:
		srv_send_error_usersdisabled(srv, cli);
		return;
	case CMD_TRACE:
		srv_process_trace(srv, cli, c);
		return;
	case CMD_SERVLIST:
		srv_send_reply_servlistend(srv, cli, c->args.cmd_servlist.mask, c->args.cmd_servlist.type);
		return;
	case CMD_SQUERY:
		srv_send_error_nosuchservice(srv, cli, c->args.cmd_squery.servicename);
		return;
	case CMD_SUMMON:
		srv_send_error_summondisabled(srv, cli);
		return;
	case CMD_WALLOPS:
		/* WALLOPS from clients must be ignored. */
		return;
	case CMD_ERROR:
		/* ERROR from clients must be ignored. */
		return;
	case CMD_DIE:
		srv_process_die(srv, cli);
		return;
	}

	/* The following commands are not implemented:
	 *
	 * CMD_REHASH 
	 * CMD_RESTART
	 * CMD_CONNECT
	 * CMD_SQUIT
	 */

	srv_send_error(srv, cli, "Command not implemented");
}

static void srv_process_error(struct server *srv, struct db_client *cli, struct command *c, struct tokens *t, int pret)
{
	int cmd_tok;

	if (pret == ERR_UNKNOWNCOMMAND) {
		if (t->token[0][0] == ':')
			cmd_tok = 1;
		else
			cmd_tok = 0;
		srv_send_error_unknowncommand(srv, cli, t->token[cmd_tok]);
		return;
	}

	switch (c->number) {
	case CMD_NICK:
		if (pret == ERR_NONICKNAMEGIVEN)
			srv_send_error_nonicknamegiven(srv, cli);
		else if (pret == ERR_ERRONEUSNICKNAME)
			srv_send_error_erroneusnickname(srv, cli, c->args.cmd_nick.nickname);
		return;
	case CMD_PING:
	case CMD_PONG:
		if (pret == ERR_NOORIGIN)
			srv_send_error_noorigin(srv, cli);
		return;
	case CMD_USER:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "USER");
		return;
	case CMD_PASS:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "PASS");
		return;
	case CMD_SERVICE:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "SERVICE");
		return;
	}

	if ((cli->regstate & REGSTATE_NICK) == 0 ||
	    (cli->regstate & REGSTATE_USER) == 0) {
		srv_send_error_notregistered(srv, cli);
		return;
	}

	switch (c->number) {
		/* The following commands have no parsing errors:
		 *
		 * CMD_QUIT
		 * CMD_LUSERS
		 * CMD_MOTD
		 * CMD_WHO
		 * CMD_AWAY
		 * CMD_REHASH
		 * CMD_DIE
		 * CMD_RESTART
		 * CMD_CONNECT
		 * CMD_USERS
		 * CMD_VERSION
		 * CMD_LINKS
		 * CMD_TIME
		 * CMD_TRACE
		 * CMD_ADMIN
		 * CMD_INFO
		 * CMD_SERVLIST
		 * CMD_STATS
		 * CMD_NAMES
		 * CMD_LIST
		 * CMD_PART
		 */
	case CMD_PRIVMSG:
		if (pret == ERR_NORECIPIENT)
			srv_send_error_norecipient(srv, cli, "PRIVMSG");
		else if (pret == ERR_NOTEXTTOSEND)
			srv_send_error_notexttosend(srv, cli);
		return;
	case CMD_JOIN:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "JOIN");
		return;
	case CMD_NOTICE:
		/* According to the RFC, no error replies should be sent. */
		return;
	case CMD_MODE:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "MODE");
		else if (pret == ERR_UMODEUNKNOWNFLAG) {
			srv_send_error_umodeunknownflag(srv, cli);
			/*
			 * Even if UMODEUNKNOWNFLAG was returned, process the
			 * command, employing a "best effort" strategy.
			 */
			srv_process_mode(srv, cli, c);
		}
		return;
	case CMD_WHOIS:
		if (pret == ERR_NONICKNAMEGIVEN)
			srv_send_error_nonicknamegiven(srv, cli);
		return;
	case CMD_KICK:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "KICK");
		return;
	case CMD_TOPIC:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "TOPIC");
		return;
	case CMD_ISON:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "ISON");
		return;
	case CMD_USERHOST:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "USERHOST");
		return;
	case CMD_INVITE:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "INVITE");
		return;
	case CMD_WHOWAS:
		if (pret == ERR_NONICKNAMEGIVEN)
			srv_send_error_nonicknamegiven(srv, cli);
		return;
	case CMD_KILL:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "KILL");
		return;
	case CMD_SQUERY:
		if (pret == ERR_NORECIPIENT)
			srv_send_error_norecipient(srv, cli, "SQUERY");
		else if (pret == ERR_NOTEXTTOSEND)
			srv_send_error_notexttosend(srv, cli);
		return;
	case CMD_SUMMON:
		srv_send_error_summondisabled(srv, cli);
		return;
	case CMD_WALLOPS:
		/* WALLOPS from clients must be ignored. */
		return;
	case CMD_ERROR:
		/* ERROR from clients must be ignored. */
		return;
	case CMD_OPER:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "OPER");
		return;
	case CMD_SQUIT:
		if (pret == ERR_NEEDMOREPARAMS)
			srv_send_error_needmoreparams(srv, cli, "SQUIT");
		return;
	default:
		break;
	}

}

static void srv_reader_cb(int fd, const char *msg, int msglen, void *srv_)
{
	static struct tokens t;
	static struct command c;
	struct db_client cli;
	struct server *srv;
	char *message = srv_malloc_msg();
	int ret;

	srv = srv_;

	/* This should never happen anyway. */
	if (msglen <= 0 || msglen > MAX_MESSAGE_LEN)
		goto out;
	
	memcpy(message, msg, msglen);
	message[msglen] = '\0';

	init_tokens(&t);
	if (tokenize(message, &t) <= 0)
		/* Erroneous message by lexer. */
		goto out;

	init_command(&c);
	ret = parse_tokens(&t, &c);
	if (ret < 0)
		/* Erroneous message by parser. */
		goto out;

	/* Increase STATS counters. */
	if (c.number >= CMD_BASE_NUMBER && c.number < CMD_TOP_NUMBER) {
		srv->dyndata.cmd_counters[c.number - CMD_BASE_NUMBER].number += 1;
		srv->dyndata.cmd_counters[c.number - CMD_BASE_NUMBER].bytes += msglen;
	}

	/* If data was read from the file descriptor, the client MUST exist. */
	assert(db_get_client_by_fd(srv->db, fd, &cli) == 0);

	/* Process command. */
	if (ret == 0)
		srv_process_cmd(srv, &cli, &c);
	else
		srv_process_error(srv, &cli, &c, &t, ret);

	/* Update activity for idle time. */
	if (c.number == CMD_PRIVMSG || c.number == CMD_NOTICE)
		cli.last_talk = time(NULL);

	/* Penalize client. */
	cli.last_activity += CLIENT_PENALIZATION;
	assert(db_modify_client(srv->db, &cli) == 0);

out:
	srv_free(&message);
}

void srv_init(struct server *srv, const struct server_config *config)
{
	FILE *opers;
	int i;
	int ret;
	int zero_len_address;

	/* Put dummy values on anything that needs to be freed. */
	srv->clients.array = NULL;
	srv->pollfds.array = NULL;
	srv->db = NULL;
	srv->listen_socket.fd = -1;
	srv->listen_socket.is_ipv6 = 0;

	/* Configuration data. */
	memcpy(&(srv->config), config, sizeof(struct server_config));

	/* Dymamic data. */
	srv->dyndata.start_time = time(NULL);
	memset(srv->dyndata.cmd_counters, 0, sizeof(srv->dyndata.cmd_counters));
	srv->dyndata.die_flag = 0;

	/* Client array. */
	srv->clients.array = malloc(srv->config.max_clients * sizeof(struct server_client));

	if (srv->clients.array == NULL) {
		fprintf(stderr, "ERROR: allocation error for clients array\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < srv->config.max_clients; ++i) {
		srv->clients.array[i].input.data = NULL;
		srv->clients.array[i].output.data = NULL;
	}

	srv->clients.next_free = 0;
	for (i = 0; i < srv->config.max_clients; ++i) {
		srv->clients.array[i].fd = -1;

		if (buffer_create(&(srv->clients.array[i].input), MAX_MESSAGE_LEN) != 0 ||
		    buffer_create(&(srv->clients.array[i].output), srv->config.output_buffer_size) != 0) {
			fprintf(stderr, "ERROR: allocation error for client buffers\n");
			exit(EXIT_FAILURE);
		}

		reader_init(&(srv->clients.array[i].reader), &(srv->clients.array[i].fd),
			    srv_reader_cb, &(srv->clients.array[i].input));
		srv->clients.array[i].next_free = i+1;
	}
	srv->clients.array[srv->config.max_clients - 1].next_free = -1;

	/* pollfd array. */
	srv->pollfds.array = malloc((srv->config.max_clients + 1) * sizeof(struct pollfd));

	if (srv->pollfds.array == NULL) {
		fprintf(stderr, "ERROR: allocation error for pollfd array\n");
		exit(EXIT_FAILURE);
	}

	srv->pollfds.used = 0;

	/* Database connection. */
	srv->db = db_create();
	if (srv->db == NULL) {
		fprintf(stderr, "ERROR: unable to create server database\n");
		exit(EXIT_FAILURE);
	}

	/* Logging channel. */
	assert(db_get_channel_by_name(srv->db, "#log", &(srv->dyndata.logchan)) == 0);

	/* Listening socket. */
	zero_len_address = (strlen(srv->config.address) == 0);
	ret = get_listen_socket(zero_len_address?NULL:srv->config.address,
				srv->config.port,
				&(srv->listen_socket.fd),
				&(srv->listen_socket.is_ipv6));

	if (ret == -1) {
		if (zero_len_address)
			fprintf(stderr, "ERROR: unable to listen on port %d\n", srv->config.port);
		else
			fprintf(stderr, "ERROR: unable to listen on address %s and port %d\n",
				srv->config.address, srv->config.port);
		exit(EXIT_FAILURE);
	}
	assert(nonblock(srv->listen_socket.fd) == 0);

	/* Operators database. */
	if (strlen(srv->config.operators_filename) > 0) {
		opers = fopen(srv->config.operators_filename, "r");
		assert(opers != NULL);
		srv_load_operators(opers, srv->db);
		fclose(opers);
	}
}

void srv_destroy(struct server *srv)
{
	int i;

	if (srv->clients.array != NULL) {
		for (i = 0; i < srv->config.max_clients; ++i) {
			buffer_destroy(&(srv->clients.array[i].input));
			buffer_destroy(&(srv->clients.array[i].output));

			if (srv->clients.array[i].fd >= 0)
				close_noeintr(srv->clients.array[i].fd);
		}

		free(srv->clients.array);
		srv->clients.array = NULL;
	}

	if (srv->pollfds.array != NULL) {
		free(srv->pollfds.array);
		srv->pollfds.array = NULL;
	}

	if (srv->db != NULL) {
		db_close(srv->db);
		srv->db = NULL;
	}

	if (srv->listen_socket.fd != -1) {
		close_noeintr(srv->listen_socket.fd);
		srv->listen_socket.fd = -1;
	}
}

static int srv_full(const struct server *srv)
{
	return (srv->clients.next_free < 0);
}

static int srv_get_client_slot(struct server *srv)
{
	int ret;

	if (srv_full(srv))
		return -1;

	ret = srv->clients.next_free;
	srv->clients.next_free = srv->clients.array[ret].next_free;
	srv->clients.array[ret].next_free = -1;
	return ret;
}

static void srv_free_client_slot(struct server *srv, int cli)
{
	srv_clear_client_slot(&(srv->clients.array[cli]));
	srv->clients.array[cli].next_free = srv->clients.next_free;
	srv->clients.next_free = cli;
}

static void srv_clear_client_slot(struct server_client *srvcli)
{
	srvcli->fd = -1;
	assert(buffer_consume(&(srvcli->input), -1) == 0);
	assert(buffer_consume(&(srvcli->output), -1) == 0);
	srvcli->reader.state = RS_NORMAL;
}

static void srv_disconnect_client(struct server *srv, struct db_client *cli)
{
	assert(close_noeintr(cli->fd) == 0);
	srv_free_client_slot(srv, cli->array_index);
	assert(db_del_client(srv->db, cli) == 0);
}

static void srv_enqueue_cb(void *cli_, void *args_)
{
	struct db_client *cli;
	struct srv_enqueue_cb_args *args;

	cli = cli_;
	args = args_;

	srv_enqueue_client_data(args->srv, cli, args->msg, args->len);
}

static void srv_anon_neighbor_cb(void *cc_, void *args_)
{
	struct db_client_channel *cc;
	struct srv_anon_neighbor_cb_args *args;

	cc = cc_;
	args = args_;

	srv_fmt_enq(args->srv, &(cc->client), ":%s PART %s\r\n", args->cli->orig_fullname, cc->channel.orig_name);
}

static void srv_client_quit(struct server *srv, struct db_client *cli, const char *reason)
{
	int len;
	char *quit_msg = srv_malloc_msg();
	struct srv_enqueue_cb_args cb_args;
	struct srv_anon_neighbor_cb_args anon_args;

	len = srv_fmt(quit_msg, MESSAGE_BUFFER_SIZE, ":%s QUIT :%s\r\n", cli->orig_fullname, reason);

	/* Compose callback arguments. */
	cb_args.srv = srv;
	cb_args.msg = quit_msg;
	cb_args.len = len;

	anon_args.srv = srv;
	anon_args.cli = cli;

	/*
	 * Mark client as about to quit. This prevents creating a recursive
	 * loop when messaging the client neighbors if they, in turn, are
	 * disconnected by filling their output buffer.
	 */
	cli->is_quitting = 1;
	db_modify_client(srv->db, cli);

	/* Run callbacks and disconnect client. */
	db_run_on_anon_neighbors(srv->db, cli->id_client, srv_anon_neighbor_cb, &anon_args);
	db_run_on_non_anon_neighbors(srv->db, cli->id_client, srv_enqueue_cb, &cb_args);

	/* Log disconnection. */
	snprintf(quit_msg, MESSAGE_BUFFER_SIZE, "CLID_%lld disconnected", (long long)(cli->id_client));
	srv_log(srv, quit_msg);

	srv_disconnect_client(srv, cli);
	srv_free(&quit_msg);
}

static void srv_enqueue_client_data(struct server *srv, struct db_client *cli, const char *in, int len)
{
	struct buffer *b;

	/*
	 * This function may be used from callbacks or loops many times in a
	 * row and a previous call may have disconnected the client, so do
	 * nothing if we detect the client slot has already been freed.
	 */
	if (srv->clients.array[cli->array_index].fd < 0)
		return;

	b = &(srv->clients.array[cli->array_index].output);

	/* Attempt to append data to client output buffer. */
	if (buffer_append(b, in, len) != 0)
		/* Appending failed. */
		srv_client_quit(srv, cli, "SendQ exceeded");
}

static void srv_ping_timeout_cb(void *cli_, void *srv_)
{
	struct db_client *cli;
	struct server *srv;

	cli = cli_;
	srv = srv_;

	srv_client_quit(srv, cli, "Ping timeout");
}

static void srv_make_new_client(struct db_client *cli, int slot, int fd, const char *ip, int port)
{
	memset(cli, 0, sizeof(struct db_client));
	cli->array_index = slot;
	cli->fd = fd;
	strcpy(cli->ip, ip);
	cli->port = port;
	cli->last_activity = time(NULL);
	cli->last_talk = cli->last_activity;
	cli->signon_time = cli->last_activity;
}

static void srv_poll_sockets(struct server *srv)
{
	struct db_client cli;
	struct buffer *b;
	int ret;
	ssize_t wret;
	int i;

	/* Prepare pollfds array. */
	srv->pollfds.array[0].fd = srv->listen_socket.fd;
	srv->pollfds.array[0].events = POLLIN | POLLPRI;
	srv->pollfds.array[0].revents = 0;
	srv->pollfds.used = 1;

	assert(db_run_on_clients(srv->db, srv_poll_cb, srv) == 0);

	/* Wait no more than one second. */
	while ((ret = poll(srv->pollfds.array, srv->pollfds.used, 1000)) == -1 && errno == EINTR)
		;
	assert(ret >= 0);

	/* Check listening socket. */
	assert(! (srv->pollfds.array[0].revents & POLLNVAL));
	assert(! (srv->pollfds.array[0].revents & POLLHUP));
	assert(! (srv->pollfds.array[0].revents & POLLERR));
	if ((srv->pollfds.array[0].revents & POLLIN) || (srv->pollfds.array[0].revents & POLLPRI))
		srv_accept_new_clients(srv);

	/* Check individual clients. */
	for (i = 1; i < srv->pollfds.used; ++i) {
		assert((srv->pollfds.array[i].revents & POLLNVAL) == 0);

		if (db_get_client_by_fd(srv->db, srv->pollfds.array[i].fd, &cli) != 0)
			/* The client vanished already. */
			continue;

		/* Hang-up. */
		if ((srv->pollfds.array[i].revents & POLLHUP) != 0) {
			srv_client_quit(srv, &cli, "Poll error: hang up");
			continue;
		}

		/* Generic error condition. */
		if ((srv->pollfds.array[i].revents & POLLERR) != 0) {
			srv_client_quit(srv, &cli, "Poll error: exceptional error");
			continue;
		}

		/* Write attempt. */
		b = &(srv->clients.array[cli.array_index].output);
		if ((srv->pollfds.array[i].revents & POLLOUT) && b->used > 0) {
			while ((wret = write(cli.fd, b->data, b->used)) == -1 && errno == EINTR)
				;
			if (wret >= 0) {
				buffer_consume(b, wret);
			} else {
				/* Possible errors:
				 *	EAGAIN and EWOULDBLOCK (fine).
				 *	EBADF (fine, client vanished).
				 *	EDESTADDRREQ (bad).
				 *	EFAULT (bad).
				 *	EFBIG (bad).
				 *	EINTR (should not happen, but fine).
				 *	EINVAL (bad).
				 *	EIO (bad).
				 *	ENOSPC (bad).
				 *	EPIPE (bad).
				 *	...
				 *	Others (bad).
				 */
				if (errno != EAGAIN &&
				    errno != EWOULDBLOCK &&
				    errno != EBADF &&
				    errno != EINTR) {
					srv_client_quit(srv, &cli, "Write error, closing link");
					continue;
				}
			}
		}

		/* Read attempt. */
		if ((srv->pollfds.array[i].revents & POLLIN) || (srv->pollfds.array[i].revents & POLLPRI)) {
			assert(db_update_client_activity(srv->db, cli.id_client) == 0);

			/* The following call may trigger srv_reader_cb(). */
			ret = read_and_callback(&(srv->clients.array[cli.array_index].reader), srv);

			if (ret == 0)
				srv_client_quit(srv, &cli, "Read error: EOF from client");
			else if (ret == -1) {
				/*
				 * Possible errors:
				 *	EAGAIN and EWOULDBLOCK (fine).
				 *	EBADF (fine, client vanished).
				 *	EFAULT (bad).
				 *	EINTR (should not happen, but fine).
				 *	EINVAL (bad).
				 *	EIO (bad).
				 *	EISDIR (bad).
				 */
				assert(errno != EFAULT);
				assert(errno != EINVAL);
				assert(errno != EIO);
				assert(errno != EISDIR);
			}
			/* Otherwise, it was a normal read. */
		}
	}
}

static void srv_accept_new_clients(struct server *srv)
{
	char *msg = srv_malloc_msg();
	char *ipstr = srv_malloc_msg();
	struct db_client cli;
	socklen_t addrlen;
	int fd;
	int slot;
	int port;

	for (;;) {
		fd = accept(srv->listen_socket.fd, NULL, NULL);

		if (fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;

		if (srv_full(srv)) {
			assert(close_noeintr(fd) == 0);
			continue;
		}

		/* Get and fill client slot. */
		slot = srv_get_client_slot(srv);
		assert(slot >= 0);
		srv_clear_client_slot(&(srv->clients.array[slot]));
		srv->clients.array[slot].fd = fd;

		/* Make file descriptor non-blocking. */
		assert(nonblock(fd) == 0);

		/* Convert client address. */
		if (srv->listen_socket.is_ipv6) {
			struct sockaddr_in6 addr;
			addrlen = sizeof(addr);
			assert(getpeername(fd, (struct sockaddr *)(&addr), &addrlen) == 0);
			assert(inet_ntop(addr.sin6_family, &(addr.sin6_addr), ipstr, MESSAGE_BUFFER_SIZE) != NULL);
			port = (int)ntohs(addr.sin6_port);
		} else {
			struct sockaddr_in addr;
			addrlen = sizeof(addr);
			assert(getpeername(fd, (struct sockaddr *)(&addr), &addrlen) == 0);
			assert(inet_ntop(addr.sin_family, &(addr.sin_addr), ipstr, MESSAGE_BUFFER_SIZE) != NULL);
			port = (int)ntohs(addr.sin_port);
		}

		/* Fill initial client data and add it to the database. */
		srv_make_new_client(&cli, slot, fd, ipstr, port);
		assert(db_add_client(srv->db, &cli) == 0);

		/* Log new connection. */
		snprintf(msg, MESSAGE_BUFFER_SIZE, "CLID_%lld %s:%d connected on file descriptor %d",
			 (long long)(cli.id_client), ipstr, port, fd);
		srv_log(srv, msg);
	}

	srv_free(&msg);
	srv_free(&ipstr);
}

static void srv_poll_cb(void *cli_, void *srv_)
{
	struct db_client *cli;
	struct server *srv;
	short events;

	cli = cli_;
	srv = srv_;

	srv->pollfds.array[srv->pollfds.used].fd = cli->fd;
	events = 0;
	if (srv->clients.array[cli->array_index].output.used > 0)
		events |= POLLOUT;
	if (cli->last_activity <= time(NULL)) {
		events |= POLLIN;
		events |= POLLPRI;
	}
	srv->pollfds.array[srv->pollfds.used].events = events;
	srv->pollfds.array[srv->pollfds.used].revents = 0;
	srv->pollfds.used += 1;
}

static void srv_inactive_cb(void *cli_, void *srv_)
{
	struct server *srv;
	struct db_client *cli;

	cli = cli_;
	srv = srv_;

	assert(db_update_client_ping(srv->db, cli->id_client) == 0);
	srv_fmt_enq(srv, cli, "PING %s\r\n", srv->config.server_name);
}

static void srv_db_maintenance(struct server *srv)
{
	assert(db_clear_whowas(srv->db, srv->config.whowas_timeout_seconds) == 0);
	assert(db_del_expired_forbidden_nicks(srv->db) == 0);
}

void srv_main_loop(struct server *srv)
{
	while (! srv->dyndata.die_flag) {

		/* Disconnect clients due to PING timeout. */
		assert(db_run_on_ping_timeout_clients(srv->db, srv->config.timeout_seconds, srv_ping_timeout_cb, srv) == 0);

		/* Enqueue pings to inactive clients. */
		assert(db_run_on_inactive_clients(srv->db, srv->config.timeout_seconds, srv_inactive_cb, srv) == 0);

		/* Poll sockets. */
		srv_poll_sockets(srv);

		/* Clean expired DB entries. */
		srv_db_maintenance(srv);
	}
}

static int srv_cfg_parse_int(const char *str)
{
	char *endptr;
	long result;

	result = strtol(str, &endptr, 10);
	if (endptr != str + strlen(str))
		return INT_MIN;
	if (result < INT_MIN || result > INT_MAX)
		return INT_MIN;
	return (int)result;
}

static int srv_cfg_verify_server_name(const char *value)
{
	const char *i;

	if (strlen(value) < MIN_SERVER_NAME_LENGTH ||
	    strlen(value) > MAX_SERVER_NAME_LENGTH)
		return 0;

	/* Equivalent regular expression: [a-zA-Z0-9\._-]+ */
	for (i = value; *i != '\0'; ++i) {
		if (! ((*i >= 'a' && *i <= 'z') ||
		       (*i >= 'A' && *i <= 'Z') ||
		       (*i >= '0' && *i <= '9') ||
		       *i == '.' || *i == '-' || *i == '_'))
			return 0;
	}

	return 1;
}

static int srv_cfg_verify_phrase(const char *value)
{
	const char *i;

	if (strlen(value) > MAX_PHRASE_LENGTH)
		return 0;

	for (i = value; *i != '\0'; ++i) {
		if (*i == '\r' || *i == '\n')
			return 0;
	}

	return 1;
}

static int srv_cfg_parse_key_value(const char *key, const char *value, struct server_config *cfg)
{
	const char *errmsg;
	struct sockaddr_in s;

	if (strcmp(key, "server_name") == 0) {
		if (! srv_cfg_verify_server_name(value)) {
		    fprintf(stderr, "ERROR: invalid value for server_name\n");
		    return -1;
		}
		strcpy(cfg->server_name, value);
	} else if (strcmp(key, "motd") == 0) {
		if (! srv_cfg_verify_phrase(value)) {
			fprintf(stderr, "ERROR: invalid value for motd\n");
			return -1;
		}
		strcpy(cfg->motd, value);
	} else if (strcmp(key, "location") == 0) {
		if (! srv_cfg_verify_phrase(value)) {
			fprintf(stderr, "ERROR: invalid value for location\n");
			return -1;
		}
		strcpy(cfg->location, value);
	} else if (strcmp(key, "entity") == 0) {
		if (! srv_cfg_verify_phrase(value)) {
			fprintf(stderr, "ERROR: invalid value for entity\n");
			return -1;
		}
		strcpy(cfg->entity, value);
	} else if (strcmp(key, "email") == 0) {
		if (! srv_cfg_verify_phrase(value)) {
			fprintf(stderr, "ERROR: invalid value for email\n");
			return -1;
		}
		strcpy(cfg->email, value);
	} else if (strcmp(key, "max_clients") == 0) {
		cfg->max_clients = srv_cfg_parse_int(value);
		if (cfg->max_clients < MIN_CLIENTS) {
			fprintf(stderr, "ERROR: invalid value for max_clients\n");
			return -1;
		}
	} else if (strcmp(key, "max_channels") == 0) {
		cfg->max_channels = srv_cfg_parse_int(value);
		if (cfg->max_channels < MIN_CHANNELS) {
			fprintf(stderr, "ERROR: invalid value for max_channels\n");
			return -1;
		}
	} else if (strcmp(key, "max_client_channels") == 0) {
		cfg->max_client_channels = srv_cfg_parse_int(value);
	} else if (strcmp(key, "max_channel_members") == 0) {
		cfg->max_channel_members = srv_cfg_parse_int(value);
	} else if (strcmp(key, "max_bans") == 0) {
		cfg->max_bans = srv_cfg_parse_int(value);
	} else if (strcmp(key, "max_exceptions") == 0) {
		cfg->max_excepts = srv_cfg_parse_int(value);
	} else if (strcmp(key, "max_invitations") == 0) {
		cfg->max_invites = srv_cfg_parse_int(value);
	} else if (strcmp(key, "port") == 0) {
		cfg->port = srv_cfg_parse_int(value);
		if (cfg->port < MIN_PORT || cfg->port > MAX_PORT) {
			fprintf(stderr, "ERROR: invalid value for port\n");
			return -1;
		}
	} else if (strcmp(key, "address") == 0) {
		if (! inet_pton(AF_INET, value, &(s.sin_addr))) {
			fprintf(stderr, "ERROR: invalid value for address\n");
			return -1;
		}
		strcpy(cfg->address, value);
	} else if (strcmp(key, "timeout_seconds") == 0) {
		cfg->timeout_seconds = srv_cfg_parse_int(value);
		if (cfg->timeout_seconds < MIN_TIMEOUT || cfg->timeout_seconds > MAX_TIMEOUT) {
			fprintf(stderr, "ERROR: invalid value for timeout_seconds\n");
			return -1;
		}
	} else if (strcmp(key, "whowas_timeout_seconds") == 0) {
		cfg->whowas_timeout_seconds = srv_cfg_parse_int(value);
		if (cfg->whowas_timeout_seconds < MIN_TIMEOUT ||
		    cfg->whowas_timeout_seconds > MAX_TIMEOUT) {
			fprintf(stderr, "ERROR: invalid value for whowas_timeout_seconds\n");
			return -1;
		}
	} else if (strcmp(key, "kill_timeout_seconds") == 0) {
		cfg->kill_timeout_seconds = srv_cfg_parse_int(value);
		if (cfg->kill_timeout_seconds < MIN_TIMEOUT ||
		    cfg->kill_timeout_seconds > MAX_TIMEOUT) {
			fprintf(stderr, "ERROR: invalid value for kill_timeout_seconds\n");
			return -1;
		}
	} else if (strcmp(key, "operators_file") == 0) {
		if (! srv_cfg_verify_operators_filename(value, &errmsg)) {
			fprintf(stderr, "ERROR: operators file: %s\n", errmsg);
			return -1;
		}
		strcpy(cfg->operators_filename, value);
	} else if (strcmp(key, "username") == 0) {
		strcpy(cfg->username, value);
	} else if (strcmp(key, "chroot_dir") == 0) {
		if (strlen(value) > 0 && value[0] != '/') {
			fprintf(stderr, "ERROR: chroot_dir must be an absolute path\n");
			return -1;
		}
		strcpy(cfg->chroot_dir, value);
	} else if (strcmp(key, "daemonize") == 0) {
		cfg->daemonize = srv_cfg_parse_int(value);
		if (cfg->daemonize != 0 && cfg->daemonize != 1) {
			fprintf(stderr, "ERROR: invalid value for daemonize\n");
			return -1;
		}
	} else
		fprintf(stderr, "WARNING: unknown keyword \"%s\", skipping\n", key);

	return 0;
}

static int srv_cfg_verify_operators_filename(const char *fn, const char **errmsg)
{
	if (strlen(fn) == 0)
		/* An empty string is the default value and means no file. */
		return 1;

	if (fn[0] != '/') {
		*errmsg = "not an absolute path";
		return 0;
	}

	if (access(fn, R_OK) != 0) {
		*errmsg = "file cannot be read";
		return 0;
	}

	return 1;
}

void srv_parse_config(FILE *f, struct server_config *cfg)
{
	char *ret;
	int lineno;
	int keylen;
	int valuelen;

	char *line = srv_malloc_msg();
	char *key = srv_malloc_msg();
	char *value = srv_malloc_msg();

	/* Set some sane default values. */
	strcpy(cfg->server_name, DEFAULT_SERVER_NAME);
	strcpy(cfg->motd, DEFAULT_MOTD);
	strcpy(cfg->location, DEFAULT_LOCATION);
	strcpy(cfg->entity, DEFAULT_ENTITY);
	strcpy(cfg->email, DEFAULT_EMAIL);
	cfg->max_clients = DEFAULT_MAX_CLIENTS;
	cfg->max_channels = DEFAULT_MAX_CHANNELS;
	cfg->max_client_channels = DEFAULT_MAX_CLIENT_CHANNELS;
	cfg->max_channel_members = DEFAULT_MAX_CHANNEL_MEMBERS;
	cfg->max_bans = DEFAULT_MAX_BANS;
	cfg->max_excepts = DEFAULT_MAX_EXCEPTS;
	cfg->max_invites = DEFAULT_MAX_INVITES;
	cfg->port = DEFAULT_PORT;
	strcpy(cfg->address, DEFAULT_ADDRESS);
	cfg->timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
	cfg->whowas_timeout_seconds = DEFAULT_WHOWAS_TIMEOUT_SECONDS;
	cfg->kill_timeout_seconds = DEFAULT_KILL_TIMEOUT_SECONDS;
	strcpy(cfg->operators_filename, DEFAULT_OPERATORS_FILENAME);
	strcpy(cfg->username, DEFAULT_USERNAME);
	strcpy(cfg->chroot_dir, DEFAULT_CHROOT_DIR);
	cfg->daemonize = DEFAULT_DAEMONIZE;

	lineno = 0;
	while (! (feof(f) || ferror(f))) {
		ret = fgets(line, MESSAGE_BUFFER_SIZE, f);

		if (ret == NULL) /* EOF */
			break;

		++lineno;

		/* If the line was too long, skip the rest of it. */
		if (line[strlen(line) - 1] != '\n') {
			fprintf(stderr, "WARNING: line %d looks malformed, skipping\n", lineno);
			while (fgets(line, MESSAGE_BUFFER_SIZE, f) != NULL &&
			       line[strlen(line) - 1] != '\n')
				;
			continue;
		}

		/* Skip comments. */
		if (line[0] == '#')
			continue;

		/* Skip empty lines. */
		if (strlen(line) == 1 && line[0] == '\n')
			continue;

		/* Skip malformed lines. */
		ret = strchr(line, '=');
		if (ret == NULL) {
			fprintf(stderr, "WARNING: line %d looks malformed, skipping\n", lineno);
			continue;
		}

		/*
		 * Remove trailing newline. The line is not empty because '='
		 * was found.
		 */
		line[strlen(line) - 1] = '\0';

		/* Store key and value. */
		keylen = ret - line;
		valuelen = strlen(line) - (ret - line + 1);

		memcpy(key, line, keylen);
		key[keylen] = '\0';
		memcpy(value, ret + 1, valuelen);
		value[valuelen] = '\0';

		if (srv_cfg_parse_key_value(key, value, cfg) != 0)
			exit(EXIT_FAILURE);
	}

	/* Reserve one output buffer line per possible channel member. */
	cfg->output_buffer_size = MAX_MESSAGE_LEN * 
		((cfg->max_clients < cfg->max_channel_members)?
		 cfg->max_clients:cfg->max_channel_members);

	srv_free(&line);
	srv_free(&key);
	srv_free(&value);
}

static void srv_load_operators(FILE *f, sqlite3 *db)
{
	char *ret;
	int lineno;
	int userlen;
	int passlen;

	struct db_operator op;
	char *line = srv_malloc_msg();

	lineno = 0;
	while (! (feof(f) || ferror(f))) {
		ret = fgets(line, MESSAGE_BUFFER_SIZE, f);

		if (ret == NULL) /* EOF */
			break;

		++lineno;

		/* If the line was too long, skip the rest of it. */
		if (line[strlen(line) - 1] != '\n') {
			fprintf(stderr, "WARNING: line %d in operators file looks malformed, skipping\n", lineno);
			while (fgets(line, MESSAGE_BUFFER_SIZE, f) != NULL &&
			       line[strlen(line) - 1] != '\n')
				;
			continue;
		}

		/* Skip comments. */
		if (line[0] == '#')
			continue;

		/* Skip empty lines. */
		if (strlen(line) == 1 && line[0] == '\n')
			continue;

		/* Skip malformed lines. */
		ret = strchr(line, ' ');
		if (ret == NULL) {
			fprintf(stderr, "WARNING: line %d in operators file looks malformed, skipping\n", lineno);
			continue;
		}

		/*
		 * Remove trailing newline. The line is not empty because a
		 * space was found.
		 */
		line[strlen(line) - 1] = '\0';

		/* Store username and password. */
		userlen = ret - line;
		passlen = strlen(line) - (ret - line + 1);

		memcpy(op.username, line, userlen);
		op.username[userlen] = '\0';
		memcpy(op.password, ret + 1, passlen);
		op.password[passlen] = '\0';

		if (! srv_op_user_pass_verify(op.username)) {
			fprintf(stderr, "ERROR: invalid operator name in line %d, skipping\n", lineno);
			continue;
		}

		if (! srv_op_user_pass_verify(op.password)) {
			fprintf(stderr, "ERROR: invalid operator password in line %d, skipping\n", lineno);
			continue;
		}

		if (db_add_operator(db, &op) != 0) {
			fprintf(stderr, "ERROR: unable to add operator in line %d to database\n", lineno);
			exit(EXIT_FAILURE);
		}
	}

	srv_free(&line);
}

static int srv_op_user_pass_verify(const char *str)
{
	const char *itr;

	for (itr = str; *itr != '\0'; ++itr) {
		if (! (
		       (*itr >= '0' && *itr <= '9') ||
		       (*itr >= 'a' && *itr <= 'z') ||
		       (*itr >= 'A' && *itr <= 'Z') ||
		       *itr == '!' || *itr == '"' || *itr == '#' ||
		       *itr == '$' || *itr == '%' || *itr == '&' ||
		       *itr == '\'' || *itr == '(' || *itr == ')' ||
		       *itr == '*' || *itr == '+' || *itr == ',' ||
		       *itr == '-' || *itr == '.' || *itr == '/' ||
		       *itr == ':' || *itr == ';' || *itr == '<' ||
		       *itr == '=' || *itr == '>' || *itr == '?' ||
		       *itr == '@' || *itr == '[' || *itr == '\\' ||
		       *itr == ']' || *itr == '^' || *itr == '_' ||
		       *itr == '`' || *itr == '{' || *itr == '|' ||
		       *itr == '}' || *itr == '~'
		))
			return 0;
	}

	return 1;
}
