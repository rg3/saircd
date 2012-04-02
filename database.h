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
 * database.h - Server Database.
 */
#ifndef _DATABASE_H_
#define _DATABASE_H_

/*
 * The following data structures reflect one database table each.
 */

struct db_forbidden_nick {
	sqlite3_int64 id_nick;
	char nickname[NICKNAME_BUFFER_SIZE];
	time_t expiry;
};

struct db_operator {
	sqlite3_int64 id_oper;
	char username[MESSAGE_BUFFER_SIZE];
	char password[MESSAGE_BUFFER_SIZE];
};

struct db_client {
	sqlite3_int64 id_client;
	sqlite3_int64 id_oper;
	int fd;
	char ip[MESSAGE_BUFFER_SIZE];
	int port;
	char orig_nickname[NICKNAME_BUFFER_SIZE];
	char nickname[NICKNAME_BUFFER_SIZE];
	char username[MESSAGE_BUFFER_SIZE];
	char realname[MESSAGE_BUFFER_SIZE];
	char orig_fullname[MESSAGE_BUFFER_SIZE];
	char fullname[MESSAGE_BUFFER_SIZE];
	int away_flag;
	char away_text[MESSAGE_BUFFER_SIZE];
	int invisible_flag;
	int wallops_flag;
	int restricted_flag;
	int operator_flag;
	int local_operator_flag;
	int server_notices_flag;
	int array_index;
	int regstate;
	time_t last_activity;
	time_t last_ping;
	time_t last_talk;
	time_t signon_time;
};

struct db_channel {
	sqlite3_int64 id_channel;
	char orig_name[CHANNEL_BUFFER_SIZE];
	char name[CHANNEL_BUFFER_SIZE];
	char topic[MESSAGE_BUFFER_SIZE];
	int key_flag;
	char key[MESSAGE_BUFFER_SIZE];
	int limit_flag;
	int limit_v;
	int anonymous_flag;
	int invite_only_flag;
	int moderated_flag;
	int no_outside_flag;
	int quiet_flag;
	int private_flag;
	int secret_flag;
	int oper_topic_flag;
	int special_flag; /* Permanent, only operators may join and it's not counted anywhere. */
};

struct db_membership {
	sqlite3_int64 id_channel;
	sqlite3_int64 id_client;
	int operator_flag;
	int voice_flag;
};

struct db_banmask {
	sqlite3_int64 id_banmask;
	sqlite3_int64 id_channel;
	char orig_mask[MESSAGE_BUFFER_SIZE];
	char mask[MESSAGE_BUFFER_SIZE];
};

struct db_exceptmask {
	sqlite3_int64 id_exceptmask;
	sqlite3_int64 id_channel;
	char orig_mask[MESSAGE_BUFFER_SIZE];
	char mask[MESSAGE_BUFFER_SIZE];
};

struct db_invitemask {
	sqlite3_int64 id_invitemask;
	sqlite3_int64 id_channel;
	char orig_mask[MESSAGE_BUFFER_SIZE];
	char mask[MESSAGE_BUFFER_SIZE];
};

struct db_invite {
	sqlite3_int64 id_channel;
	sqlite3_int64 id_client;
};

struct db_whowas {
	sqlite3_int64 id_whowas;
	char orig_nickname[NICKNAME_BUFFER_SIZE];
	char nickname[NICKNAME_BUFFER_SIZE];
	char username[MESSAGE_BUFFER_SIZE];
	char ip[MESSAGE_BUFFER_SIZE];
	char realname[MESSAGE_BUFFER_SIZE];
	time_t quit_time;
};

struct db_client_channel {
	struct db_client client;
	struct db_channel channel;
};

/*
 * Callback prototype, used in some functions below. The idea here is that
 * functions that receive a callback to be executed on every result row will
 * pass a pointer to a struct db_<whatever> as the first argument to the
 * callback, containing the data from the given row, and will forward the
 * extra pointer as the second argument to the callback function.
 */
typedef void (*db_callback)(void *row, void *extra);

/*
 * Database API functions. Unless stated otherwise, these functions return zero
 * on success and nonzero on failure.
 */

/*
 * This function creates the database and returns its handler.
 */
sqlite3 *db_create(void);

/*
 * This function clears the database.
 */
void db_clear(sqlite3 *db);

/*
 * This function closes the database.
 */
void db_close(sqlite3 *db);

/*
 * The following functions retrieve a table entry by ID.
 */
int db_get_forbidden_nick(sqlite3 *db, sqlite3_int64 id, struct db_forbidden_nick *out);
int db_get_operator(sqlite3 *db, sqlite3_int64 id, struct db_operator *out);
int db_get_client(sqlite3 *db, sqlite3_int64 id, struct db_client *out);
int db_get_channel(sqlite3 *db, sqlite3_int64 id, struct db_channel *out);
int db_get_membership(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client, struct db_membership *out);
int db_get_banmask(sqlite3 *db, sqlite3_int64 id, struct db_banmask *out);
int db_get_exceptmask(sqlite3 *db, sqlite3_int64 id, struct db_exceptmask *out);
int db_get_invitemask(sqlite3 *db, sqlite3_int64 id, struct db_invitemask *out);
int db_get_invite(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client, struct db_invite *out);
int db_get_whowas(sqlite3 *db, sqlite3_int64 id, struct db_whowas *out);

/*
 * Add a new forbidden nick.
 */
int db_add_forbidden_nick(sqlite3 *db, struct db_forbidden_nick *in);

/*
 * Add a new forbidden nick, with automatic expiry time.
 */
int db_add_expiring_forbidden_nick(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE], int seconds);

/*
 * Delete a forbidden nick.
 */
int db_del_forbidden_nick(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE]);

/*
 * Delete all expired forbidden nicks.
 */
int db_del_expired_forbidden_nicks(sqlite3 *db);

/*
 * Check if a nickname is in the forbidden nick table.
 */
int db_nickname_is_forbidden(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE]);

/* 
 * Check if a nickname is available.
 */
int db_nickname_available(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE]);

/*
 * Add an operator.
 */
int db_add_operator(sqlite3 *db, struct db_operator *in);

/*
 * Add a client.
 */
int db_add_client(sqlite3 *db, struct db_client *in);

/*
 * Delete a client.
 */
int db_del_client(sqlite3 *db, const struct db_client *in);

/*
 * Modify a client.
 */
int db_modify_client(sqlite3 *db, const struct db_client *in);

/*
 * Update last activity time on a client.
 */
int db_update_client_activity(sqlite3 *db, sqlite3_int64 cli);

/*
 * Update last unanswered ping time on a client.
 */
int db_update_client_ping(sqlite3 *db, sqlite3_int64 cli);

/*
 * Add a channel.
 */
int db_add_channel(sqlite3 *db, struct db_channel *in);

/*
 * Delete a channel.
 */
int db_del_channel(sqlite3 *db, const struct db_channel *in);

/*
 * Modify a channel.
 */
int db_modify_channel(sqlite3 *db, const struct db_channel *in);

/*
 * Get a banmask, exceptmask or invitemask by normalized mask.
 */
int db_get_banmask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_banmask *out);
int db_get_exceptmask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_exceptmask *out);
int db_get_invitemask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_invitemask *out);

/*
 * Add a banmask, exceptmask or invitemask.
 */
int db_add_banmask(sqlite3 *db, struct db_banmask *in);
int db_add_exceptmask(sqlite3 *db, struct db_exceptmask *in);
int db_add_invitemask(sqlite3 *db, struct db_invitemask *in);

/*
 * Delete a banmask, exceptmask or invitemask.
 */
int db_del_banmask(sqlite3 *db, const struct db_banmask *mask);
int db_del_exceptmask(sqlite3 *db, const struct db_exceptmask *mask);
int db_del_invitemask(sqlite3 *db, const struct db_invitemask *mask);

/*
 * Count channel banmasks, exceptmasks or invitemasks.
 */
int db_count_banmasks(sqlite3 *db, sqlite3_int64 chan);
int db_count_exceptmasks(sqlite3 *db, sqlite3_int64 chan);
int db_count_invitemasks(sqlite3 *db, sqlite3_int64 chan);

/*
 * Get client information by file descriptor.
 */
int db_get_client_by_fd(sqlite3 *db, int fd, struct db_client *out);

/*
 * Get client information by nickname.
 */
int db_get_client_by_nick(sqlite3 *db, const char *nickname, struct db_client *out);

/*
 * Get client by operator id.
 */
int db_get_client_by_opid(sqlite3 *db, sqlite3_int64 id, struct db_client *out);

/*
 * Get operator ID by username and password.
 */
int db_get_operator_id(sqlite3 *db, const char *un, const char *pw, sqlite3_int64 *id);

/*
 * Get channel by name.
 */
int db_get_channel_by_name(sqlite3 *db, const char *name, struct db_channel *out);

/*
 * Get number of channels a client is in.
 */
int db_count_client_channels(sqlite3 *db, sqlite3_int64 id_client);

/*
 * Get number of clients in a channel.
 */
int db_count_channel_members(sqlite3 *db, sqlite3_int64 id_channel);

/*
 * Get number of non-invisible clients in a channel.
 */
int db_count_visible_members(sqlite3 *db, sqlite3_int64 id_channel);

/*
 * Get number of channels.
 */
int db_count_channels(sqlite3 *db);

/*
 * Get number of clients.
 */
int db_count_clients(sqlite3 *db);

/*
 * Get number of clients that are operators.
 */
int db_count_client_operators(sqlite3 *db);

/*
 * Create a new membership.
 */
int db_add_membership(sqlite3 *db, const struct db_membership *in);

/*
 * Modify a membership.
 */
int db_modify_membership(sqlite3 *db, const struct db_membership *in);

/*
 * Delete a membership.
 */
int db_delete_membership(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client);

/*
 * Delete all client memberships (JOIN 0).
 */
int db_delete_client_memberships(sqlite3 *db, sqlite3_int64 id_client);

/*
 * Check if a client can invite others to a channel. Returns the boolean answer
 * to the question "Can this client invite others to this channel?"
 */
int db_client_can_invite(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan);

/*
 * Invite a client to a channel.
 */
int db_invite_client(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client);

/*
 * Delete a client invitation.
 */
int db_del_invite(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client);

/*
 * Clear all channel invites.
 */
int db_clear_all_invites(sqlite3 *db, sqlite3_int64 id_channel);

/*
 * Check if a client is banned from a channel. Returns the boolean answer to the
 * question "Is this client NOT banned from this channel?"
 */
int db_client_not_banned(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan);

/*
 * Check if a client meets the invite requirements for a channel. Returns the
 * boolean answer to the question "Is the channel invite-only flag disabled or
 * else the client matches an invite mask or else the client has been invited?"
 */
int db_client_meets_invite_req(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan);

/*
 * Check if a client meets the requirements to be able to join an existing
 * channel. Return codes are:
 *	-1 if the client is already on the channel.
 *	0 if the client may join the channel.
 *	A reply code in case of errors (e.g. ERR_BADCHANNELKEY).
 */
int db_client_may_join(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan, const char *key);

/*
 * Check if a client may talk in a given channel. Returns the boolean answer to
 * the question "May this client send a PRIVMSG to this channel?"
 */
int db_client_may_talk(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan);

/*
 * Check if a client may set the channel topic for a given channel. Returns the
 * boolean answer to the question "May this user set the topic for this
 * channel?"
 */
int db_client_may_set_topic(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan);

/*
 * Clear whowas information older than a given time in seconds.
 */
int db_clear_whowas(sqlite3 *db, int seconds);

/* Run the following callback on every client. */
int db_run_on_clients(sqlite3 *db, db_callback callback, void *extra);

/*
 * Run the following callback on every channel member. The first callback
 * argument will be a struct db_client pointer.
 */
int db_run_on_members(sqlite3 *db, sqlite3_int64 chan,
		      db_callback callback, void *extra);

/*
 * Run the following callback on every channel member except one. The first
 * callback argument will be a struct db_client pointer.
 */
int db_run_on_members_except(sqlite3 *db, sqlite3_int64 chan, sqlite3_int64 cli,
			     db_callback callback, void *extra);

/*
 * Run the following callback for every client sharing a non-quiet and
 * non-anonymous channel with the given one. The first callback argument will
 * be a struct db_client pointer.
 */
int db_run_on_non_anon_neighbors(sqlite3 *db, sqlite3_int64 cli,
				 db_callback callback, void *extra);

/*
 * Run the following callback for every client-channel pair where the channel
 * is an anonymous channel the client "cli" is in, and the client is another
 * member of that channel. The first callback argument will be a struct
 * db_client_channel pointer.
 */
int db_run_on_anon_neighbors(sqlite3 *db, sqlite3_int64 cli,
			     db_callback callback, void *extra);

/*
 * Run the following callback for every client sharing a non-quiet client with
 * the given one. The first callback argument will be a struct db_client
 * pointer.
 */
int db_run_on_neighbors(sqlite3 *db, sqlite3_int64 cli,
			db_callback callback, void *extra);

/*
 * Run the following callback on every channel ban mask. THe first callback
 * argument will be a struct db_banmask pointer.
 */
int db_run_on_banmasks(sqlite3 *db, sqlite3_int64 chan,
		       db_callback callback, void *extra);

/*
 * Run the following callback on every channel ban mask. THe first callback
 * argument will be a struct db_exceptmask pointer.
 */
int db_run_on_exceptmasks(sqlite3 *db, sqlite3_int64 chan,
			  db_callback callback, void *extra);

/*
 * Run the following callback on every channel ban mask. THe first callback
 * argument will be a struct db_invitemask pointer.
 */
int db_run_on_invitemasks(sqlite3 *db, sqlite3_int64 chan,
			  db_callback callback, void *extra);

/*
 * Run the following callback on every whowas entry matching a given nickname.
 * The first callback argument will be a struct db_whowas pointer.
 */
int db_run_on_whowas(sqlite3 *db, const char *nick, int count,
		     db_callback callback, void *extra);

/*
 * Run the following callback on every client having the wallops flag active.
 */
int db_run_on_wallops(sqlite3 *db, db_callback callback, void *extra);

/*
 * Run the following callback on every channel the client is a member of.
 */
int db_run_on_client_channels(sqlite3 *db, sqlite3_int64 cli, db_callback callback, void *extra);

/*
 * Run the following callback on every client with an expired PING time.
 */
int db_run_on_ping_timeout_clients(sqlite3 *db, int seconds, db_callback callback, void *extra);

/*
 * Run the following callback on inactive clients with no pending PINGs.
 */
int db_run_on_inactive_clients(sqlite3 *db, int seconds, db_callback callback, void *extra);

#endif /* _DATABASE_H_ */
