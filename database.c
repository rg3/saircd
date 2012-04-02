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
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#include "messages.h"
#include "database.h"

/*
 * Auxiliar macros for small pieces of code that repeat all the time.
 */
#define FINALIZE_IF_DB_NULL()					\
	do {							\
		if (db == NULL) {				\
			if (stmt != NULL) {			\
				sqlite3_finalize(stmt);		\
				stmt = NULL;			\
			}					\
			return 0;				\
		}						\
	} while (0)

#define PREPARE_IF_STMT_NULL()					\
	do {							\
		if (stmt == NULL)				\
			assert(sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL) == SQLITE_OK);	\
	} while (0)

/*
 * Auxiliar function prototypes.
 */

/* Run a simple SQL statement that should not fail. */
static void db_simple_exec(sqlite3 *db, const char *query);

/* Fill client information from the current row with the given column offset. */
static void db_fill_client_from_row(sqlite3_stmt *stmt, struct db_client *out, int offset);

/* Fill channel information from the current row with the given column offset. */
static void db_fill_channel_from_row(sqlite3_stmt *stmt, struct db_channel *out, int offset);

/* Fill whowas information from the current row with the given column offset. */
static void db_fill_whowas_from_row(sqlite3_stmt *stmt, struct db_whowas *out, int offset);

/* Bind client data to a statement. */
static void db_bind_client_data(sqlite3_stmt *stmt, const struct db_client *in);

/* Bind channel data to a statement. */
static void db_bind_channel_data(sqlite3_stmt *stmt, const struct db_channel *in);

/*
 * Auxiliar function implementation.
 */

static void db_simple_exec(sqlite3 *db, const char *query)
{
	char *errmsg;

	errmsg = NULL;
	assert(sqlite3_exec(db, query, NULL, NULL, &errmsg) == SQLITE_OK);

	/* In theory, this never happens. */
	if (errmsg != NULL)
		sqlite3_free(errmsg);
}

static void db_fill_client_from_row(sqlite3_stmt *stmt, struct db_client *out, int offset)
{
	out->id_client = sqlite3_column_int64(stmt, 0 + offset);
	out->id_oper = sqlite3_column_int64(stmt, 1 + offset);
	out->fd = sqlite3_column_int(stmt, 2 + offset);
	strcpy(out->ip, (const char *)sqlite3_column_text(stmt, 3 + offset));
	out->port = sqlite3_column_int(stmt, 4 + offset);
	strcpy(out->orig_nickname, (const char *)sqlite3_column_text(stmt, 5 + offset));
	strcpy(out->nickname, (const char *)sqlite3_column_text(stmt, 6 + offset));
	strcpy(out->username, (const char *)sqlite3_column_text(stmt, 7 + offset));
	strcpy(out->realname, (const char *)sqlite3_column_text(stmt, 8 + offset));
	strcpy(out->orig_fullname, (const char *)sqlite3_column_text(stmt, 9 + offset));
	strcpy(out->fullname, (const char *)sqlite3_column_text(stmt, 10 + offset));
	out->away_flag = sqlite3_column_int(stmt, 11 + offset);
	strcpy(out->away_text, (const char *)sqlite3_column_text(stmt, 12 + offset));
	out->invisible_flag = sqlite3_column_int(stmt, 13 + offset);
	out->wallops_flag = sqlite3_column_int(stmt, 14 + offset);
	out->restricted_flag = sqlite3_column_int(stmt, 15 + offset);
	out->operator_flag = sqlite3_column_int(stmt, 16 + offset);
	out->local_operator_flag = sqlite3_column_int(stmt, 17 + offset);
	out->server_notices_flag = sqlite3_column_int(stmt, 18 + offset);
	out->array_index = sqlite3_column_int(stmt, 19 + offset);
	out->regstate = sqlite3_column_int(stmt, 20 + offset);
	out->last_activity = (time_t)sqlite3_column_int64(stmt, 21 + offset);
	out->last_ping = (time_t)sqlite3_column_int64(stmt, 22 + offset);
	out->last_talk = (time_t)sqlite3_column_int64(stmt, 23 + offset);
	out->signon_time = (time_t)sqlite3_column_int64(stmt, 24 + offset);
}

static void db_fill_channel_from_row(sqlite3_stmt *stmt, struct db_channel *out, int offset)
{
	out->id_channel = sqlite3_column_int64(stmt, 0 + offset);
	strcpy(out->orig_name, (const char *)sqlite3_column_text(stmt, 1 + offset));
	strcpy(out->name, (const char *)sqlite3_column_text(stmt, 2 + offset));
	strcpy(out->topic, (const char *)sqlite3_column_text(stmt, 3 + offset));
	out->key_flag = sqlite3_column_int(stmt, 4 + offset);
	strcpy(out->key, (const char *)sqlite3_column_text(stmt, 5 + offset));
	out->limit_flag = sqlite3_column_int(stmt, 6 + offset);
	out->limit_v = sqlite3_column_int(stmt, 7 + offset);
	out->anonymous_flag = sqlite3_column_int(stmt, 8 + offset);
	out->invite_only_flag = sqlite3_column_int(stmt, 9 + offset);
	out->moderated_flag = sqlite3_column_int(stmt, 10 + offset);
	out->no_outside_flag = sqlite3_column_int(stmt, 11 + offset);
	out->quiet_flag = sqlite3_column_int(stmt, 12 + offset);
	out->private_flag = sqlite3_column_int(stmt, 13 + offset);
	out->secret_flag = sqlite3_column_int(stmt, 14 + offset);
	out->oper_topic_flag = sqlite3_column_int(stmt, 15 + offset);
	out->special_flag = sqlite3_column_int(stmt, 16 + offset);
}

static void db_fill_whowas_from_row(sqlite3_stmt *stmt, struct db_whowas *out, int offset)
{
	out->id_whowas = sqlite3_column_int64(stmt, 0 + offset);
	strcpy(out->orig_nickname, (const char *)sqlite3_column_text(stmt, 1 + offset));
	strcpy(out->nickname, (const char *)sqlite3_column_text(stmt, 2 + offset));
	strcpy(out->username, (const char *)sqlite3_column_text(stmt, 3 + offset));
	strcpy(out->ip, (const char *)sqlite3_column_text(stmt, 4 + offset));
	strcpy(out->realname, (const char *)sqlite3_column_text(stmt, 5 + offset));
	out->quit_time = (time_t)sqlite3_column_int64(stmt, 6 + offset);
}

static void db_bind_client_data(sqlite3_stmt *stmt, const struct db_client *in)
{
	assert(sqlite3_bind_int64(stmt, 1, in->id_oper) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 2, in->fd) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 3, in->ip, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 4, in->port) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 5, in->orig_nickname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 6, in->nickname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 7, in->username, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 8, in->realname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 9, in->orig_fullname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 10, in->fullname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 11, in->away_flag) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 12, in->away_text, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 13, in->invisible_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 14, in->wallops_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 15, in->restricted_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 16, in->operator_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 17, in->local_operator_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 18, in->server_notices_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 19, in->array_index) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 20, in->regstate) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 21, in->last_activity) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 22, in->last_ping) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 23, in->last_talk) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 24, in->signon_time) == SQLITE_OK);
}

static void db_bind_channel_data(sqlite3_stmt *stmt, const struct db_channel *in)
{
	assert(sqlite3_bind_text(stmt, 1, in->orig_name, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, in->name, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 3, in->topic, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 4, in->key_flag) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 5, in->key, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 6, in->limit_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 7, in->limit_v) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 8, in->anonymous_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 9, in->invite_only_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 10, in->moderated_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 11, in->no_outside_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 12, in->quiet_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 13, in->private_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 14, in->secret_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 15, in->oper_topic_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 16, in->special_flag) == SQLITE_OK);
}

/*
 * Interface implementation.
 */

sqlite3 *db_create(void)
{
	sqlite3 *db;

	assert(sqlite3_open(":memory:", &db) == SQLITE_OK);

	db_simple_exec(db,
		"CREATE TABLE forbidden_nick ("
		"id_nick INTEGER PRIMARY KEY,"
		"nickname TEXT,"
		"expiry INTEGER);"
	);

	db_simple_exec(db,
		"CREATE INDEX fbd_nick "
		"ON forbidden_nick (nickname ASC);"
	);

	db_simple_exec(db,
		"INSERT INTO forbidden_nick (nickname, expiry) VALUES ('root', 0);"
	);

	db_simple_exec(db,
		"INSERT INTO forbidden_nick (nickname, expiry) VALUES ('anonymous', 0);"
	);

	db_simple_exec(db,
		"CREATE TABLE operator ("
		"id_oper INTEGER PRIMARY KEY,"
		"username TEXT UNIQUE,"
		"password TEXT);"
	);

	db_simple_exec(db,
		"CREATE INDEX op_userpass ON operator "
		"(username ASC, password ASC);"
	);

	db_simple_exec(db,
		"CREATE TABLE client ("
		"id_client INTEGER PRIMARY KEY,"
		"id_oper INTEGER REFERENCES operator (id_oper),"
		"fd INTEGER UNIQUE,"
		"ip TEXT,"
		"port INTEGER,"
		"orig_nickname TEXT,"
		"nickname TEXT,"
		"username TEXT,"
		"realname TEXT,"
		"orig_fullname TEXT,"
		"fullname TEXT,"
		"away_flag INTEGER,"
		"away_text TEXT,"
		"invisible_flag INTEGER,"
		"wallops_flag INTEGER,"
		"restricted_flag INTEGER,"
		"operator_flag INTEGER,"
		"local_operator_flag INTEGER,"
		"server_notices_flag INTEGER,"
		"array_index INTEGER,"
		"regstate INTEGER,"
		"last_activity INTEGER,"
		"last_ping INTEGER,"
		"last_talk INTEGER,"
		"signon_time INTEGER);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_fd ON client (fd ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_nick ON client (nickname ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_oper ON client (id_oper ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_opflag ON client (operator_flag ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_lopflag ON client (local_operator_flag ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX client_invflag ON client (invisible_flag ASC);"
	);

	db_simple_exec(db,
		"CREATE TABLE channel ("
		"id_channel INTEGER PRIMARY KEY,"
		"orig_name TEXT,"
		"name TEXT,"
		"topic TEXT,"
		"key_flag INTEGER,"
		"key STRING,"
		"limit_flag INTEGER,"
		"limit_v INTEGER,"
		"anonymous_flag INTEGER,"
		"invite_only_flag INTEGER,"
		"moderated_flag INTEGER,"
		"no_outside_flag INTEGER,"
		"quiet_flag INTEGER,"
		"private_flag INTEGER,"
		"secret_flag INTEGER,"
		"oper_topic_flag INTEGER,"
		"special_flag INTEGER);"
	);

	db_simple_exec(db,
		"CREATE INDEX channel_name ON channel (name ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX channel_special ON channel (special_flag ASC);"
	);

	db_simple_exec(db,
		"INSERT INTO channel "
		"(orig_name, name, topic, key_flag, key, limit_flag, limit_v, "
		" anonymous_flag, invite_only_flag, moderated_flag, "
		" no_outside_flag, quiet_flag, private_flag, secret_flag, "
		" oper_topic_flag, special_flag) "
		"VALUES ('#log', '#log', 'Server Log', 0, '', 0, 0, 0, 0, 0, "
		"        1, 1, 0, 1, 1, 1);"
	);

	db_simple_exec(db,
		"CREATE TABLE membership ("
		"id_channel INTEGER REFERENCES channel (id_channel),"
		"id_client INTEGER REFERENCES client (id_client),"
		"operator_flag INTEGER,"
		"voice_flag INTEGER,"
		"PRIMARY KEY (id_channel, id_client));"
	);

	db_simple_exec(db,
		"CREATE INDEX memb_cli ON "
		"membership (id_client ASC);"
	);

	db_simple_exec(db,
		"CREATE TRIGGER chan_del_part AFTER DELETE ON membership "
		"WHEN (SELECT COUNT(*) FROM membership WHERE id_channel = OLD.id_channel) = 0 "
		"BEGIN "
		"DELETE FROM channel WHERE id_channel = OLD.id_channel AND special_flag = 0;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TRIGGER chan_membership_del AFTER DELETE ON channel "
		"BEGIN "
		"DELETE FROM membership WHERE id_channel = OLD.id_channel;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TRIGGER cli_membership_del AFTER DELETE ON client "
		"BEGIN "
		"DELETE FROM membership WHERE id_client = OLD.id_client;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TABLE banmask ("
		"id_banmask INTEGER PRIMARY KEY,"
		"id_channel INTEGER REFERENCES channel (id_channel),"
		"orig_mask TEXT,"
		"mask TEXT);"
	);

	db_simple_exec(db,
		"CREATE INDEX banmask_chan ON "
		"banmask (id_channel ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX banmask_mask ON "
		"banmask (id_channel ASC, mask ASC);"
	);

	db_simple_exec(db,
		"CREATE TRIGGER banmask_del AFTER DELETE ON channel "
		"BEGIN "
		"DELETE FROM banmask WHERE id_channel = OLD.id_channel;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TABLE exceptmask ("
		"id_exceptmask INTEGER PRIMARY KEY,"
		"id_channel INTEGER REFERENCES channel (id_channel),"
		"orig_mask TEXT,"
		"mask TEXT);"
	);

	db_simple_exec(db,
		"CREATE INDEX exceptmask_chan ON "
		"exceptmask (id_channel ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX exceptmask_mask ON "
		"exceptmask (id_channel ASC, mask ASC);"
	);

	db_simple_exec(db,
		"CREATE TRIGGER exceptmask_del AFTER DELETE ON channel "
		"BEGIN "
		"DELETE FROM exceptmask WHERE id_channel = OLD.id_channel;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TABLE invitemask ("
		"id_invitemask INTEGER PRIMARY KEY,"
		"id_channel INTEGER REFERENCES channel (id_channel),"
		"orig_mask TEXT,"
		"mask TEXT);"
	);

	db_simple_exec(db,
		"CREATE INDEX invitemask_chan ON "
		"invitemask (id_channel ASC);"
	);

	db_simple_exec(db,
		"CREATE INDEX invitemask_mask ON "
		"invitemask (id_channel ASC, mask ASC);"
	);

	db_simple_exec(db,
		"CREATE TRIGGER invitemask_del AFTER DELETE ON channel "
		"BEGIN "
		"DELETE FROM invitemask WHERE id_channel = OLD.id_channel;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TABLE invite ("
		"id_channel INTEGER REFERENCES channel (id_channel),"
		"id_client INTEGER REFERENCES client (id_client),"
		"PRIMARY KEY(id_channel, id_client));"
	);

	db_simple_exec(db,
		"CREATE TRIGGER invite_del AFTER DELETE ON channel "
		"BEGIN "
		"DELETE FROM invite WHERE id_channel = OLD.id_channel;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TRIGGER invite_cli_del AFTER DELETE ON client "
		"BEGIN "
		"DELETE FROM invite WHERE id_client = OLD.id_client;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TRIGGER invite_clear AFTER INSERT ON membership "
		"BEGIN "
		"DELETE FROM invite WHERE id_channel = NEW.id_channel AND id_client = NEW.id_client;"
		"END;"
	);

	db_simple_exec(db,
		"CREATE TABLE whowas ("
		"id_whowas INTEGER PRIMARY KEY,"
		"orig_nickname TEXT,"
		"nickname TEXT,"
		"username TEXT,"
		"ip TEXT,"
		"realname TEXT,"
		"quit_time INTEGER);"
		); 

	db_simple_exec(db,
		"CREATE INDEX whowas_nick ON whowas (nickname ASC);"
	);

	db_simple_exec(db,
		"CREATE TRIGGER whowas_insert AFTER DELETE ON client "
		"BEGIN "
		"INSERT INTO whowas "
		"(orig_nickname, nickname, username, ip, realname, quit_time) "
		"VALUES (OLD.orig_nickname, OLD.nickname, OLD.username, OLD.ip, OLD.realname, strftime('%s'));"
		"END;"
	);

	return db;
}

void db_clear(sqlite3 *db)
{
	db_simple_exec(db, "DELETE FROM client;");
	db_simple_exec(db, "DELETE FROM channel;");
	db_simple_exec(db, "DELETE FROM whowas;");
	db_simple_exec(db, "DELETE FROM forbidden_nick WHERE expiry != 0;");
}

void db_close(sqlite3 *db)
{
	db_get_forbidden_nick(NULL, 0, NULL);
	db_get_operator(NULL, 0, NULL);
	db_get_client(NULL, 0, NULL);
	db_get_channel(NULL, 0, NULL);
	db_get_membership(NULL, 0, 0, NULL);
	db_get_banmask(NULL, 0, NULL);
	db_get_exceptmask(NULL, 0, NULL);
	db_get_invitemask(NULL, 0, NULL);
	db_get_invite(NULL, 0, 0, NULL);
	db_get_whowas(NULL, 0, NULL);
	db_add_forbidden_nick(NULL, NULL);
	db_add_expiring_forbidden_nick(NULL, NULL, 0);
	db_del_forbidden_nick(NULL, NULL);
	db_del_expired_forbidden_nicks(NULL);
	db_nickname_is_forbidden(NULL, NULL);
	db_nickname_available(NULL, NULL);
	db_add_operator(NULL, NULL);
	db_add_client(NULL, NULL);
	db_del_client(NULL, NULL);
	db_modify_client(NULL, NULL);
	db_update_client_activity(NULL, 0);
	db_update_client_ping(NULL, 0);
	db_add_channel(NULL, NULL);
	db_del_channel(NULL, NULL);
	db_modify_channel(NULL, NULL);
	db_get_banmask_by_mask(NULL, 0, NULL, NULL);
	db_get_exceptmask_by_mask(NULL, 0, NULL, NULL);
	db_get_invitemask_by_mask(NULL, 0, NULL, NULL);
	db_add_banmask(NULL, NULL);
	db_add_exceptmask(NULL, NULL);
	db_add_invitemask(NULL, NULL);
	db_del_banmask(NULL, NULL);
	db_del_exceptmask(NULL, NULL);
	db_del_invitemask(NULL, NULL);
	db_count_banmasks(NULL, 0);
	db_count_exceptmasks(NULL, 0);
	db_count_invitemasks(NULL, 0);
	db_get_client_by_fd(NULL, 0, NULL);
	db_get_client_by_nick(NULL, NULL, NULL);
	db_get_client_by_opid(NULL, 0, NULL);
	db_get_operator_id(NULL, NULL, NULL, NULL);
	db_get_channel_by_name(NULL, NULL, NULL);
	db_count_client_channels(NULL, 0);
	db_count_channel_members(NULL, 0);
	db_count_visible_members(NULL, 0);
	db_count_channels(NULL);
	db_count_clients(NULL);
	db_count_client_operators(NULL);
	db_add_membership(NULL, NULL);
	db_modify_membership(NULL, NULL);
	db_delete_membership(NULL, 0, 0);
	db_delete_client_memberships(NULL, 0);
	db_client_can_invite(NULL, NULL, NULL);
	db_invite_client(NULL, 0, 0);
	db_del_invite(NULL, 0, 0);
	db_clear_all_invites(NULL, 0);
	db_client_not_banned(NULL, NULL, NULL);
	db_client_meets_invite_req(NULL, NULL, NULL);
	db_client_may_join(NULL, NULL, NULL, NULL);
	db_client_may_talk(NULL, NULL, NULL);
	db_client_may_set_topic(NULL, NULL, NULL);
	db_clear_whowas(NULL, 0);
	db_run_on_members(NULL, 0, NULL, NULL);
	db_run_on_anon_neighbors(NULL, 0, NULL, NULL);
	db_run_on_neighbors(NULL, 0, NULL, NULL);
	db_run_on_non_anon_neighbors(NULL, 0, NULL, NULL);
	db_run_on_members_except(NULL, 0, 0, NULL, NULL);
	db_run_on_banmasks(NULL, 0, NULL, NULL);
	db_run_on_exceptmasks(NULL, 0, NULL, NULL);
	db_run_on_invitemasks(NULL, 0, NULL, NULL);
	db_run_on_whowas(NULL, NULL, 0, NULL, NULL);
	db_run_on_wallops(NULL, NULL, NULL);
	db_run_on_client_channels(NULL, 0, NULL, NULL);
	db_run_on_ping_timeout_clients(NULL, 0, NULL, NULL);
	db_run_on_inactive_clients(NULL, 0, NULL, NULL);
	db_run_on_clients(NULL, NULL, NULL);
	assert(sqlite3_close(db) == SQLITE_OK);
}

int db_get_forbidden_nick(sqlite3 *db, sqlite3_int64 id, struct db_forbidden_nick *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM forbidden_nick WHERE id_nick = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_nick = id;
	strcpy(out->nickname, (const char *)sqlite3_column_text(stmt, 1));
	out->expiry = (time_t)sqlite3_column_int64(stmt, 2);

	return 0;
}

int db_get_operator(sqlite3 *db, sqlite3_int64 id, struct db_operator *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM operator WHERE id_oper = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_oper = id;
	strcpy(out->username, (const char *)sqlite3_column_text(stmt, 1));
	strcpy(out->password, (const char *)sqlite3_column_text(stmt, 2));

	return 0;
}

int db_get_client(sqlite3 *db, sqlite3_int64 id, struct db_client *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_client_from_row(stmt, out, 0);

	return 0;
}

int db_get_channel(sqlite3 *db, sqlite3_int64 id, struct db_channel *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM channel WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_channel_from_row(stmt, out, 0);

	return 0;
}

int db_get_membership(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client, struct db_membership *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM membership WHERE id_channel = ? AND id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, id_client) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_channel = id_channel;
	out->id_client = id_client;
	out->operator_flag = sqlite3_column_int(stmt, 2);
	out->voice_flag = sqlite3_column_int(stmt, 3);

	return 0;
}

int db_get_banmask(sqlite3 *db, sqlite3_int64 id, struct db_banmask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM banmask WHERE id_banmask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_banmask = id;
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_banmask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_banmask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM banmask WHERE id_channel = ? AND mask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_banmask = sqlite3_column_int64(stmt, 0);
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_exceptmask(sqlite3 *db, sqlite3_int64 id, struct db_exceptmask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM exceptmask WHERE id_exceptmask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_exceptmask = id;
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_exceptmask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_exceptmask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM exceptmask WHERE id_channel = ? AND mask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_exceptmask = sqlite3_column_int64(stmt, 0);
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_invitemask(sqlite3 *db, sqlite3_int64 id, struct db_invitemask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM invitemask WHERE id_invitemask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_invitemask = id;
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_invitemask_by_mask(sqlite3 *db, sqlite3_int64 chan, const char *mask, struct db_invitemask *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM invitemask WHERE id_channel = ? AND mask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_invitemask = sqlite3_column_int64(stmt, 0);
	out->id_channel = sqlite3_column_int64(stmt, 1);
	strcpy(out->orig_mask, (const char *)sqlite3_column_text(stmt, 2));
	strcpy(out->mask, (const char *)sqlite3_column_text(stmt, 3));

	return 0;
}

int db_get_invite(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client, struct db_invite *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM invite WHERE id_channel = ? AND id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, id_client) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	out->id_channel = id_channel;
	out->id_client = id_client;

	return 0;
}

int db_get_whowas(sqlite3 *db, sqlite3_int64 id, struct db_whowas *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM whowas WHERE id_whowas = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_whowas_from_row(stmt, out, 0);
	return 0;
}

int db_add_forbidden_nick(sqlite3 *db, struct db_forbidden_nick *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO forbidden_nick (nickname, expiry) VALUES (?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, in->nickname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(in->expiry)) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;
	in->id_nick = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_add_expiring_forbidden_nick(sqlite3 *db, const char *nickname, int seconds)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO forbidden_nick (nickname, expiry) VALUES (?, strftime('%s') + ?);";

	FINALIZE_IF_DB_NULL();

	if (seconds < 0)
		return 1;

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, nickname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 2, seconds) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_del_forbidden_nick(sqlite3 *db, const char *nickname)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM forbidden_nick WHERE nickname = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, nickname, -1, SQLITE_STATIC) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_del_expired_forbidden_nicks(sqlite3 *db)
{
	static sqlite3_stmt *stmt;
	/* +0 forces integer conversion, so it's not a string comparison. */
	static const char query[] = "DELETE FROM forbidden_nick WHERE expiry != 0 AND strftime('%s') + 0 >= expiry;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_nickname_is_forbidden(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE])
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM forbidden_nick WHERE nickname = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, nickname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0) > 0;
}

int db_nickname_available(sqlite3 *db, const char nickname[NICKNAME_BUFFER_SIZE])
{
	struct db_client cli;

	if (db == NULL)
		return 0;

	return (! db_nickname_is_forbidden(db, nickname) &&
		db_get_client_by_nick(db, nickname, &cli) != 0);
}

int db_add_operator(sqlite3 *db, struct db_operator *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO operator (username, password) VALUES (?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, in->username, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, in->password, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;
	in->id_oper = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_add_client(sqlite3 *db, struct db_client *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"INSERT INTO client "
		"(id_oper, fd, ip, port, orig_nickname, nickname, username, "
		"realname, orig_fullname, fullname, away_flag, away_text, "
		"invisible_flag, wallops_flag, restricted_flag, "
		"operator_flag, local_operator_flag, server_notices_flag, "
		"array_index, regstate, last_activity, last_ping, "
		"last_talk, signon_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	db_bind_client_data(stmt, in);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;

	in->id_client = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_del_client(sqlite3 *db, const struct db_client *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM client WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_client) == SQLITE_OK);
	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_modify_client(sqlite3 *db, const struct db_client *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"UPDATE client SET "
		"id_oper = ?, fd = ?, ip = ?, port = ?, orig_nickname = ?, "
		"nickname = ?, username = ?, realname = ?, orig_fullname = ?, "
		"fullname = ?, away_flag = ?, away_text = ?, "
		"invisible_flag = ?, wallops_flag = ?, restricted_flag = ?, "
		"operator_flag = ?, local_operator_flag = ?, "
		"server_notices_flag = ?, array_index = ?, regstate = ?, "
		"last_activity = ?, last_ping = ?, last_talk = ?, "
		"signon_time = ? WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	db_bind_client_data(stmt, in);
	assert(sqlite3_bind_int64(stmt, 25, in->id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_update_client_activity(sqlite3 *db, sqlite3_int64 cli)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "UPDATE client SET last_activity = strftime('%s') WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_update_client_ping(sqlite3 *db, sqlite3_int64 cli)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "UPDATE client SET last_ping = strftime('%s') WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_add_channel(sqlite3 *db, struct db_channel *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"INSERT INTO channel "
		"(orig_name, name, topic, key_flag, key, limit_flag, "
		"limit_v, anonymous_flag, invite_only_flag, moderated_flag, "
		"no_outside_flag, quiet_flag, private_flag, secret_flag, "
		"oper_topic_flag, special_flag) VALUES "
		"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	db_bind_channel_data(stmt, in);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;

	in->id_channel = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_del_channel(sqlite3 *db, const struct db_channel *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM channel WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_channel) == SQLITE_OK);
	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_modify_channel(sqlite3 *db, const struct db_channel *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"UPDATE channel SET "
		"orig_name = ?, name = ?, topic = ?, "
		"key_flag = ?, key = ?, limit_flag = ?, limit_v = ?, "
		"anonymous_flag = ?, invite_only_flag = ?, moderated_flag = ?, "
		"no_outside_flag = ?, quiet_flag = ?, private_flag = ?, "
		"secret_flag = ?, oper_topic_flag = ?, special_flag = ? "
		"WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	db_bind_channel_data(stmt, in);
	assert(sqlite3_bind_int64(stmt, 17, in->id_channel) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_add_banmask(sqlite3 *db, struct db_banmask *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO banmask (id_channel, orig_mask, mask) VALUES (?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, in->orig_mask, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 3, in->mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;
	in->id_banmask = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_add_exceptmask(sqlite3 *db, struct db_exceptmask *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO exceptmask (id_channel, orig_mask, mask) VALUES (?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, in->orig_mask, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 3, in->mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;
	in->id_exceptmask = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_add_invitemask(sqlite3 *db, struct db_invitemask *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO invitemask (id_channel, orig_mask, mask) VALUES (?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, in->orig_mask, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 3, in->mask, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		return 1;
	in->id_invitemask = sqlite3_last_insert_rowid(db);
	return 0;
}

int db_del_banmask(sqlite3 *db, const struct db_banmask *mask)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM banmask WHERE id_channel = ? AND id_banmask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, mask->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, mask->id_banmask) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_del_exceptmask(sqlite3 *db, const struct db_exceptmask *mask)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM exceptmask WHERE id_channel = ? AND id_exceptmask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, mask->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, mask->id_exceptmask) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_del_invitemask(sqlite3 *db, const struct db_invitemask *mask)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM invitemask WHERE id_channel = ? AND id_invitemask = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, mask->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, mask->id_invitemask) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_count_banmasks(sqlite3 *db, sqlite3_int64 chan)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM banmask WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_exceptmasks(sqlite3 *db, sqlite3_int64 chan)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM exceptmask WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_invitemasks(sqlite3 *db, sqlite3_int64 chan)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM invitemask WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_get_client_by_fd(sqlite3 *db, int fd, struct db_client *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE fd = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int(stmt, 1, fd) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_client_from_row(stmt, out, 0);

	return 0;
}

int db_get_client_by_nick(sqlite3 *db, const char *nickname, struct db_client *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE nickname = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, nickname, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_client_from_row(stmt, out, 0);

	return 0;
}

int db_get_client_by_opid(sqlite3 *db, sqlite3_int64 id, struct db_client *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE id_oper = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_client_from_row(stmt, out, 0);

	return 0;
}

int db_get_operator_id(sqlite3 *db, const char *un, const char *pw, sqlite3_int64 *id)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT id_oper FROM operator WHERE username = ? AND password = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, un, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, pw, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	*id = sqlite3_column_int64(stmt, 0);

	return 0;
}

int db_get_channel_by_name(sqlite3 *db, const char *name, struct db_channel *out)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM channel WHERE name = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) == SQLITE_OK);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return 1;

	db_fill_channel_from_row(stmt, out, 0);

	return 0;
}

int db_count_client_channels(sqlite3 *db, sqlite3_int64 id_client)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM membership WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_client) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_channel_members(sqlite3 *db, sqlite3_int64 id_channel)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM membership WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_visible_members(sqlite3 *db, sqlite3_int64 id_channel)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT COUNT(*) FROM "
		"	membership INNER JOIN client "
		"	ON membership.id_client = client.id_client "
		"	WHERE membership.id_channel = ? AND client.invisible_flag = 0;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_channels(sqlite3 *db)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM channel WHERE special_flag = 0;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_clients(sqlite3 *db)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM client;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_count_client_operators(sqlite3 *db)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT COUNT(*) FROM client WHERE operator_flag = 1 OR local_operator_flag = 1;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_step(stmt) == SQLITE_ROW);
	return sqlite3_column_int(stmt, 0);
}

int db_add_membership(sqlite3 *db, const struct db_membership *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"INSERT INTO membership "
		"(id_channel, id_client, operator_flag, voice_flag) "
		"VALUES (?, ?, ?, ?);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, in->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, in->id_client) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 3, in->operator_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 4, in->voice_flag) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_modify_membership(sqlite3 *db, const struct db_membership *in)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"UPDATE membership SET "
		"operator_flag = ?, voice_flag = ? "
		"WHERE id_channel = ? AND id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int(stmt, 1, in->operator_flag) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 2, in->voice_flag) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 3, in->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 4, in->id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_delete_membership(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM membership WHERE id_channel = ? AND id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_delete_client_memberships(sqlite3 *db, sqlite3_int64 id_client)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM membership WHERE id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_client_can_invite(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan)
{
	struct db_membership memb;
	int ret;

	if (db == NULL)
		return 0;

	ret = db_get_membership(db, chan->id_channel, cli->id_client, &memb);
	if (ret != 0)
		return 0;		/* User not in channel. */
	if (! chan->invite_only_flag)
		return 1;		/* Any member may invite. */
	return memb.operator_flag;	/* Only operators can. */
}

int db_invite_client(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "INSERT INTO invite (id_channel, id_client) VALUES (?, ?);";

	struct db_invite invite;
	int ret;

	FINALIZE_IF_DB_NULL();

	ret = db_get_invite(db, id_channel, id_client, &invite);
	if (ret == 0)
		return 0;	/* User was already invited. */

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_del_invite(sqlite3 *db, sqlite3_int64 id_channel, sqlite3_int64 id_client)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM invite WHERE id_channel = ? AND id_client = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, id_client) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_clear_all_invites(sqlite3 *db, sqlite3_int64 id_channel)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM invite WHERE id_channel = ?;";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, id_channel) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_client_not_banned(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT "
		"((SELECT COUNT(*) FROM banmask WHERE id_channel = ? AND (? GLOB mask)) = 0) OR "
		"((SELECT COUNT(*) FROM exceptmask WHERE id_channel = ? AND (? GLOB mask)) > 0);";

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, cli->fullname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 3, chan->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 4, cli->fullname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);

	return sqlite3_column_int(stmt, 0);
}

int db_client_meets_invite_req(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT "
		"((SELECT COUNT(*) FROM invitemask WHERE id_channel = ? AND (? GLOB mask)) > 0) OR "
		"((SELECT COUNT(*) FROM invite WHERE id_channel = ? AND id_client = ?) > 0);";

	FINALIZE_IF_DB_NULL();

	if (! chan->invite_only_flag)
		return 1;

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 2, cli->fullname, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 3, chan->id_channel) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 4, cli->id_client) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_ROW);

	return sqlite3_column_int(stmt, 0);
}

int db_client_may_join(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan, const char *key)
{
	/*
	 * A user may join a channel if:
	 *	Not already in, and
	 *	User is a network operator, or
	 *	Key matches, if applicable, and
	 *	User limit not reached, and
	 *	User meets invite requirements, and
	 *	User is not banned.
	 */
	struct db_membership memb;
	struct db_invite inv;

	if (db == NULL)
		return 0;

	if (db_get_membership(db, chan->id_channel, cli->id_client, &memb) == 0)
		return -1;

	if (cli->operator_flag || cli->local_operator_flag)
		return 0;

	if (chan->special_flag)
		return ERR_NOPRIVILEGES;

	if (chan->key_flag && (key == NULL || strcmp(chan->key, key) != 0))
		return ERR_BADCHANNELKEY;

	if (chan->limit_flag && db_count_channel_members(db, chan->id_channel) >= chan->limit_v)
		return ERR_CHANNELISFULL;

	if (! db_client_meets_invite_req(db, cli, chan))
		return ERR_INVITEONLYCHAN;

	if (db_client_not_banned(db, cli, chan))
		return 0;

	if (db_get_invite(db, chan->id_channel, cli->id_client, &inv) == 0)
		/* Personal invitation found. */
		return 0;

	return ERR_BANNEDFROMCHAN;
}

int db_client_may_talk(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan)
{
	struct db_membership memb;

	if (db == NULL)
		return 0;

	if (chan->quiet_flag)
		return 0;

	if (db_get_membership(db, chan->id_channel, cli->id_client, &memb) == 0) {
		/* User in channel. */
		if (memb.operator_flag || memb.voice_flag)
			return 1;
		return (! chan->moderated_flag) && db_client_not_banned(db, cli, chan);
	}

	/* User not in channel. */
	if (chan->no_outside_flag || chan->moderated_flag)
		return 0;
	return db_client_not_banned(db, cli, chan);
}

int db_client_may_set_topic(sqlite3 *db, const struct db_client *cli, const struct db_channel *chan)
{
	struct db_membership memb;

	if (db == NULL)
		return 0;

	if (db_get_membership(db, chan->id_channel, cli->id_client, &memb) != 0)
		return 0; /* Non-members cannot set topic. */

	return (memb.operator_flag || (! chan->oper_topic_flag));
}

int db_clear_whowas(sqlite3 *db, int seconds)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "DELETE FROM whowas WHERE quit_time <= strftime('%s') - ?;";

	FINALIZE_IF_DB_NULL();

	if (seconds < 0)
		return 1;

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int(stmt, 1, seconds) == SQLITE_OK);

	return (sqlite3_step(stmt) != SQLITE_DONE);
}

int db_run_on_members_except(sqlite3 *db, sqlite3_int64 chan, sqlite3_int64 cli,
			     db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT client.* FROM membership INNER JOIN client ON "
		"membership.id_client = client.id_client WHERE "
		"membership.id_channel = ? AND membership.id_client != ?;";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, cli) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_members(sqlite3 *db, sqlite3_int64 chan, db_callback callback, void *extra)
{
	/*
	 * Note: sqlite ROWID starts at one. Zero will not match any client and
	 * none will be excluded.
	 */ 
	return db_run_on_members_except(db, chan, 0, callback, extra);
}

int db_run_on_neighbors(sqlite3 *db, sqlite3_int64 cli, db_callback callback, void *extra)
{
	/* The following query has proved to be faster and less memory-hungry
	 * on a variety of scenarios than other alternative queries. A faster
	 * query is always welcome, though. */
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT * FROM client WHERE client.id_client != ? AND client.id_client IN "
		"(SELECT id_client FROM membership WHERE membership.id_channel IN "
		"(SELECT membership.id_channel FROM membership INNER JOIN channel ON "
		" membership.id_channel = channel.id_channel "
		" WHERE membership.id_client = ? AND "
		"       channel.quiet_flag = 0));";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, cli) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_non_anon_neighbors(sqlite3 *db, sqlite3_int64 cli, db_callback callback, void *extra)
{
	/* The following query has proved to be faster and less memory-hungry
	 * on a variety of scenarios than other alternative queries. A faster
	 * query is always welcome, though. */
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT * FROM client WHERE client.id_client != ? AND client.id_client IN "
		"(SELECT id_client FROM membership WHERE membership.id_channel IN "
		"(SELECT membership.id_channel FROM membership INNER JOIN channel ON "
		" membership.id_channel = channel.id_channel "
		" WHERE membership.id_client = ? AND "
		"       channel.anonymous_flag = 0 AND "
		"       channel.quiet_flag = 0));";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, cli) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_anon_neighbors(sqlite3 *db, sqlite3_int64 cli, db_callback callback, void *extra)
{
	/* Like the previous query, this has proved to be reasonably fast and
	 * not to use a lot of memory, but a better query is always welcome. */
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT client.*,channel.* FROM "
		"membership INNER JOIN client INNER JOIN channel "
		"ON membership.id_channel = channel.id_channel AND "
		"   membership.id_client = client.id_client "
		"WHERE client.id_client != ? AND "
		"      channel.anonymous_flag = 1 AND "
		"      channel.quiet_flag = 0 AND membership.id_channel IN "
		" (SELECT id_channel FROM membership WHERE id_client = ?);";

	int ret;
	struct db_client_channel cc;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);
	assert(sqlite3_bind_int64(stmt, 2, cli) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client and channel data and run callback on it. */
		db_fill_client_from_row(stmt, &(cc.client), 0);
		db_fill_channel_from_row(stmt, &(cc.channel), 25);
		callback((void *)(&cc), extra);
	}
	
	return 0;
}

int db_run_on_banmasks(sqlite3 *db, sqlite3_int64 chan, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM banmask WHERE id_channel = ?;";

	int ret;
	struct db_banmask mask;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		mask.id_banmask = sqlite3_column_int64(stmt, 0);
		mask.id_channel = sqlite3_column_int64(stmt, 1);
		strcpy(mask.orig_mask, (const char *)sqlite3_column_text(stmt, 2));
		strcpy(mask.mask, (const char *)sqlite3_column_text(stmt, 3));

		callback((void *)(&mask), extra);
	}
	
	return 0;
}

int db_run_on_exceptmasks(sqlite3 *db, sqlite3_int64 chan, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM exceptmask WHERE id_channel = ?;";

	int ret;
	struct db_exceptmask mask;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		mask.id_exceptmask = sqlite3_column_int64(stmt, 0);
		mask.id_channel = sqlite3_column_int64(stmt, 1);
		strcpy(mask.orig_mask, (const char *)sqlite3_column_text(stmt, 2));
		strcpy(mask.mask, (const char *)sqlite3_column_text(stmt, 3));

		callback((void *)(&mask), extra);
	}
	
	return 0;
}

int db_run_on_invitemasks(sqlite3 *db, sqlite3_int64 chan, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM invitemask WHERE id_channel = ?;";

	int ret;
	struct db_invitemask mask;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, chan) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		mask.id_invitemask = sqlite3_column_int64(stmt, 0);
		mask.id_channel = sqlite3_column_int64(stmt, 1);
		strcpy(mask.orig_mask, (const char *)sqlite3_column_text(stmt, 2));
		strcpy(mask.mask, (const char *)sqlite3_column_text(stmt, 3));

		callback((void *)(&mask), extra);
	}
	
	return 0;
}

int db_run_on_whowas(sqlite3 *db, const char *nick, int count, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM whowas WHERE nickname = ? ORDER BY quit_time DESC LIMIT ?;";

	int ret;
	struct db_whowas dbw;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_text(stmt, 1, nick, -1, SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 2, count) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get whowas data and run callback on it. */
		db_fill_whowas_from_row(stmt, &dbw, 0);
		callback((void *)(&dbw), extra);
	}
	
	return 0;
}

int db_run_on_wallops(sqlite3 *db, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE wallops_flag = 1;";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_client_channels(sqlite3 *db, sqlite3_int64 cli, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] =
		"SELECT channel.* FROM membership INNER JOIN channel "
		" ON membership.id_channel = channel.id_channel "
		" WHERE membership.id_client = ?;";

	int ret;
	struct db_channel chan;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int64(stmt, 1, cli) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get channel data and run callback on it. */
		db_fill_channel_from_row(stmt, &chan, 0);
		callback((void *)(&chan), extra);
	}
	
	return 0;
}

int db_run_on_ping_timeout_clients(sqlite3 *db, int seconds, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE last_ping != 0 AND strftime('%s') - ? > last_ping;";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int(stmt, 1, seconds) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_inactive_clients(sqlite3 *db, int seconds, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client WHERE last_ping = 0 AND strftime('%s') - ? > last_activity;";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);
	assert(sqlite3_bind_int(stmt, 1, seconds) == SQLITE_OK);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

int db_run_on_clients(sqlite3 *db, db_callback callback, void *extra)
{
	static sqlite3_stmt *stmt;
	static const char query[] = "SELECT * FROM client;";

	int ret;
	struct db_client dbcli;

	FINALIZE_IF_DB_NULL();

	PREPARE_IF_STMT_NULL();

	sqlite3_reset(stmt);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE)
			return 1;
		if (ret == SQLITE_DONE)
			break;

		/* Get client data and run callback on it. */
		db_fill_client_from_row(stmt, &dbcli, 0);
		callback((void *)(&dbcli), extra);
	}
	
	return 0;
}

