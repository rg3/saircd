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
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3.h>

#include "messages.h"
#include "database.h"
#include "util.h"

sqlite3 *db;
sqlite3_int64 id_oper;
sqlite3_int64 id_client;

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

	printf("Database test: %.1f%% passed (failed %d out of %d tests)\n",
	       percentage, tests_failed, tests_counter);

	return (tests_passed == tests_counter)?0:1;
}

void test_get_forbidden_nicks(void)
{
	struct db_forbidden_nick fn;

	++tests_counter;
	if (db_get_forbidden_nick(db, 1, &fn) != 0 ||
	    fn.id_nick != 1 ||
	    strcmp(fn.nickname, "root") != 0 ||
	    fn.expiry != 0) {
		printf("Unexpected data trying to get \"root\" forbidden nick\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_get_forbidden_nick(db, 2, &fn) != 0 ||
	    fn.id_nick != 2 ||
	    strcmp(fn.nickname, "anonymous") != 0 ||
	    fn.expiry != 0) {
		printf("Unexpected data trying to get \"anonymous\" forbidden nick\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_forbidden_check(void)
{
	++tests_counter;
	if (! db_nickname_is_forbidden(db, "root") ||
	    ! db_nickname_is_forbidden(db, "anonymous") ||
	    db_nickname_is_forbidden(db, "nonforb")) {
		printf("Forbidden nickname check failed\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_add_del_forbidden_nicks(void)
{
	struct db_forbidden_nick fn;

	strcpy(fn.nickname, "nobody");
	fn.expiry = 0;

	++tests_counter;
	if (db_add_forbidden_nick(db, &fn) != 0) {
		printf("Unable to add forbidden nick before deletion\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (! db_nickname_is_forbidden(db, fn.nickname)) {
		printf("Forbidden nickname was not added properly\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_forbidden_nick(db, fn.nickname) != 0) {
		printf("Forbidden nickname was not removed properly\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_add_expiring_forbidden_nick(db, fn.nickname, 0) != 0) {
		printf("Unable to add forbidden expiring nickname\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (! db_nickname_is_forbidden(db, fn.nickname)) {
		printf("Forbidden expiring nickname was not added properly\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_expired_forbidden_nicks(db) != 0) {
		printf("Unable to delete expired forbidden nicknames\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_nickname_is_forbidden(db, fn.nickname)) {
		printf("Expired forbidden nickname was not deleted properly\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_add_get_operator(void)
{
	struct db_operator op;
	sqlite3_int64 aux;

	strcpy(op.username, "oper1");
	strcpy(op.password, "pass1");

	++tests_counter;
	if (db_add_operator(db, &op) != 0) {
		printf("Unable to insert new operator\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	id_oper = op.id_oper;
	memset(&op, 0, sizeof(op));

	++tests_counter;
	if (db_get_operator(db, id_oper, &op) != 0 ||
	    strcmp(op.username, "oper1") != 0 ||
	    strcmp(op.password, "pass1") != 0) {
		printf("Unable to get inserted operator\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_get_operator_id(db, "oper1", "pass1", &aux) != 0 ||
	    aux != id_oper) {
		printf("Unable to get operator ID by username and password\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_get_operator_id(db, "oper2", "pass1", &aux) == 0 ||
	    db_get_operator_id(db, "oper1", "pass2", &aux) == 0) {
		printf("Got operator ID with wrong username or password\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void test_add_get_client(void)
{
	const int fdval = 11;

	struct db_client cli;
	struct db_client cli2;
	struct db_client cli3;
	struct db_client cli4;
	struct db_client cli5;
	struct db_client cli6;

	char orig_nickname[NICKNAME_BUFFER_SIZE];

	strcpy(orig_nickname, "cLiEnT1");

	memset(&cli, 0, sizeof(cli));
	cli.fd = fdval;
	strcpy(cli.ip, "192.168.1.51");
	cli.port = 32767;
	cli.regstate = 9;
	strcpy(cli.orig_nickname, orig_nickname);
	strcpy(cli.nickname, cli.orig_nickname);
	irclower(cli.nickname);
	strcpy(cli.username, "resu");
	strcpy(cli.realname, "Iñigo Montoya"); /* You killed my father. Prepare to die. */
	sprintf(cli.orig_fullname, "%s!%s@%s", orig_nickname, cli.username, cli.ip);
	strcpy(cli.fullname, cli.orig_fullname);
	irclower(cli.fullname);
	cli.away_flag = 0;
	cli.away_text[0] = '\0';
	cli.invisible_flag = 1;
	cli.wallops_flag = 0;
	cli.restricted_flag = 1;
	cli.operator_flag = 0;
	cli.local_operator_flag = 1;
	cli.server_notices_flag = 0;
	cli.last_activity = 0;
	cli.last_ping = 0;
	cli.id_oper = id_oper;

	++tests_counter;
	if (! db_nickname_available(db, cli.nickname)) {
		printf("Unused nickname appears not to be available\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_add_client(db, &cli) != 0) {
		printf("Unable to add client\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_nickname_available(db, cli.nickname)) {
		printf("Used nickname is not unavailable\n");
		++tests_failed;
	} else
		++tests_passed;

	id_client = cli.id_client;
	memset(&cli2, 0, sizeof(cli2));

	++tests_counter;
	if (db_get_client(db, id_client, &cli2) != 0 ||
	    memcmp(&cli, &cli2, sizeof(struct db_client)) != 0) {
		printf("Unable to retrieve added client by ID\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	memset(&cli3, 0, sizeof(cli3));

	++tests_counter;
	if (db_get_client_by_nick(db, cli.nickname, &cli3) != 0 ||
	    memcmp(&cli, &cli3, sizeof(struct db_client)) != 0) {
		printf("Unable to retrieve added client by nick\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	memset(&cli4, 0, sizeof(cli4));
	
	++tests_counter;
	if (db_get_client_by_fd(db, fdval, &cli4) != 0 ||
	    memcmp(&cli, &cli4, sizeof(struct db_client)) != 0) {
		printf("Unable to retrieve added client by file descriptor\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	memset(&cli5, 0, sizeof(cli5));

	++tests_counter;
	if (db_get_client_by_opid(db, id_oper, &cli5) != 0 ||
	    memcmp(&cli, &cli5, sizeof(struct db_client)) != 0) {
		printf("Unable to retrieve added client by operator ID\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	memset(&cli6, 0, sizeof(cli6));

	++tests_counter;
	if (db_get_client(db, id_client+1, &cli6) == 0 ||
	    db_get_client_by_nick(db, "anonymous", &cli6) == 0 ||
	    db_get_client_by_fd(db, fdval+1, &cli6) == 0 ||
	    db_get_client_by_opid(db, id_oper+1, &cli6) == 0) {
		printf("Got valid client data with invalid input\n");
		++tests_failed;
	} else {
		++tests_passed;
	}
}

void wallops_callback(void *row, void *extra)
{
	struct db_client *cli;
	struct db_client *ref;

	cli = (struct db_client *)row;
	ref = (struct db_client *)extra;

	++tests_counter;
	if (cli->id_client != ref->id_client ||
	    cli->id_oper != ref->id_oper ||
	    strcmp(cli->ip, ref->ip) != 0 ||
	    cli->port != ref->port ||
	    strcmp(cli->orig_nickname, ref->orig_nickname) != 0 ||
	    strcmp(cli->nickname, ref->nickname) != 0 ||
	    strcmp(cli->username, ref->username) != 0 ||
	    strcmp(cli->realname, ref->realname) != 0 ||
	    strcmp(cli->orig_fullname, ref->orig_fullname) != 0 ||
	    cli->away_flag != ref->away_flag ||
	    strcmp(cli->away_text, ref->away_text) != 0 ||
	    cli->invisible_flag != ref->invisible_flag ||
	    cli->wallops_flag != ref->wallops_flag ||
	    cli->restricted_flag != ref->restricted_flag ||
	    cli->operator_flag != ref->operator_flag ||
	    cli->local_operator_flag != ref->local_operator_flag ||
	    cli->server_notices_flag != ref->server_notices_flag ||
	    cli->array_index != ref->array_index || 
	    cli->regstate != ref->regstate ||
	    cli->last_activity != ref->last_activity ||
	    cli->last_ping != ref->last_ping ||
	    cli->signon_time != ref->signon_time) {
		printf("Unexpected data on wallops callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_get_modify_client(void)
{
	struct db_client cli;
	struct db_client cli2;
	time_t now;

	memset(&cli, 0, sizeof(cli));
	memset(&cli2, 0, sizeof(cli2));

	++tests_counter;
	if (db_get_client(db, id_client, &cli) != 0) {
		printf("Unable to retrieve client by ID before modification\n");
		++tests_failed;
	} else
		++tests_passed;

	cli.away_flag = 1;
	strcpy(cli.away_text, "afk, tornado");
	cli.invisible_flag = 0;
	cli.wallops_flag = 1;
	cli.restricted_flag = 0;
	cli.operator_flag = 1;
	cli.local_operator_flag = 0;
	cli.server_notices_flag = 1;
	cli.last_activity = 0;
	cli.last_ping = 0;
	cli.id_oper = id_oper;
	cli.is_quitting = 1;

	++tests_counter;
	if (db_modify_client(db, &cli) != 0) {
		printf("Unable to modify client\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_client(db, id_client, &cli2) != 0 ||
	    memcmp(&cli, &cli2, sizeof(struct db_client)) != 0) {
		printf("Unable to retrieve modified client\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_client_operators(db) != 1) {
		printf("Unable to correctly count client operators\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_run_on_wallops(db, wallops_callback, &cli) != 0) {
		printf("Error running wallops callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_update_client_activity(db, id_client) != 0 ||
	    db_update_client_ping(db, id_client) != 0) {
		printf("Unable to update activity or ping client time\n");
		++tests_failed;
	} else
		++tests_passed;

	now = time(NULL);

	++tests_counter;
	if (db_get_client(db, id_client, &cli2) != 0 ||
	    cli2.last_activity < now - 1 ||
	    cli2.last_ping < now - 1) {
		printf("Client activity and ping times not updated properly\n");
		++tests_failed;
	} else
		++tests_passed;
}

void row_count_callback(void *row, void *extra)
{
	UNUSED(row);
	++(*(int *)(extra));
}

void whowas_callback(void *row, void *extra)
{
	struct db_whowas *ww;
	struct db_client *cli;

	ww = (struct db_whowas *)row;
	cli = (struct db_client *)extra;

	++tests_counter;
	if (strcmp(ww->orig_nickname, cli->orig_nickname) != 0 ||
	    strcmp(ww->nickname, cli->nickname) != 0 ||
	    strcmp(ww->username, cli->username) != 0 ||
	    strcmp(ww->ip, cli->ip) != 0 ||
	    strcmp(ww->realname, cli->realname) != 0) {
		printf("Unexpected data on whowas callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_count_del_client(void)
{
	struct db_client cli;
	struct db_whowas ww;
	time_t now;
	int counter;

	++tests_counter;
	if (db_count_clients(db) != 1) {
		printf("Got wrong number counting clients\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_get_client(db, id_client, &cli) != 0) {
		printf("Unable to get client before deletion\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_client(db, &cli) != 0) {
		printf("Unable to delete known client\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	++tests_counter;
	if (db_count_clients(db) != 0) {
		printf("Got wrong number counting clients after deletion\n");
		++tests_failed;
	} else {
		++tests_passed;
	}

	/* The nick should have been autoinserted in the whowas table. */
	++tests_counter;
	now = time(NULL);
	if (db_get_whowas(db, sqlite3_last_insert_rowid(db), &ww) != 0 ||
	    strcmp(ww.orig_nickname, cli.orig_nickname) != 0 ||
	    strcmp(ww.nickname, cli.nickname) != 0 ||
	    strcmp(ww.username, cli.username) != 0 ||
	    strcmp(ww.ip, cli.ip) != 0 ||
	    strcmp(ww.realname, cli.realname) != 0 ||
	    ww.quit_time < now - 1 ||
	    ww.quit_time > now) {
		printf("Deleted nickname did not properly appear in the whowas table\n");
		++tests_failed;
	} else
		++tests_passed;

	/* Try to check that with a callback too. */
	++tests_counter;
	if (db_run_on_whowas(db, cli.nickname, -1, whowas_callback, &cli) != 0) {
		printf("Error running whowas callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_clear_whowas(db, 0) != 0) {
		printf("Unable to clear whowas items\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;
	++tests_counter;
	if (db_run_on_whowas(db, cli.nickname, -1, row_count_callback, &counter) != 0 ||
	    counter != 0) {
		printf("Whowas table not empty after total clear\n");
		++tests_failed;
	} else
		++tests_passed;
}

void banmask_callback(void *row, void *extra)
{
	struct db_banmask *cur;
	struct db_banmask *ref;

	cur = (struct db_banmask *)row;
	ref = (struct db_banmask *)extra;

	++tests_counter;
	if (cur->id_banmask != ref->id_banmask ||
	    cur->id_channel != ref->id_channel ||
	    strcmp(cur->orig_mask, ref->orig_mask) != 0 ||
	    strcmp(cur->mask, ref->mask) != 0) {
		printf("Unexpected data in banmask callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void exceptmask_callback(void *row, void *extra)
{
	struct db_exceptmask *cur;
	struct db_exceptmask *ref;

	cur = (struct db_exceptmask *)row;
	ref = (struct db_exceptmask *)extra;

	++tests_counter;
	if (cur->id_exceptmask != ref->id_exceptmask ||
	    cur->id_channel != ref->id_channel ||
	    strcmp(cur->orig_mask, ref->orig_mask) != 0 ||
	    strcmp(cur->mask, ref->mask) != 0) {
		printf("Unexpected data in exceptmask callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void invitemask_callback(void *row, void *extra)
{
	struct db_invitemask *cur;
	struct db_invitemask *ref;

	cur = (struct db_invitemask *)row;
	ref = (struct db_invitemask *)extra;

	++tests_counter;
	if (cur->id_invitemask != ref->id_invitemask ||
	    cur->id_channel != ref->id_channel ||
	    strcmp(cur->orig_mask, ref->orig_mask) != 0 ||
	    strcmp(cur->mask, ref->mask) != 0) {
		printf("Unexpected data in invitemask callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_channel_masks(void)
{
	struct db_channel chan;
	struct db_channel chan2;

	struct db_banmask bm1;
	struct db_banmask bm2;
	struct db_exceptmask em1;
	struct db_exceptmask em2;
	struct db_invitemask im1;
	struct db_invitemask im2;

	int counter;

	memset(&chan, 0, sizeof(chan));
	strcpy(chan.orig_name, "#ABC123[]\\~");
	strcpy(chan.name, chan.orig_name);
	irclower(chan.name);
	strcpy(chan.topic, "Channel topic");
	chan.key_flag = 0;
	chan.key[0] = '\0';
	chan.limit_flag = 0;
	chan.limit_v = 0;
	chan.anonymous_flag = 0;
	chan.invite_only_flag = 1;
	chan.moderated_flag = 0;
	chan.no_outside_flag = 1;
	chan.quiet_flag = 0;
	chan.secret_flag = 1;
	chan.oper_topic_flag = 1;
	chan.special_flag = 0;

	++tests_counter;
	if (strcmp(chan.name, "#abc123{}|^") != 0) {
		printf("Unexpected lowercase conversion in channel name\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_channels(db) != 0) {
		printf("Unexpected nonzero channel count\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_add_channel(db, &chan) != 0) {
		printf("Unable to add channel to database\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_channels(db) != 1) {
		printf("Unexpected value when counting one channel\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&chan2, 0, sizeof(chan2));

	++tests_counter;
	if (db_get_channel(db, chan.id_channel, &chan2) != 0 ||
	    memcmp(&chan, &chan2, sizeof(struct db_channel)) != 0) {
		printf("Unable to properly get channel by ID\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.key_flag = 1;
	strcpy(chan.key, "TeSt");
	chan.limit_flag = 0;
	chan.limit_v = 0;
	chan.anonymous_flag = 1;
	chan.invite_only_flag = 0;
	chan.moderated_flag = 1;
	chan.no_outside_flag = 0;
	chan.quiet_flag = 1;
	chan.private_flag = 1;
	chan.secret_flag = 0;
	chan.oper_topic_flag = 1;
	chan.special_flag = 0;

	++tests_counter;
	if (db_modify_channel(db, &chan) != 0) {
		printf("Unable to modify channel\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&chan2, 0, sizeof(chan2));

	++tests_counter;
	if (db_get_channel_by_name(db, chan.name, &chan2) != 0 ||
	    memcmp(&chan, &chan2, sizeof(struct db_channel)) != 0) {
		printf("Unable to properly get channel by name\n");
		++tests_failed;
	} else
		++tests_passed;

	/* Banmask. */

	memset(&bm1, 0, sizeof(bm1));
	bm1.id_channel = chan.id_channel;
	strcpy(bm1.orig_mask, "USER*!*@*");
	strcpy(bm1.mask, bm1.orig_mask);
	irclower(bm1.mask);

	++tests_counter;
	if (db_add_banmask(db, &bm1) != 0) {
		printf("Unable to add channel banmask\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_banmask_by_mask(db, bm1.id_channel, bm1.mask, &bm1) != 0) {
		printf("Unable to retrieve recently added banmask\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&bm2, 0, sizeof(bm2));

	++tests_counter;
	if (db_get_banmask(db, bm1.id_banmask, &bm2) != 0 ||
	    memcmp(&bm1, &bm2, sizeof(struct db_banmask)) != 0) {
		printf("Unable to retrieve banmask by ID\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_run_on_banmasks(db, bm1.id_channel, banmask_callback, &bm1) != 0) {
		printf("Error running banmask callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_banmasks(db, bm1.id_channel) != 1) {
		printf("Unexpected value counting banmasks\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_banmask(db, &bm1) != 0) {
		printf("Unable to delete channel banmask\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;

	++tests_counter;
	if (db_run_on_banmasks(db, bm1.id_channel, row_count_callback, &counter) != 0 ||
	    counter != 0) {
		printf("Error running banmask counter callback\n");
		++tests_failed;
	} else
		++tests_passed;

	/* Exceptmask. */

	memset(&em1, 0, sizeof(em1));
	em1.id_channel = chan.id_channel;
	strcpy(em1.orig_mask, "*!*@192.168.1.*");
	strcpy(em1.mask, em1.orig_mask);
	irclower(em1.mask);

	++tests_counter;
	if (db_add_exceptmask(db, &em1) != 0) {
		printf("Unable to add channel exceptmask\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_exceptmask_by_mask(db, em1.id_channel, em1.mask, &em1) != 0) {
		printf("Unable to retrieve recently added exceptmask\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&em2, 0, sizeof(em2));

	++tests_counter;
	if (db_get_exceptmask(db, em1.id_exceptmask, &em2) != 0 ||
	    memcmp(&em1, &em2, sizeof(struct db_exceptmask)) != 0) {
		printf("Unable to retrieve exceptmask by ID\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_run_on_exceptmasks(db, em1.id_channel, exceptmask_callback, &em1) != 0) {
		printf("Error running exceptmask callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_exceptmasks(db, em1.id_channel) != 1) {
		printf("Unexpected value counting exceptmasks\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_exceptmask(db, &em1) != 0) {
		printf("Unable to delete channel exceptmask\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;

	++tests_counter;
	if (db_run_on_exceptmasks(db, em1.id_channel, row_count_callback, &counter) != 0 ||
	    counter != 0) {
		printf("Error running exceptmask counter callback\n");
		++tests_failed;
	} else
		++tests_passed;

	/* Invitemask. */

	memset(&im1, 0, sizeof(im1));
	im1.id_channel = chan.id_channel;
	strcpy(im1.orig_mask, "*!*vampire*@*");
	strcpy(im1.mask, im1.orig_mask);
	irclower(im1.mask);

	++tests_counter;
	if (db_add_invitemask(db, &im1) != 0) {
		printf("Unable to add channel invitemask\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_invitemask_by_mask(db, im1.id_channel, im1.mask, &im1) != 0) {
		printf("Unable to retrieve recently added invitemask\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&im2, 0, sizeof(im2));

	++tests_counter;
	if (db_get_invitemask(db, im1.id_invitemask, &im2) != 0 ||
	    memcmp(&im1, &im2, sizeof(struct db_invitemask)) != 0) {
		printf("Unable to retrieve invitemask by ID\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_run_on_invitemasks(db, im1.id_channel, invitemask_callback, &im1) != 0) {
		printf("Error running invitemask callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_invitemasks(db, im1.id_channel) != 1) {
		printf("Unexpected value counting invitemasks\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_invitemask(db, &im1) != 0) {
		printf("Unable to delete channel invitemask\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;

	++tests_counter;
	if (db_run_on_invitemasks(db, im1.id_channel, row_count_callback, &counter) != 0 ||
	    counter != 0) {
		printf("Error running invitemask counter callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_channel(db, &chan) != 0 ||
	    db_count_channels(db) != 0) {
		printf("Unable to delete channel\n");
		++tests_failed;
	} else
		++tests_passed;
}

void make_simple_client(struct db_client *cli, int fd, const char *ip, int port, const char *nick)
{
	memset(cli, 0, sizeof(struct db_client));
	cli->fd = fd;
	snprintf(cli->ip, MESSAGE_BUFFER_SIZE, "%s", ip);
	cli->port = port;
	snprintf(cli->orig_nickname, NICKNAME_BUFFER_SIZE, "%s", nick);
	strcpy(cli->nickname, cli->orig_nickname);
	irclower(cli->nickname);
	strcpy(cli->username, cli->nickname);
	strcpy(cli->realname, cli->nickname);
	snprintf(cli->orig_fullname, MESSAGE_BUFFER_SIZE, "%s!%s@%s", cli->orig_nickname, cli->username, cli->ip);
	snprintf(cli->fullname, MESSAGE_BUFFER_SIZE, "%s!%s@%s", cli->nickname, cli->username, cli->ip);
	cli->invisible_flag = 1;
}

void make_simple_channel(struct db_channel *chan, const char *name)
{
	memset(chan, 0, sizeof(struct db_channel));
	snprintf(chan->orig_name, CHANNEL_BUFFER_SIZE, "%s", name);
	strcpy(chan->name, chan->orig_name);
	irclower(chan->name);

	/* Classic +nt modes. */
	chan->no_outside_flag = 1;
	chan->oper_topic_flag = 1;
}

void test_memberships(void)
{
	struct db_client cli1;
	struct db_client cli2;
	struct db_client cli3;
	struct db_channel chan1;
	struct db_channel chan2;
	struct db_membership ms1;
	struct db_membership ms2;
	int counter;
	int ret;

	make_simple_client(&cli1, 50, "192.168.1.100", 64000, "CLI01");
	make_simple_client(&cli2, 51, "192.168.1.101", 64001, "CLI02");
	cli2.invisible_flag = 0;
	make_simple_client(&cli3, 52, "192.168.1.102", 64002, "CLI03");
	make_simple_channel(&chan1, "#test01");
	make_simple_channel(&chan2, "#Test02");

	ret = db_add_client(db, &cli1);
	assert(ret == 0);
	ret = db_add_client(db, &cli2);
	assert(ret == 0);
	ret = db_add_client(db, &cli3);
	assert(ret == 0);
	ret = db_add_channel(db, &chan1);
	assert(ret == 0);
	ret = db_add_channel(db, &chan2);
	assert(ret == 0);

	memset(&ms1, 0, sizeof(struct db_membership));
	memset(&ms2, 0, sizeof(struct db_membership));

	ms1.id_channel = chan1.id_channel;
	ms1.id_client = cli1.id_client;

	++tests_counter;
	if (db_count_client_channels(db, cli1.id_client) != 0) {
		printf("Unexpected nonzero client channel count\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_channel_members(db, chan1.id_channel) != 0) {
		printf("Unexpected nonzero client count for channel\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_add_membership(db, &ms1) != 0) {
		printf("Unable to add membership 1\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_membership(db, ms1.id_channel, ms1.id_client, &ms2) != 0 ||
	    memcmp(&ms1, &ms2, sizeof(struct db_membership)) != 0) {
		printf("Unexpected data retrieving membership 1\n");
		++tests_failed;
	} else
		++tests_passed;

	ms1.operator_flag = 1;
	ms1.voice_flag = 1;

	++tests_counter;
	if (db_modify_membership(db, &ms1) != 0) {
		printf("Unable to modify membership 1\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_client_channels(db, cli1.id_client) != 1) {
		printf("Unexpected non-one client channel count\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&ms1, 0, sizeof(struct db_membership));
	ms1.id_channel = chan1.id_channel;
	ms1.id_client = cli2.id_client;

	ret = db_add_membership(db, &ms1);
	assert(ret == 0);

	++tests_counter;
	if (db_count_channel_members(db, chan1.id_channel) != 2) {
		printf("Unexpected membership count for channel\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_count_visible_members(db, chan1.id_channel) != 1) {
		printf("Unexpected visible membership count for channel\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;
	++tests_counter;
	if (db_run_on_members(db, chan1.id_channel, row_count_callback, &counter) != 0 ||
	    counter != 2) {
		printf("Error running channel members callback\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;
	++tests_counter;
	if (db_run_on_members_except(db, chan1.id_channel, cli1.id_client, row_count_callback, &counter) != 0 ||
	    counter != 1) {
		printf("Error running channel members callback with exception\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_client_may_set_topic(db, &cli2, &chan1) ||
	    db_client_may_set_topic(db, &cli3, &chan1) ||
	    (! db_client_may_set_topic(db, &cli1, &chan1))) {
		printf("Error in topic set policy\n");
		++tests_failed;
	} else
		++tests_passed;

	chan1.oper_topic_flag = 0;
	ret = db_modify_channel(db, &chan1);
	assert(ret == 0);

	++tests_counter;
	if ((! db_client_may_set_topic(db, &cli1, &chan1)) ||
	    (! db_client_may_set_topic(db, &cli2, &chan1)) ||
	    db_client_may_set_topic(db, &cli3, &chan1)) {
		printf("Error in topic set policy for -t channels\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_delete_membership(db, chan1.id_channel, cli2.id_client) != 0 ||
	    db_count_client_channels(db, cli2.id_client) != 0 ||
	    db_count_channel_members(db, chan1.id_channel) != 1) {
		printf("Unable to properly delete channel membership\n");
		++tests_failed;
	} else
		++tests_passed;

	ms1.id_channel = chan2.id_channel;
	ms1.id_client = cli1.id_client;

	ret = db_add_membership(db, &ms1);
	assert(ret == 0);

	++tests_counter;
	counter = 0;
	if (db_run_on_client_channels(db, cli1.id_client, row_count_callback, &counter) != 0 ||
	    counter != 2) {
		printf("Error running client channels callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_delete_client_memberships(db, cli1.id_client) != 0 ||
	    db_count_client_channels(db, cli1.id_client) != 0) {
		printf("Unable to delete client memberships\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_invites(void)
{
	struct db_client cli;
	struct db_channel chan;
	struct db_invite i1;
	struct db_membership memb;
	struct db_invitemask im;
	int ret;

	make_simple_client(&cli, 80, "192.168.1.110", 64010, "inv01"); 
	make_simple_channel(&chan, "#invitechan");

	ret = db_add_client(db, &cli);
	assert(ret == 0);
	ret = db_add_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_invite_client(db, chan.id_channel, cli.id_client) != 0) {
		printf("Unable to invite client to channel\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_get_invite(db, chan.id_channel, cli.id_client, &i1) != 0 ||
	    i1.id_channel != chan.id_channel ||
	    i1.id_client != cli.id_client) {
		printf("Unable to properly recover added invite\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_del_invite(db, chan.id_channel, cli.id_client) != 0 ||
	    db_get_invite(db, chan.id_channel, cli.id_client, &i1) == 0) {
		printf("Unable to delete invite\n");
		++tests_counter;
	} else
		++tests_passed;

	ret = db_invite_client(db, chan.id_channel, cli.id_client);
	assert(ret == 0);

	++tests_counter;
	if (db_clear_all_invites(db, chan.id_channel) != 0 ||
	    db_get_invite(db, chan.id_channel, cli.id_client, &i1) == 0) {
		printf("Unable to clear all channel invites\n");
		++tests_counter;
	} else
		++tests_passed;

	++tests_counter;
	if (db_client_can_invite(db, &cli, &chan)) {
		printf("Outside client is erroneously allowed to invite\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&memb, 0, sizeof(memb));
	memb.id_channel = chan.id_channel;
	memb.id_client = cli.id_client;
	memb.voice_flag = 1;
	ret = db_add_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_can_invite(db, &cli, &chan)) {
		printf("Non-invite-only channel prevents members from inviting others\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.invite_only_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_can_invite(db, &cli, &chan)) {
		printf("Invite-only channel allows non-operators to invite others\n");
		++tests_failed;
	} else
		++tests_passed;

	memb.operator_flag = 1;
	ret = db_modify_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_can_invite(db, &cli, &chan)) {
		printf("Invite-only flag does not let operators invite others\n");
		++tests_failed;
	} else
		++tests_passed;

	ret = db_delete_membership(db, chan.id_channel, cli.id_client);
	assert(ret == 0);
	chan.invite_only_flag = 0;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_meets_invite_req(db, &cli, &chan)) {
		printf("Client unable to meet invite requirements on normal channel\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.invite_only_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_meets_invite_req(db, &cli, &chan)) {
		printf("Client invited to channel when it should not be\n");
		++tests_failed;
	} else
		++tests_passed;

	im.id_channel = chan.id_channel;
	snprintf(im.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*@192.168.1.*");
	strcpy(im.mask, im.orig_mask);
	irclower(im.mask);
	ret = db_add_invitemask(db, &im);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_meets_invite_req(db, &cli, &chan)) {
		printf("User invited by mask does not meet invite requirements\n");
		++tests_failed;
	} else
		++tests_passed;

	ret = db_del_invitemask(db, &im);
	assert(ret == 0);
	ret = db_invite_client(db, chan.id_channel, cli.id_client);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_meets_invite_req(db, &cli, &chan)) {
		printf("User with personal invitation does not meet invite req.\n");
		++tests_failed;
	} else
		++tests_passed;

	memb.id_channel = chan.id_channel;
	memb.id_client = cli.id_client;
	ret = db_add_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (db_client_meets_invite_req(db, &cli, &chan)) {
		printf("Personal invite was not automatically deleted on JOIN\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_bans(void)
{
	struct db_client cli;
	struct db_channel chan;
	struct db_banmask bm;
	struct db_exceptmask em;
	int ret;

	make_simple_client(&cli, 150, "192.168.1.120", 64020, "Joiner"); 
	make_simple_channel(&chan, "#BanChan");

	ret = db_add_client(db, &cli);
	assert(ret == 0);
	ret = db_add_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_not_banned(db, &cli, &chan)) {
		printf("User banned on pristine channel\n");
		++tests_failed;
	} else
		++tests_passed;

	bm.id_channel = chan.id_channel;
	snprintf(bm.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*@192.168.2.*");
	strcpy(bm.mask, bm.orig_mask);
	irclower(bm.mask);
	ret = db_add_banmask(db, &bm);
	assert(ret == 0);
	
	++tests_counter;
	if (! db_client_not_banned(db, &cli, &chan)) {
		printf("Ban to others erroneusly banned a user\n");
		++tests_failed;
	} else
		++tests_passed;

	snprintf(bm.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*@192.168.1.*");
	strcpy(bm.mask, bm.orig_mask);
	irclower(bm.mask);
	ret = db_add_banmask(db, &bm);
	assert(ret == 0);

	++tests_counter;
	if (db_client_not_banned(db, &cli, &chan)) {
		printf("Unable to correctly ban user\n");
		++tests_failed;
	} else
		++tests_passed;

	em.id_channel = chan.id_channel;
	snprintf(em.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*@10.*");
	strcpy(em.mask, em.orig_mask);
	irclower(em.mask);
	ret = db_add_exceptmask(db, &em);
	assert(ret == 0);

	++tests_counter;
	if (db_client_not_banned(db, &cli, &chan)) {
		printf("Exception mask erroneusly affected other client\n");
		++tests_failed;
	} else
		++tests_passed;

	snprintf(em.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*join*@*");
	strcpy(em.mask, em.orig_mask);
	irclower(em.mask);
	ret = db_add_exceptmask(db, &em);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_not_banned(db, &cli, &chan)) {
		printf("Unable to unban user with exception mask\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_may_join(void)
{
	struct db_channel chan;
	struct db_client cli;
	struct db_membership memb;
	struct db_banmask bm;
	struct db_exceptmask em;
	int ret;

	make_simple_client(&cli, 60, "192.168.21.120", 64020, "tron");
	make_simple_channel(&chan, "#core");

	ret = db_add_client(db, &cli);
	assert(ret == 0);
	ret = db_add_channel(db, &chan);
	assert(ret == 0);

	memb.id_channel = chan.id_channel;
	memb.id_client = cli.id_client;
	memb.operator_flag = 0;
	memb.voice_flag = 0;

	ret = db_add_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != -1) {
		printf("Unexpected return value testing join capability for client in channel\n");
		++tests_failed;
	} else
		++tests_passed;

	ret = db_delete_membership(db, memb.id_channel, memb.id_client);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != 0) {
		printf("Client not allowed to join in normal situation\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.key_flag = 1;
	snprintf(chan.key, MESSAGE_BUFFER_SIZE, "%s", "p4ssw0rd");

	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != ERR_BADCHANNELKEY) {
		printf("Channel with key allows joining without it\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, "nicetry") != ERR_BADCHANNELKEY) {
		printf("Channel with key allows joining with wrong key\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, "p4ssw0rd") != 0) {
		printf("Not allowed to join passworded channel with correct password\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.key_flag = 0;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	bm.id_channel = chan.id_channel;
	snprintf(bm.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "TRON*!*@*");
	strcpy(bm.mask, bm.orig_mask);
	irclower(bm.mask);

	ret = db_add_banmask(db, &bm);
	assert(ret == 0);
	
	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != ERR_BANNEDFROMCHAN) {
		printf("Banned user allowed to join channel\n");
		++tests_failed;
	} else
		++tests_passed;

	em.id_channel = chan.id_channel;
	snprintf(em.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*ron!*@*");
	strcpy(em.mask, em.orig_mask);
	irclower(em.mask);

	ret = db_add_exceptmask(db, &em);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != 0) {
		printf("Client with exception mask entry not allowed to join\n");
		++tests_failed;
	} else
		++tests_passed;

	ret = db_del_exceptmask(db, &em);
	assert(ret == 0);
	ret = db_invite_client(db, chan.id_channel, cli.id_client);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != 0) {
		printf("Personal invite did not override channel ban\n");
		++tests_failed;
	} else
		++tests_passed;

	ret = db_add_membership(db, &memb);
	assert(ret == 0);
	ret = db_delete_membership(db, memb.id_channel, memb.id_client);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_join(db, &cli, &chan, NULL) != ERR_BANNEDFROMCHAN) {
		printf("Personal invite not properly deleted after join\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_may_talk(void)
{
	struct db_channel chan;
	struct db_client cli;
	struct db_membership memb;
	struct db_banmask bm;
	int ret;

	make_simple_client(&cli, 70, "192.168.21.130", 64030, "George6");
	make_simple_channel(&chan, "#Radio");
	chan.no_outside_flag = 0;

	ret = db_add_client(db, &cli);
	assert(ret == 0);
	ret = db_add_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_may_talk(db, &cli, &chan)) {
		printf("Client unable to talk on channel from outside\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.moderated_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_talk(db, &cli, &chan)) {
		printf("Client able to talk on moderated channel from outside\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.moderated_flag = 0;
	chan.no_outside_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_talk(db, &cli, &chan)) {
		printf("Client able to talk on +n channel from outside\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.no_outside_flag = 0;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	bm.id_channel = chan.id_channel;
	snprintf(bm.orig_mask, MESSAGE_BUFFER_SIZE, "%s", "*!*6*@*");
	strcpy(bm.mask, bm.orig_mask);
	irclower(bm.mask);

	ret = db_add_banmask(db, &bm);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_talk(db, &cli, &chan)) {
		printf("Client able to talk from outside when banned\n");
		++tests_failed;
	} else
		++tests_passed;

	memset(&memb, 0, sizeof(memb));
	memb.id_channel = chan.id_channel;
	memb.id_client = cli.id_client;

	ret = db_add_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_talk(db, &cli, &chan)) {
		printf("Client able to talk from inside when banned\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.no_outside_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);
	ret = db_del_banmask(db, &bm);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_may_talk(db, &cli, &chan)) {
		printf("Client unable to talk normally on channel\n");
		++tests_failed;
	} else
		++tests_passed;

	chan.moderated_flag = 1;
	ret = db_modify_channel(db, &chan);
	assert(ret == 0);

	++tests_counter;
	if (db_client_may_talk(db, &cli, &chan)) {
		printf("Client able to talk on moderated channel\n");
		++tests_failed;
	} else
		++tests_passed;

	memb.operator_flag = 1;
	ret = db_modify_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_may_talk(db, &cli, &chan)) {
		printf("Client with channel operator status unable to talk on channel\n");
		++tests_failed;
	} else
		++tests_passed;

	memb.operator_flag = 0;
	memb.voice_flag = 1;
	ret = db_modify_membership(db, &memb);
	assert(ret == 0);

	++tests_counter;
	if (! db_client_may_talk(db, &cli, &chan)) {
		printf("Client with voice on moderated channel unable to talk\n");
		++tests_failed;
	} else
		++tests_passed;
}

/* Neighborhood test. */
struct db_client me;
struct db_client oper;
struct db_client brother;
struct db_client friend;
struct db_client foe;
struct db_channel debug_ch;
struct db_channel public_ch;
struct db_channel anon_ch;
struct db_membership m;

void anonymous_callback(void *row, void *extra)
{
	struct db_client *cli;

	UNUSED(extra);
	cli = (struct db_client *)row;

	++tests_counter;
	if (cli->id_client == me.id_client ||
	    cli->id_client == oper.id_client ||
	    cli->id_client == friend.id_client) {
		printf("Got unexpected client ID on anonymous callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void non_anonymous_callback(void *row, void *extra)
{
	struct db_client_channel *cc;
	struct db_client *cli;
	struct db_channel *chan;

	UNUSED(extra);
	cc = row;
	cli = &(cc->client);
	chan = &(cc->channel);

	++tests_counter;
	if ((cli->id_client == me.id_client ||
	     cli->id_client == oper.id_client ||
	     cli->id_client == foe.id_client) &&
	    strcmp(chan->name, "#mind") != 0) {
		printf("Got unexpected result on non-anonymous callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_neighborhood(void)
{
	int counter;
	int ret;

	make_simple_client(&me, 100, "10.10.210.1", 64100, "roland");
	make_simple_client(&oper, 101, "10.10.210.2", 64101, "god");
	make_simple_client(&brother, 102, "10.10.210.3", 64102, "eddie");
	make_simple_client(&friend, 103, "10.10.210.4", 64103, "jake");
	make_simple_client(&foe, 104, "10.10.210.5", 64104, "mordred");

	make_simple_channel(&debug_ch, "#debug");
	make_simple_channel(&public_ch, "#tower");
	make_simple_channel(&anon_ch, "#MiNd");

	debug_ch.quiet_flag = 1;
	anon_ch.anonymous_flag = 1;

	ret = db_add_client(db, &me);
	assert(ret == 0);
	ret = db_add_client(db, &oper);
	assert(ret == 0);
	ret = db_add_client(db, &brother);
	assert(ret == 0);
	ret = db_add_client(db, &friend);
	assert(ret == 0);
	ret = db_add_client(db, &foe);
	assert(ret == 0);
	ret = db_add_channel(db, &debug_ch);
	assert(ret == 0);
	ret = db_add_channel(db, &public_ch);
	assert(ret == 0);
	ret = db_add_channel(db, &anon_ch);
	assert(ret == 0);

	memset(&m, 0, sizeof(m));
	m.id_client = me.id_client;

	/* me */
	m.id_channel = debug_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);
	m.id_channel = public_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);
	m.id_channel = anon_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);

	/* oper */
	m.id_client = oper.id_client;
	m.id_channel = debug_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);

	/* brother */
	m.id_client = brother.id_client;
	m.id_channel = public_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);
	m.id_channel = anon_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);

	/* friend */
	m.id_client = friend.id_client;
	m.id_channel = public_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);

	/* foe */
	m.id_client = foe.id_client;
	m.id_channel = anon_ch.id_channel;
	ret = db_add_membership(db, &m);
	assert(ret == 0);

	++tests_counter;
	if (db_run_on_anon_neighbors(db, me.id_client, anonymous_callback, NULL) != 0) {
		printf("Error running anonymous callback\n");
		++tests_failed;
	} else
		++tests_passed;

	++tests_counter;
	if (db_run_on_non_anon_neighbors(db, me.id_client, non_anonymous_callback, NULL) != 0) {
		printf("Error running non-anonymous callback\n");
		++tests_failed;
	} else
		++tests_passed;

	counter = 0;
	++tests_counter;
	if (db_run_on_neighbors(db, me.id_client, row_count_callback, &counter) != 0 ||
	    counter != 3) {
		printf("Error counting all my neighbors\n");
		++tests_failed;
	} else
		++tests_passed;

}

struct db_client simul0;
struct db_client simul1;
struct db_client simul2;
struct db_client simul3;

void test_simultaneous_callback(void *row, void *extra)
{
	int *counter = extra;
	int ret;

	ret = db_del_client(db, row);
	assert(ret == 0);
	ret = db_del_client(db, &simul1);
	assert(ret == 0);
	ret = db_del_client(db, &simul3);
	assert(ret == 0);

	++(*counter);
}

void test_simultaneous(void)
{
	int counter;
	int ret;

	/*
	 * The following test will run a query and delete rows from the result
	 * while iterating over it.
	 */
	make_simple_client(&simul0, 200, "10.200.0.1", 64200, "simul0");
	make_simple_client(&simul1, 201, "10.200.1.1", 64201, "simul1");
	make_simple_client(&simul2, 202, "10.200.2.1", 64202, "simul2");
	make_simple_client(&simul3, 203, "10.200.3.1", 64203, "simul3");

	simul0.wallops_flag = 1;
	simul1.wallops_flag = 1;
	simul2.wallops_flag = 1;
	simul3.wallops_flag = 1;

	ret = db_add_client(db, &simul0);
	assert(ret == 0);
	ret = db_add_client(db, &simul1);
	assert(ret == 0);
	ret = db_add_client(db, &simul2);
	assert(ret == 0);
	ret = db_add_client(db, &simul3);
	assert(ret == 0);

	counter = 0;
	++tests_counter;
	if (db_run_on_wallops(db, test_simultaneous_callback, &counter) != 0 ||
	    counter != 2) {
		printf("Simultaneous queries do not work as expected\n");
		++tests_failed;
	} else
		++tests_passed;
}

struct db_client writer;
struct db_client pingout;
struct db_client nowait;
struct db_client inactive;

void ping_timeout_cb(void *row, void *extra)
{
	struct db_client *cli;

	UNUSED(extra);
	cli = row;

	++tests_counter;
	if (strcmp(cli->nickname, pingout.nickname) != 0) {
		printf("Unexpected client in ping timeout callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void nonwaiting_cb(void *row, void *extra)
{
	struct db_client *cli;

	UNUSED(extra);
	cli = row;

	++tests_counter;
	if (strcmp(cli->nickname, nowait.nickname) != 0 &&
	    strcmp(cli->nickname, inactive.nickname) != 0) {
		printf("Unexpected client in nonwaiting clients callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void inactive_cb(void *row, void *extra)
{
	struct db_client *cli;

	UNUSED(extra);
	cli = row;

	++tests_counter;
	if (strcmp(cli->nickname, inactive.nickname) != 0) {
		printf("Unexpected client in inactive clients callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

void test_activity(void)
{
	int counter;
	int ret;

	db_clear(db);

	make_simple_client(&writer, 220, "10.1.220.1", 64220, "writer");
	writer.last_ping = 0;
	writer.last_activity = time(NULL) + 2;
	writer.signon_time = 0;

	make_simple_client(&pingout, 221, "10.1.221.1", 64221, "pingout");
	pingout.last_ping = time(NULL) - 31;
	pingout.last_activity = time(NULL) + 2;

	make_simple_client(&nowait, 222, "10.1.222.1", 64222, "nowait");
	nowait.last_ping = 0;
	nowait.last_activity = time(NULL) - 1;

	make_simple_client(&inactive, 223, "10.1.223.1", 64223, "inactive");
	inactive.last_ping = 0;
	inactive.last_activity = time(NULL) - 31;

	ret = db_add_client(db, &writer);
	assert(ret == 0);
	ret = db_add_client(db, &pingout);
	assert(ret == 0);
	ret = db_add_client(db, &nowait);
	assert(ret == 0);
	ret = db_add_client(db, &inactive);
	assert(ret == 0);

	ret = db_run_on_ping_timeout_clients(db, 30, ping_timeout_cb, NULL);
	assert(ret == 0);
	ret = db_run_on_inactive_clients(db, 30, inactive_cb, NULL);
	assert(ret == 0);

	counter = 0;
	ret = db_run_on_clients(db, row_count_callback, &counter);
	assert(ret == 0);
	++tests_counter;
	if (counter != 4) {
		printf("Unexpected client count in all-clients callback\n");
		++tests_failed;
	} else
		++tests_passed;
}

int main()
{
	init_counters();
	db = db_create();

	test_get_forbidden_nicks();
	test_forbidden_check();
	test_add_del_forbidden_nicks();
	test_add_get_operator();
	test_add_get_client();
	test_get_modify_client();
	test_count_del_client();
	test_channel_masks();
	test_memberships();
	test_invites();
	test_bans();
	test_may_join();
	test_may_talk();
	test_neighborhood();
	test_simultaneous();
	test_activity();

	db_close(db);
	return tests_summary();
}
