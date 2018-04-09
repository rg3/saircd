/*
 * Copyright 2012,2018 Ricardo Garcia Gonzalez
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
 * server.h - Server data structures and procedures.
 */
#ifndef _SERVER_H_
#define _SERVER_H_

#define DEFAULT_DATE ("N/A")
#define MAX_ADDRESS_LEN	(39)
#define ADDRESS_BUFFER_SIZE (MAX_ADDRESS_LEN + 1)

/* Number of nicks in a single RPL_NAMREPLY message. */
#define MAX_NAMREPLY_NICKS	(32)

/* Registration state bits. */
#define REGSTATE_PASS	(1)
#define REGSTATE_NICK	(2)
#define REGSTATE_USER	(4)

#define CLIENT_PENALIZATION (1)	/* Per command, in seconds. */

/* Configuration defaults. */
#define DEFAULT_SERVER_NAME		("irc.server")
#define DEFAULT_MOTD			("")
#define DEFAULT_LOCATION		("N/A")
#define DEFAULT_ENTITY			("N/A")
#define DEFAULT_EMAIL			("N/A")
#define DEFAULT_MAX_CLIENTS		(1000)
#define DEFAULT_MAX_CHANNELS		(500)
#define DEFAULT_MAX_CLIENT_CHANNELS	(20)
#define DEFAULT_MAX_CHANNEL_MEMBERS	(300)
#define DEFAULT_MAX_BANS		(30)
#define DEFAULT_MAX_EXCEPTS		(30)
#define DEFAULT_MAX_INVITES		(30)
#define DEFAULT_PORT			(6667)
#define DEFAULT_ADDRESS			("")
#define DEFAULT_TIMEOUT_SECONDS		(30)
#define DEFAULT_WHOWAS_TIMEOUT_SECONDS	(10)
#define DEFAULT_KILL_TIMEOUT_SECONDS	(60)
#define DEFAULT_OPERATORS_FILENAME	("")
#define DEFAULT_USERNAME		("")
#define DEFAULT_CHROOT_DIR		("")
#define DEFAULT_DAEMONIZE		(1)

/* Some configuration limits. */
#define MIN_CLIENTS		(1)
#define MIN_CHANNELS		(1)
#define MIN_PORT		(1)
#define MAX_PORT		(65535)
#define MIN_TIMEOUT		(10)
#define MAX_TIMEOUT		(86400)
#define MAX_PHRASE_LENGTH	(256)
#define MIN_SERVER_NAME_LENGTH	(1)
#define MAX_SERVER_NAME_LENGTH	(64)

struct server_config {
	int max_clients;
	int output_buffer_size;
	char address[ADDRESS_BUFFER_SIZE];
	int port;
	int timeout_seconds;
	int whowas_timeout_seconds;
	int kill_timeout_seconds;
	int max_channels;
	int max_client_channels;
	int max_channel_members;
	int max_bans;
	int max_excepts;
	int max_invites;
	char server_name[MESSAGE_BUFFER_SIZE];
	char motd[MESSAGE_BUFFER_SIZE];
	char location[MESSAGE_BUFFER_SIZE];
	char entity[MESSAGE_BUFFER_SIZE];
	char email[MESSAGE_BUFFER_SIZE];
	char operators_filename[MESSAGE_BUFFER_SIZE];
	char username[MESSAGE_BUFFER_SIZE];
	char chroot_dir[MESSAGE_BUFFER_SIZE];
	int daemonize;
};

struct server_cmdcounter {
	long long number;
	long long bytes;
};

struct server_dyndata {
	time_t start_time;
	struct server_cmdcounter cmd_counters[CMD_TOP_NUMBER - CMD_BASE_NUMBER];
	int die_flag;
	struct db_channel logchan;
};

struct server_client {
	int fd;
	struct buffer input;
	struct buffer output;
	struct reader reader;
	int next_free;
};

struct server_clients {
	int next_free;
	struct server_client *array;
};

struct server_pollfds {
	int used;
	struct pollfd *array;
};

struct server_listen_socket {
	int fd;
	int is_ipv6;
};

struct server {
	struct server_config config;
	struct server_dyndata dyndata;
	struct server_clients clients;
	struct server_pollfds pollfds;
	struct server_listen_socket listen_socket;
	sqlite3 *db;
};

/* Initialize server with the given configuration data. */
void srv_init(struct server *srv, const struct server_config *config);

/* Destroy server and free all resources. */
void srv_destroy(struct server *srv);

/* Server's main loop. */
void srv_main_loop(struct server *srv);

/* Parse a server configuration file and store values in the structure. */
void srv_parse_config(FILE *f, struct server_config *cfg);

#endif /* _SERVER_H_ */
