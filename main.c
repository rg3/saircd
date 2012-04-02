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
 * main.c - Server's main function.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sqlite3.h>

#include "messages.h"
#include "database.h"
#include "buffer.h"
#include "reader.h"
#include "server.h"
#include "util.h"

struct server srv;

static void free_resources(void);

int main(int argc, char *argv[])
{
	struct server_config cfg;
	const char *cfg_file_name;
	FILE *cfg_file;
	uid_t uid;
	gid_t gid;
	int dev_null_fd;

	/* Check args. */
	if (argc > 2) {
		fprintf(stderr, "Usage: %s [CONFIG_FILE]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Parse config. */
	cfg_file_name = (argc == 2)?argv[1]:"/dev/null";

	cfg_file = fopen(cfg_file_name, "r");
	if (cfg_file == NULL) {
		fprintf(stderr, "ERROR: unable to open \"%s\" for reading\n", cfg_file_name);
		exit(EXIT_FAILURE);
	}

	srv_parse_config(cfg_file, &cfg);
	fclose(cfg_file);

	if (i_am_superuser() && strlen(cfg.username) == 0)
		fprintf(stderr, "WARNING: the server will run as the superuser\n");

	if (cfg.daemonize) {
		dev_null_fd = open("/dev/null", O_RDWR);
		if (dev_null_fd == -1) {
			fprintf(stderr, "ERROR: unable to open file descriptor for /dev/null\n");
			exit(EXIT_FAILURE);
		}
	} else
		dev_null_fd = -1;

	/* Initialize server. */
	if (atexit(free_resources) != 0) {
		fprintf(stderr, "ERROR: unable to set cleaning exit function\n");
		exit(EXIT_FAILURE);
	}
	srv_init(&srv, &cfg);

	/* Post-initialization configuration. */
	if (strlen(cfg.username) > 0) {
		if (get_uid_gid(cfg.username, &uid, &gid) != 0) {
			fprintf(stderr, "ERROR: could not get UID and GID for username \"%s\"\n", cfg.username);
			exit(EXIT_FAILURE);
		}
	}
	if (strlen(cfg.chroot_dir) > 0) {
		if (! i_am_superuser()) {
			fprintf(stderr, "ERROR: cannot chroot properly without being superuser\n");
			exit(EXIT_FAILURE);
		}
		if (chroot_to(cfg.chroot_dir) != 0) {
			fprintf(stderr, "ERROR: unable to chroot to specified directory, check path\n");
			exit(EXIT_FAILURE);
		}
	}
	if (strlen(cfg.username) > 0) {
		if (! i_am_superuser()) {
			fprintf(stderr, "ERROR: cannot change UID and GID properly without being superuser\n");
			exit(EXIT_FAILURE);
		}
		if (set_uid_gid(uid, gid) != 0) {
			fprintf(stderr, "ERROR: could not set GID and UID, check passwd entries\n");
			exit(EXIT_FAILURE);
		}
		if (i_am_superuser())
			fprintf(stderr, "WARNING: still superuser after changing UID and GID\n");
	}

	if (strlen(cfg.chroot_dir) > 0 && i_am_superuser())
		fprintf(stderr, "WARNING: staying in a chroot jail as the superuser is not secure\n");

	if (cfg.daemonize) {
		if (daemonize(dev_null_fd) != 0) {
			fprintf(stderr, "ERROR: unable to daemonize process\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Launch server's main loop. */
	srv_main_loop(&srv);

	return 0;
}

static void free_resources(void)
{
	srv_destroy(&srv);
	messages_free();
}
