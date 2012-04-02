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
 * util.h - Miscellaneous utility functions.
 */
#ifndef _UTIL_H_
#define _UTIL_H_

/* Macro to mark a variable as unused explicitly and silence the compiler. */
#define UNUSED(x) do { (void)(x); } while (0)

/* Convert a string to its lowercase version (according to the RFC). */
void irclower(char *str);

/* Make a file descriptor nonblocking. */
int nonblock(int fd);

/* Close a file descriptor catching EINTR. */
int close_noeintr(int fd);

/* Get a listening socket. Returns -1 on failure. */
int get_listen_socket(const char *addr, int port, int *s, int *ipv6);

/* Daemonize process. */
int daemonize(int dev_null_fd);

/* Set username and group. */
int get_uid_gid(const char *username, uid_t *uid, gid_t *gid);
int set_uid_gid(uid_t uid, gid_t gid);

/* Returns answer to the question "am I running as the superuser?". */
int i_am_superuser(void);

/* Run chroot properly. */
int chroot_to(const char *dirname);

#endif
