#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>

#include "util.h"

void irclower(char *str)
{
	char *itr;

	for (itr = str; *itr != '\0'; ++itr) {
		if (*itr == '[')
			*itr = '{';
		else if (*itr == ']')
			*itr = '}';
		else if (*itr == '\\')
			*itr = '|';
		else if (*itr == '~')
			*itr = '^';
		else
			*itr = tolower((unsigned char)(*itr));
	}
}

int nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_GETFL, 0) == -1)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int close_noeintr(int fd)
{
	int ret;
	while ((ret = close(fd)) == -1 && errno == EINTR)
		;
	return ret;
}

/* Auxiliar function to create a listening socket from the given address. */
static int make_listen_socket(struct addrinfo *info)
{
	int fd;

	fd = socket(info->ai_family, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	if (bind(fd, info->ai_addr, info->ai_addrlen) == -1) {
		close_noeintr(fd);
		return -1;
	}
	if (listen(fd, SOMAXCONN) == -1) {
		close_noeintr(fd);
		return -1;
	}

	return fd;
}

int get_listen_socket(const char *addr, int port, int *s, int *ipv6)
{
	char portstr[8];
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *iter;
	struct addrinfo *ipv4_addr;
	struct addrinfo *ipv6_addr;
	int ret;
	int fd;
	int ipv6_flag;

	assert(s != NULL);
	assert(ipv6 != NULL);

	ipv4_addr = NULL;
	ipv6_addr = NULL;
	fd = -1;
	ipv6_flag = 0;

	/* Check port. */
	if (port <= 0 || port > 65535)
		return -1;
	ret = snprintf(portstr, sizeof(portstr), "%d", port);
	assert(ret > 0);

	/* Prepare hints for getaddrinfo(). */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_PASSIVE;

	/* Get the addresses with getaddrinfo(). */
	result = NULL;
	ret = getaddrinfo(addr, portstr, &hints, &result);
	if (ret != 0)
		return -1;

	/* Iterate over the results and bookmark interesting addresses. */
	for (iter = result; iter != NULL; iter = iter->ai_next) {
		if (iter->ai_family == AF_INET6)
			ipv6_addr = iter;
		else if (iter->ai_family == AF_INET)
			ipv4_addr = iter;
	}

	/* Give preference to the IPv6 socket if possible. */
	if (ipv6_addr != NULL) {
		fd = make_listen_socket(ipv6_addr);
		if (fd != -1)
			ipv6_flag = 1;
	}
	if (fd == -1 && ipv4_addr != NULL)
		fd = make_listen_socket(ipv4_addr);

	/* Free the results before returning. */
	freeaddrinfo(result);

	if (fd == -1)
		return -1;

	*s = fd;
	*ipv6 = ipv6_flag;
	return 0;
}

int daemonize(int dev_null_fd)
{
	char buf;
	int pipefd[2];

	if (pipe(pipefd) == -1)
		return -1;

	/* Make sure setsid() works. */
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		/* Child. */
		/* Detach from terminal. */
		setsid();

		/*
		 * Allow parent to terminate. This prevents a race condition by
		 * which the parent terminates too early and its parent process
		 * too, causing the reception of SIGHUP in the child before
		 * it's had an opportunity to call setsid().
		 */
		close_noeintr(pipefd[0]);
		while (write(pipefd[1], &buf, 1) == -1 && errno == EINTR)
			;
		close_noeintr(pipefd[1]);
		break;
	default:
		/* Parent. */
		close_noeintr(pipefd[1]);
		while (read(pipefd[0], &buf, 1) == -1 && errno == EINTR)
			;
		close_noeintr(pipefd[0]);
		exit(EXIT_SUCCESS);
		break;
	}

	/* Make sure reattaching is not possible. */
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
		break;
	}

	/* Replace standard file descriptors. */
	close_noeintr(STDIN_FILENO);
	close_noeintr(STDOUT_FILENO);
	close_noeintr(STDERR_FILENO);

	if (dup2(dev_null_fd, STDIN_FILENO) == -1)
		return -1;
	if (dup2(dev_null_fd, STDOUT_FILENO) == -1)
		return -1;
	if (dup2(dev_null_fd, STDERR_FILENO) == -1)
		return -1;

	if (dev_null_fd > STDERR_FILENO)
		close_noeintr(dev_null_fd);

	/* Umask. */
	umask(0);

	/* Change to root. */
	if (chdir("/") == -1)
		return -1;

	return 0;
}

int get_uid_gid(const char *username, uid_t *uid, gid_t *gid)
{
	struct passwd *p;

	errno = 0;
	p = getpwnam(username);
	if (p == NULL)
		return -1;
	*uid = p->pw_uid;
	*gid = p->pw_gid;
	return 0;
}

int set_uid_gid(uid_t uid, gid_t gid)
{
	if (setgid(gid) == -1)
		return -1;

	if (setuid(uid) == -1)
		return -1;

	return 0;
}

int i_am_superuser(void)
{
	return (geteuid() == (uid_t)0);
}

int chroot_to(const char *dirname)
{
	if (chdir(dirname) == -1)
		return -1;
	if (chroot(dirname) == -1)
		return -1;
	return 0;
}
