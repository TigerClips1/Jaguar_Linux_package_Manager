/* io_url_wget.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ps4_io.h"

static char wget_timeout[16];
static char wget_no_check_certificate;

static int wget_translate_status(int status)
{
	if (!WIFEXITED(status)) return -EFAULT;
	switch (WEXITSTATUS(status)) {
	case 0: return 0;
	case 3: return -EIO;
	case 4: return -ENETUNREACH;
	case 5: return -EACCES;
	case 6: return -EACCES;
	case 7: return -EPROTO;
	default: return -PS4E_REMOTE_IO;
	}
}

struct ps4_wget_istream {
	struct ps4_istream is;
	int fd;
	pid_t pid;
};

static int wget_spawn(const char *url, pid_t *pid, int *fd)
{
	int i = 0, r, pipefds[2];
	posix_spawn_file_actions_t act;
	char *argv[16];

	argv[i++] = "wget";
	argv[i++] = "-q";
	argv[i++] = "-T";
	argv[i++] = wget_timeout;
	if (wget_no_check_certificate) argv[i++] = "--no-check-certificate";
	argv[i++] = (char *) url;
	argv[i++] = "-O";
	argv[i++] = "-";
	argv[i++] = 0;

	if (pipe2(pipefds, O_CLOEXEC) != 0) return -errno;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_adddup2(&act, pipefds[1], STDOUT_FILENO);
	r = posix_spawnp(pid, "wget", &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) return -r;
	close(pipefds[1]);
	*fd = pipefds[0];
	return 0;
}

static int wget_check_exit(struct ps4_wget_istream *wis)
{
	int status;

	if (wis->pid == 0) return ps4_istream_error(&wis->is, 0);
	if (waitpid(wis->pid, &status, 0) == wis->pid) {
		wis->pid = 0;
		return ps4_istream_error(&wis->is, wget_translate_status(status));
	}
	return 0;
}

static void wget_get_meta(struct ps4_istream *is, struct ps4_file_meta *meta)
{
}

static ssize_t wget_read(struct ps4_istream *is, void *ptr, size_t size)
{
	struct ps4_wget_istream *wis = container_of(is, struct ps4_wget_istream, is);
	ssize_t r;

	r = read(wis->fd, ptr, size);
	if (r < 0) return -errno;
	if (r == 0) return wget_check_exit(wis);
	return r;
}

static int wget_close(struct ps4_istream *is)
{
	int r = is->err;
	struct ps4_wget_istream *wis = container_of(is, struct ps4_wget_istream, is);

	while (wis->pid != 0)
		wget_check_exit(wis);

	close(wis->fd);
	free(wis);
	return r < 0 ? r : 0;
}

static const struct ps4_istream_ops wget_istream_ops = {
	.get_meta = wget_get_meta,
	.read = wget_read,
	.close = wget_close,
};

struct ps4_istream *ps4_io_url_istream(const char *url, time_t since)
{
	struct ps4_wget_istream *wis;
	int r;

	wis = malloc(sizeof(*wis) + ps4_io_bufsize);
	if (wis == NULL) return ERR_PTR(-ENOMEM);

	*wis = (struct ps4_wget_istream) {
		.is.ops = &wget_istream_ops,
		.is.buf = (uint8_t *)(wis + 1),
		.is.buf_size = ps4_io_bufsize,
	};
	r = wget_spawn(url, &wis->pid, &wis->fd);
	if (r != 0) {
		free(wis);
		return ERR_PTR(r);
	}

	return &wis->is;
}

void ps4_io_url_no_check_certificate(void)
{
	wget_no_check_certificate = 1;
}

void ps4_io_url_set_timeout(int timeout)
{
	snprintf(wget_timeout, sizeof wget_timeout, "%d", timeout);
}

void ps4_io_url_set_redirect_callback(void (*cb)(int, const char *))
{
}

void ps4_io_url_init(void)
{
}
