/* fsops_uvol.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <spawn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "ps4_context.h"
#include "ps4_fs.h"

static int uvol_run(struct ps4_ctx *ac, char *action, const char *volname, char *arg1, char *arg2)
{
	char buf[PS4_EXIT_STATUS_MAX_SIZE];
	struct ps4_out *out = &ac->out;
	pid_t pid;
	int r, status;
	char *argv[] = { (char*)ps4_ctx_get_uvol(ac), action, (char*) volname, arg1, arg2, 0 };
	posix_spawn_file_actions_t act;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_addclose(&act, STDIN_FILENO);
	r = posix_spawn(&pid, ps4_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		ps4_err(out, "%s: uvol run exec error: %s", volname, ps4_error_str(r));
		return r;
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	if (ps4_exit_status_str(status, buf, sizeof buf)) {
		ps4_err(out, "%s: uvol run %s", volname, buf);
		return -PS4E_UVOL_ERROR;
	}
	return 0;
}

static int uvol_extract(struct ps4_ctx *ac, const char *volname, char *arg1, off_t sz,
	struct ps4_istream *is, ps4_progress_cb cb, void *cb_ctx)
{
	char buf[PS4_EXIT_STATUS_MAX_SIZE];
	struct ps4_out *out = &ac->out;
	struct ps4_ostream *os;
	pid_t pid;
	int r, status, pipefds[2];
	char *argv[] = { (char*)ps4_ctx_get_uvol(ac), "write", (char*) volname, arg1, 0 };
	posix_spawn_file_actions_t act;

	if (pipe2(pipefds, O_CLOEXEC) != 0) return -errno;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_adddup2(&act, pipefds[0], STDIN_FILENO);
	r = posix_spawn(&pid, ps4_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		ps4_err(out, "%s: uvol exec error: %s", volname, ps4_error_str(r));
		return r;
	}
	close(pipefds[0]);
	os = ps4_ostream_to_fd(pipefds[1]);
	ps4_stream_copy(is, os, sz, cb, cb_ctx, 0);
	r = ps4_ostream_close(os);
	if (r != 0) {
		if (r >= 0) r = -PS4E_UVOL_ERROR;
		ps4_err(out, "%s: uvol write error: %s", volname, ps4_error_str(r));
		return r;
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	if (ps4_exit_status_str(status, buf, sizeof buf)) {
		ps4_err(out, "%s: uvol extract %s", volname, buf);
		return -PS4E_UVOL_ERROR;
	}
	return 0;
}

static int uvol_dir_create(struct ps4_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	return 0;
}

static int uvol_dir_delete(struct ps4_fsdir *d)
{
	return 0;
}

static int uvol_dir_check(struct ps4_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	return 0;
}

static int uvol_dir_update_perms(struct ps4_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	return 0;
}

static int uvol_file_extract(struct ps4_ctx *ac, const struct ps4_file_info *fi, struct ps4_istream *is,
	ps4_progress_cb cb, void *cb_ctx, unsigned int extract_flags, ps4_blob_t pkgctx)
{
	char size[64];
	const char *uvol_name;
	int r;

	if (IS_ERR(ac->uvol)) return PTR_ERR(ac->uvol);

	uvol_name = strrchr(fi->name, '/');
	uvol_name = uvol_name ? uvol_name + 1 : fi->name;

	snprintf(size, sizeof size, "%ju", (intmax_t) fi->size);
	r = uvol_run(ac, "create", uvol_name, size, "ro");
	if (r != 0) return r;

	r = uvol_extract(ac, uvol_name, size, fi->size, is, cb, cb_ctx);
	if (r == 0 && !pkgctx.ptr)
		r = uvol_run(ac, "up", uvol_name, 0, 0);

	if (r != 0) uvol_run(ac, "remove", uvol_name, 0, 0);

	return r;
}

static int uvol_file_control(struct ps4_fsdir *d, ps4_blob_t filename, int ctrl)
{
	struct ps4_ctx *ac = d->ac;
	struct ps4_pathbuilder pb;
	const char *uvol_name;
	int r;

	if (IS_ERR(ac->uvol)) return PTR_ERR(ac->uvol);

	ps4_pathbuilder_setb(&pb, filename);
	uvol_name = ps4_pathbuilder_cstr(&pb);

	switch (ctrl) {
	case PS4_FS_CTRL_COMMIT:
		return uvol_run(ac, "up", uvol_name, 0, 0);
	case PS4_FS_CTRL_PS4NEW:
	case PS4_FS_CTRL_CANCEL:
	case PS4_FS_CTRL_DELETE:
		r = uvol_run(ac, "down", uvol_name, 0, 0);
		if (r)
			return r;
		return uvol_run(ac, "remove", uvol_name, 0, 0);
	case PS4_FS_CTRL_DELETE_PS4NEW:
		return 0;
	default:
		return -PS4E_UVOL_ERROR;
	}
}

static int uvol_file_info(struct ps4_fsdir *d, ps4_blob_t filename, unsigned int flags, struct ps4_file_info *fi)
{
	return -PS4E_UVOL_ERROR;
}

const struct ps4_fsdir_ops fsdir_ops_uvol = {
	.priority = PS4_FS_PRIO_UVOL,
	.dir_create = uvol_dir_create,
	.dir_delete = uvol_dir_delete,
	.dir_check = uvol_dir_check,
	.dir_update_perms = uvol_dir_update_perms,
	.file_extract = uvol_file_extract,
	.file_control = uvol_file_control,
	.file_info = uvol_file_info,
};
