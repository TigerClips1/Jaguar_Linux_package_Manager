/* ps4_fs.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_FS_H
#define PS4_FS_H

#include "ps4_context.h"
#include "ps4_io.h"
#include "ps4_pathbuilder.h"

#define PS4_FS_PRIO_DISK	0
#define PS4_FS_PRIO_UVOL	1
#define PS4_FS_PRIO_MAX		2

#define PS4_FS_CTRL_COMMIT		1
#define PS4_FS_CTRL_PS4NEW		2
#define PS4_FS_CTRL_CANCEL		3
#define PS4_FS_CTRL_DELETE		4
#define PS4_FS_CTRL_DELETE_PS4NEW	5

#define PS4_FS_DIR_MODIFIED	1

struct ps4_fsdir_ops;

struct ps4_fsdir {
	struct ps4_ctx *ac;
	const struct ps4_fsdir_ops *ops;
	struct ps4_pathbuilder pb;
	unsigned int extract_flags;
	ps4_blob_t pkgctx;
};

struct ps4_fsdir_ops {
	uint8_t priority;

	int (*dir_create)(struct ps4_fsdir *, mode_t, uid_t, gid_t);
	int (*dir_delete)(struct ps4_fsdir *);
	int (*dir_check)(struct ps4_fsdir *, mode_t, uid_t, gid_t);
	int (*dir_update_perms)(struct ps4_fsdir *, mode_t, uid_t, gid_t);

	int (*file_extract)(struct ps4_ctx *, const struct ps4_file_info *, struct ps4_istream *, ps4_progress_cb, void *, unsigned int, ps4_blob_t);
	int (*file_control)(struct ps4_fsdir *, ps4_blob_t, int);
	int (*file_info)(struct ps4_fsdir *, ps4_blob_t, unsigned int, struct ps4_file_info *);
};

#define PS4_FSEXTRACTF_NO_CHOWN		0x0001
#define PS4_FSEXTRACTF_NO_OVERWRITE	0x0002
#define PS4_FSEXTRACTF_NO_SYS_XATTRS	0x0004

int ps4_fs_extract(struct ps4_ctx *, const struct ps4_file_info *, struct ps4_istream *, ps4_progress_cb, void *, unsigned int, ps4_blob_t);

void ps4_fsdir_get(struct ps4_fsdir *, ps4_blob_t dir, unsigned int extract_flags, struct ps4_ctx *ac, ps4_blob_t pkgctx);

static inline uint8_t ps4_fsdir_priority(struct ps4_fsdir *fs) {
	return fs->ops->priority;
}
static inline int ps4_fsdir_create(struct ps4_fsdir *fs, mode_t mode, uid_t uid, gid_t gid) {
	return fs->ops->dir_create(fs, mode, uid, gid);
}
static inline int ps4_fsdir_delete(struct ps4_fsdir *fs) {
	return fs->ops->dir_delete(fs);
}
static inline int ps4_fsdir_check(struct ps4_fsdir *fs, mode_t mode, uid_t uid, gid_t gid) {
	return fs->ops->dir_check(fs, mode, uid, gid);
}
static inline int ps4_fsdir_update_perms(struct ps4_fsdir *fs, mode_t mode, uid_t uid, gid_t gid) {
	return fs->ops->dir_update_perms(fs, mode, uid, gid);
}

static inline int ps4_fsdir_file_control(struct ps4_fsdir *fs, ps4_blob_t filename, int ctrl) {
	return fs->ops->file_control(fs, filename, ctrl);
}
static inline int ps4_fsdir_file_info(struct ps4_fsdir *fs, ps4_blob_t filename, unsigned int flags, struct ps4_file_info *fi) {
	return fs->ops->file_info(fs, filename, flags, fi);
}

#endif
