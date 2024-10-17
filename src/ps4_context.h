/* ps4_context.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_CONTEXT_H
#define PS4_CONTEXT_H

#include "ps4_blob.h"
#include "ps4_print.h"
#include "ps4_trust.h"
#include "ps4_io.h"
#include "ps4_crypto.h"
#include "adb.h"

#define PS4_SIMULATE			BIT(0)
#define PS4_CLEAN_PROTECTED		BIT(1)
#define PS4_RECURSIVE			BIT(2)
#define PS4_ALLOW_UNTRUSTED		BIT(3)
#define PS4_PURGE			BIT(4)
#define PS4_INTERACTIVE			BIT(5)
#define PS4_NO_NETWORK			BIT(6)
#define PS4_OVERLAY_FROM_STDIN		BIT(7)
#define PS4_NO_SCRIPTS			BIT(8)
#define PS4_NO_CACHE			BIT(9)
#define PS4_NO_COMMIT_HOOKS		BIT(10)
#define PS4_NO_CHROOT			BIT(11)
#define PS4_NO_LOGFILE			BIT(12)
#define PS4_PRESERVE_ENV		BIT(13)

#define PS4_FORCE_OVERWRITE		BIT(0)
#define PS4_FORCE_OLD_PS4		BIT(1)
#define PS4_FORCE_BROKEN_WORLD		BIT(2)
#define PS4_FORCE_REFRESH		BIT(3)
#define PS4_FORCE_NON_REPOSITORY	BIT(4)
#define PS4_FORCE_BINARY_STDOUT		BIT(5)
#define PS4_FORCE_MISSING_REPOSITORIES	BIT(6)

#define PS4_OPENF_READ			0x0001
#define PS4_OPENF_WRITE			0x0002
#define PS4_OPENF_CREATE		0x0004
#define PS4_OPENF_NO_INSTALLED		0x0010
#define PS4_OPENF_NO_SCRIPTS		0x0020
#define PS4_OPENF_NO_WORLD		0x0040
#define PS4_OPENF_NO_SYS_REPOS		0x0100
#define PS4_OPENF_NO_INSTALLED_REPO	0x0200
#define PS4_OPENF_CACHE_WRITE		0x0400
#define PS4_OPENF_NO_AUTOUPDATE		0x0800
#define PS4_OPENF_NO_CMDLINE_REPOS	0x1000
#define PS4_OPENF_USERMODE		0x2000
#define PS4_OPENF_ALLOW_ARCH		0x4000

#define PS4_OPENF_NO_REPOS	(PS4_OPENF_NO_SYS_REPOS |	\
				 PS4_OPENF_NO_CMDLINE_REPOS |	\
				 PS4_OPENF_NO_INSTALLED_REPO)
#define PS4_OPENF_NO_STATE	(PS4_OPENF_NO_INSTALLED |	\
				 PS4_OPENF_NO_SCRIPTS |		\
				 PS4_OPENF_NO_WORLD)

struct ps4_database;

struct ps4_ctx {
	unsigned int flags, force, open_flags;
	unsigned int lock_wait, cache_max_age;
	struct ps4_out out;
	struct ps4_progress progress;
	struct adb_compression_spec compspec;
	const char *root;
	const char *arch;
	const char *keys_dir;
	const char *cache_dir;
	const char *repositories_file;
	const char *uvol;
	struct ps4_string_array *repository_list;
	struct ps4_istream *protected_paths;

	struct ps4_digest_ctx dctx;
	struct ps4_trust trust;
	struct ps4_id_cache id_cache;
	struct ps4_database *db;
	int root_fd, dest_fd;
	unsigned int root_set : 1;
};

void ps4_ctx_init(struct ps4_ctx *ac);
void ps4_ctx_free(struct ps4_ctx *ac);
int ps4_ctx_prepare(struct ps4_ctx *ac);

struct ps4_trust *ps4_ctx_get_trust(struct ps4_ctx *ac);
struct ps4_id_cache *ps4_ctx_get_id_cache(struct ps4_ctx *ac);

static inline int ps4_ctx_fd_root(struct ps4_ctx *ac) { return ac->root_fd; }
static inline int ps4_ctx_fd_dest(struct ps4_ctx *ac) { return ac->dest_fd; }
static inline time_t ps4_ctx_since(struct ps4_ctx *ac, time_t since) {
	return (ac->force & PS4_FORCE_REFRESH) ? PS4_ISTREAM_FORCE_REFRESH : since;
}
static inline const char *ps4_ctx_get_uvol(struct ps4_ctx *ac) { return ac->uvol; }

#endif
