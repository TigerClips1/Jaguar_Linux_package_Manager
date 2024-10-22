/* app_cache.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_package.h"
#include "ps4_print.h"
#include "ps4_solver.h"

#define CACHE_CLEAN	BIT(0)
#define CACHE_DOWNLOAD	BIT(1)

struct cache_ctx {
	unsigned short solver_flags;
	unsigned short add_dependencies : 1;
};

#define CACHE_OPTIONS(OPT) \
	OPT(OPT_CACHE_add_dependencies,	"add-dependencies") \
	OPT(OPT_CACHE_available,	PS4_OPT_SH("a") "available") \
	OPT(OPT_CACHE_ignore_conflict,	"ignore-conflict") \
	OPT(OPT_CACHE_latest,		PS4_OPT_SH("l") "latest") \
	OPT(OPT_CACHE_upgrade,		PS4_OPT_SH("u") "upgrade") \
	OPT(OPT_CACHE_simulate,		PS4_OPT_SH("s") "simulate") \

PS4_OPT_APPLET(option_desc, CACHE_OPTIONS);

static int option_parse_applet(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct cache_ctx *cctx = (struct cache_ctx *) ctx;

	switch (opt) {
	case OPT_CACHE_add_dependencies:
		cctx->add_dependencies = 1;
		break;
	case OPT_CACHE_available:
		cctx->solver_flags |= PS4_SOLVERF_AVAILABLE;
		break;
	case OPT_CACHE_ignore_conflict:
		cctx->solver_flags |= PS4_SOLVERF_IGNORE_CONFLICT;
		break;
	case OPT_CACHE_latest:
		cctx->solver_flags |= PS4_SOLVERF_LATEST;
		break;
	case OPT_CACHE_upgrade:
		cctx->solver_flags |= PS4_SOLVERF_UPGRADE;
		break;
	case OPT_CACHE_simulate:
		ac->flags |= PS4_SIMULATE;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct ps4_option_group optgroup_applet = {
	.desc = option_desc,
	.parse = option_parse_applet,
};

struct progress {
	struct ps4_progress prog;
	size_t done, total;
};

static void progress_cb(void *ctx, size_t bytes_done)
{
	struct progress *prog = (struct progress *) ctx;
	ps4_print_progress(&prog->prog, prog->done + bytes_done, prog->total);
}

static int cache_download(struct cache_ctx *cctx, struct ps4_database *db, struct ps4_string_array *args)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_changeset changeset = {};
	struct ps4_change *change;
	struct ps4_package *pkg;
	struct ps4_repository *repo;
	struct ps4_dependency_array *deps;
	struct ps4_dependency dep;
	struct progress prog = { .prog = db->ctx->progress };
	int i, r, ret = 0;

	ps4_dependency_array_init(&deps);
	if (ps4_array_len(args) == 1 || cctx->add_dependencies)
		ps4_dependency_array_copy(&deps, db->world);
	for (i = 1; i < ps4_array_len(args); i++) {
		ps4_blob_t b = PS4_BLOB_STR(args->item[i]);
		ps4_blob_pull_dep(&b, db, &dep);
		if (ps4_BLOB_IS_NULL(b)) {
			ps4_err(out, "bad dependency: %s", args->item[i]);
			return -EINVAL;
		}
		ps4_dependency_array_add(&deps, dep);
	}
	r = ps4_solver_solve(db, cctx->solver_flags, deps, &changeset);
	ps4_dependency_array_free(&deps);
	if (r < 0) {
		ps4_err(out, "Unable to select packages. Run ps4 fix.");
		return r;
	}

	foreach_array_item(change, changeset.changes) {
		pkg = change->new_pkg;
		if (!pkg || (pkg->repos & db->local_repos) || !pkg->installed_size)
			continue;
		if (!ps4_db_select_repo(db, pkg)) continue;
		prog.total += pkg->size;
	}

	foreach_array_item(change, changeset.changes) {
		pkg = change->new_pkg;
		if (!pkg || (pkg->repos & db->local_repos) || !pkg->installed_size)
			continue;

		repo = ps4_db_select_repo(db, pkg);
		if (repo == NULL)
			continue;

		r = ps4_cache_download(db, repo, pkg, 0, progress_cb, &prog);
		if (r && r != -EALREADY) {
			ps4_err(out, PKG_VER_FMT ": %s", PKG_VER_PRINTF(pkg), ps4_error_str(r));
			ret++;
		}
		prog.done += pkg->size;
	}

	return ret;
}

static void cache_clean_item(struct ps4_database *db, int static_cache, int dirfd, const char *name, struct ps4_package *pkg)
{
	struct ps4_out *out = &db->ctx->out;
	char tmp[PATH_MAX];
	ps4_blob_t b;
	int i;

	if (!static_cache) {
		if (strcmp(name, "installed") == 0) return;
		if (pkg) {
			if (db->ctx->flags & PS4_PURGE) {
				if (db->permanent || !pkg->ipkg) goto delete;
			}
			if (pkg->repos & db->local_repos & ~BIT(PS4_REPOSITORY_CACHED)) goto delete;
			if (pkg->ipkg == NULL && !(pkg->repos & ~BIT(PS4_REPOSITORY_CACHED))) goto delete;
			return;
		}
	}

	b = PS4_BLOB_STR(name);
	for (i = 0; i < db->num_repos; i++) {
		/* Check if this is a valid index */
		ps4_repo_format_cache_index(PS4_BLOB_BUF(tmp), &db->repos[i]);
		if (ps4_blob_compare(b, PS4_BLOB_STR(tmp)) == 0) return;
	}

delete:
	ps4_dbg(out, "deleting %s", name);
	if (!(db->ctx->flags & PS4_SIMULATE)) {
		if (unlinkat(dirfd, name, 0) < 0 && errno == EISDIR)
			unlinkat(dirfd, name, AT_REMOVEDIR);
	}
}

static int cache_clean(struct ps4_database *db)
{
	if (ps4_db_cache_active(db)) {
		int r = ps4_db_cache_foreach_item(db, cache_clean_item, 0);
		if (r) return r;
	}
	return ps4_db_cache_foreach_item(db, cache_clean_item, 1);
}

static int cache_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_database *db = ac->db;
	struct cache_ctx *cctx = (struct cache_ctx *) ctx;
	char *arg;
	int r = 0, actions = 0;

	if (ps4_array_len(args) < 1) return -EINVAL;
	arg = args->item[0];
	if (strcmp(arg, "sync") == 0) {
		actions = CACHE_CLEAN | CACHE_DOWNLOAD;
	} else if (strcmp(arg, "clean") == 0) {
		actions = CACHE_CLEAN;
	} else if (strcmp(arg, "purge") == 0) {
		actions = CACHE_CLEAN;
		db->ctx->flags |= PS4_PURGE;
	} else if (strcmp(arg, "download") == 0) {
		actions = CACHE_DOWNLOAD;
	} else
		return -EINVAL;

	if (!ps4_db_cache_active(db))
		actions &= CACHE_CLEAN;

	if ((actions & CACHE_DOWNLOAD) && (cctx->solver_flags || cctx->add_dependencies)) {
		if (ps4_db_repository_check(db) != 0) return 3;
	}

	if (r == 0 && (actions & CACHE_CLEAN))
		r = cache_clean(db);
	if (r == 0 && (actions & CACHE_DOWNLOAD))
		r = cache_download(cctx, db, args);

	return r;
}

static struct ps4_applet ps4_cache = {
	.name = "cache",
	.open_flags = PS4_OPENF_READ|PS4_OPENF_NO_SCRIPTS|PS4_OPENF_CACHE_WRITE,
	.context_size = sizeof(struct cache_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = cache_main,
};

PS4_DEFINE_APPLET(ps4_cache);
