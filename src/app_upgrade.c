/* app_upgrade.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_print.h"
#include "ps4_solver.h"

extern char **ps4_argv;

struct upgrade_ctx {
	unsigned short solver_flags;
	unsigned short no_self_upgrade : 1;
	unsigned short self_upgrade_only : 1;
	unsigned short ignore : 1;
	unsigned short prune : 1;
	int errors;
};

#define UPGRADE_OPTIONS(OPT) \
	OPT(OPT_UPGRADE_available,		PS4_OPT_SH("a") "available") \
	OPT(OPT_UPGRADE_ignore,			"ignore") \
	OPT(OPT_UPGRADE_latest,			PS4_OPT_SH("l") "latest") \
	OPT(OPT_UPGRADE_no_self_upgrade,	"no-self-upgrade") \
	OPT(OPT_UPGRADE_prune,			"prune") \
	OPT(OPT_UPGRADE_self_upgrade_only,	"self-upgrade-only")

PS4_OPT_APPLET(option_desc, UPGRADE_OPTIONS);

static int option_parse_applet(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) ctx;

	switch (opt) {
	case OPT_UPGRADE_no_self_upgrade:
		uctx->no_self_upgrade = 1;
		break;
	case OPT_UPGRADE_self_upgrade_only:
		uctx->self_upgrade_only = 1;
		break;
	case OPT_UPGRADE_ignore:
		uctx->ignore = 1;
		break;
	case OPT_UPGRADE_prune:
		uctx->prune = 1;
		break;
	case OPT_UPGRADE_available:
		uctx->solver_flags |= PS4_SOLVERF_AVAILABLE;
		break;
	case OPT_UPGRADE_latest:
		uctx->solver_flags |= PS4_SOLVERF_LATEST;
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

int ps4_do_self_upgrade(struct ps4_database *db, unsigned short solver_flags, unsigned int self_upgrade_only)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_name *name;
	struct ps4_package *pkg;
	struct ps4_provider *p0;
	struct ps4_changeset changeset = {};
	int r;

	ps4_change_array_init(&changeset.changes);
	name = ps4_db_get_name(db, PS4_BLOB_STR("ps4-tools"));

	/* First check if new version is even available */
	r = 0;
	pkg = ps4_pkg_get_installed(name);
	if (!pkg) goto ret;

	foreach_array_item(p0, name->providers) {
		struct ps4_package *pkg0 = p0->pkg;
		if (pkg0->name != name || pkg0->repos == 0)
			continue;
		if (ps4_version_match(*pkg0->version, PS4_VERSION_GREATER, *pkg->version)) {
			r = 1;
			break;
		}
	}

	if (r == 0) goto ret;

	/* Create new commit upgrading ps4-tools only with minimal other changes */
	db->performing_self_upgrade = 1;
	ps4_solver_set_name_flags(name, solver_flags, 0);

	r = ps4_solver_solve(db, 0, db->world, &changeset);
	if (r != 0) {
		ps4_warn(out, "Failed to perform initial self-upgrade, continuing with full upgrade.");
		r = 0;
		goto ret;
	}

	if (changeset.num_total_changes == 0)
		goto ret;

	if (!self_upgrade_only && db->ctx->flags & PS4_SIMULATE) {
		ps4_warn(out, "This simulation is not reliable as ps4-tools upgrade is available.");
		goto ret;
	}

	ps4_msg(out, "Upgrading critical system libraries and ps4-tools:");
	ps4_solver_commit_changeset(db, &changeset, db->world);
	if (self_upgrade_only) goto ret;

	ps4_db_close(db);
	ps4_msg(out, "Continuing the upgrade transaction with new ps4-tools:");

	for (r = 0; ps4_argv[r] != NULL; r++)
		;
	ps4_argv[r] = "--no-self-upgrade";
	execvp(ps4_argv[0], ps4_argv);

	ps4_err(out, "PANIC! Failed to re-execute new ps4-tools!");
	exit(1);

ret:
	ps4_change_array_free(&changeset.changes);
	db->performing_self_upgrade = 0;
	return r;
}

static int set_upgrade_for_name(struct ps4_database *db, const char *match, struct ps4_name *name, void *pctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) pctx;

	if (!name) {
		ps4_err(out, "Package '%s' not found", match);
		uctx->errors++;
		return 0;
	}

	ps4_solver_set_name_flags(name, uctx->ignore ? PS4_SOLVERF_INSTALLED : PS4_SOLVERF_UPGRADE, 0);
	return 0;
}

static int upgrade_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) ctx;
	unsigned short solver_flags;
	struct ps4_dependency *dep;
	struct ps4_provider *p;
	struct ps4_dependency_array *world;
	int r = 0;

	ps4_dependency_array_init(&world);
	if (ps4_db_check_world(db, db->world) != 0) {
		ps4_err(out,
			"Not continuing with upgrade due to missing repository tags. "
			"Use --force-broken-world to override.");
		return -1;
	}
	if (ps4_db_repository_check(db) != 0) return -1;

	solver_flags = PS4_SOLVERF_UPGRADE | uctx->solver_flags;
	if (!uctx->no_self_upgrade && ps4_array_len(args) == 0) {
		r = ps4_do_self_upgrade(db, solver_flags, uctx->self_upgrade_only);
		if (r != 0)
			return r;
	}
	if (uctx->self_upgrade_only)
		return 0;

	if (uctx->prune || (solver_flags & PS4_SOLVERF_AVAILABLE)) {
		ps4_dependency_array_copy(&world, db->world);
		if (solver_flags & PS4_SOLVERF_AVAILABLE) {
			foreach_array_item(dep, world) {
				if (dep->op == PS4_DEPMASK_CHECKSUM) {
					dep->op = PS4_DEPMASK_ANY;
					dep->version = &ps4_atom_null;
				}
			}
		}
		if (uctx->prune) {
			int i, j;
			for (i = j = 0; i < ps4_array_len(world); i++) {
				foreach_array_item(p, world->item[i].name->providers) {
					if (p->pkg->repos & ~PS4_REPOSITORY_CACHED) {
						world->item[j++] = world->item[i];
						break;
					}
				}
			}
			ps4_array_truncate(world, j);
		}
	} else {
		world = db->world;
	}

	if (ps4_array_len(args) > 0) {
		/* if specific packages are listed, we don't want to upgrade world. */
		if (!uctx->ignore) solver_flags &= ~PS4_SOLVERF_UPGRADE;
		ps4_db_foreach_matching_name(db, args, set_upgrade_for_name, uctx);
		if (uctx->errors) return uctx->errors;
	}

	r = ps4_solver_commit(db, solver_flags, world);

	if (world != db->world) ps4_dependency_array_free(&world);
	return r;
}

static struct ps4_applet ps4_upgrade = {
	.name = "upgrade",
	.open_flags = PS4_OPENF_WRITE,
	.context_size = sizeof(struct upgrade_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = upgrade_main,
};

PS4_DEFINE_APPLET(ps4_upgrade);

