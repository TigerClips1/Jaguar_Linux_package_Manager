/* app_fix.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_print.h"
#include "ps4_solver.h"
#include "ps4_fs.h"

struct fix_ctx {
	struct ps4_database *db;
	unsigned short solver_flags;
	unsigned short fix_depends : 1;
	unsigned short fix_xattrs : 1;
	unsigned short fix_directory_permissions : 1;
	int errors;
};

#define FIX_OPTIONS(OPT) \
	OPT(OPT_FIX_depends,			PS4_OPT_SH("d") "depends") \
	OPT(OPT_FIX_directory_permissions,	"directory-permissions") \
	OPT(OPT_FIX_reinstall,			PS4_OPT_SH("r") "reinstall") \
	OPT(OPT_FIX_upgrade,			PS4_OPT_SH("u") "upgrade") \
	OPT(OPT_FIX_xattr,			PS4_OPT_SH("x") "xattr")

PS4_OPT_APPLET(option_desc, FIX_OPTIONS);

static int option_parse_applet(void *pctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	switch (opt) {
	case OPT_FIX_depends:
		ctx->fix_depends = 1;
		break;
	case OPT_FIX_directory_permissions:
		ctx->fix_directory_permissions = 1;
		break;
	case OPT_FIX_reinstall:
		ctx->solver_flags |= PS4_SOLVERF_REINSTALL;
		break;
	case OPT_FIX_upgrade:
		ctx->solver_flags |= PS4_SOLVERF_UPGRADE;
		break;
	case OPT_FIX_xattr:
		ctx->fix_xattrs = 1;
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

static int fix_directory_permissions(ps4_hash_item item, void *pctx)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	struct ps4_database *db = ctx->db;
	struct ps4_out *out = &db->ctx->out;
	struct ps4_db_dir *dir = (struct ps4_db_dir *) item;

	if (dir->namelen == 0 || !dir->refs) return 0;

	ps4_db_dir_prepare(db, dir, dir->owner->acl, dir->owner->acl);
	if (dir->permissions_ok) return 0;

	ps4_dbg(out, "fixing directory %s", dir->name);
	dir->permissions_ok = 1;
	ps4_db_dir_update_permissions(db, dir->owner);
	return 0;
}

static void mark_fix(struct fix_ctx *ctx, struct ps4_name *name)
{
	ps4_solver_set_name_flags(name, ctx->solver_flags, ctx->fix_depends ? ctx->solver_flags : 0);
}

static int set_solver_flags(struct ps4_database *db, const char *match, struct ps4_name *name, void *pctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct fix_ctx *ctx = pctx;

	if (!name) {
		ps4_err(out, "Package '%s' not found", match);
		ctx->errors++;
		return 0;
	}

	mark_fix(ctx, name);
	return 0;
}

static int fix_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_database *db = ac->db;
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	struct ps4_installed_package *ipkg;

	ctx->db = db;
	if (!ctx->solver_flags)
		ctx->solver_flags = PS4_SOLVERF_REINSTALL;

	if (ps4_array_len(args) == 0) {
		list_for_each_entry(ipkg, &db->installed.packages, installed_pkgs_list) {
			if (ipkg->broken_files || ipkg->broken_script ||
			    (ipkg->broken_xattr && ctx->fix_xattrs))
				mark_fix(ctx, ipkg->pkg->name);
		}
	} else
		ps4_db_foreach_matching_name(db, args, set_solver_flags, ctx);

	if (ctx->errors) return ctx->errors;

	if (ctx->fix_directory_permissions) {
		ps4_hash_foreach(&db->installed.dirs, fix_directory_permissions, ctx);
		if (db->num_dir_update_errors) {
			ps4_err(&ac->out, "Failed to fix directory permissions");
			return -1;
		}
	}

	return ps4_solver_commit(db, 0, db->world);
}

static struct ps4_applet ps4_fix = {
	.name = "fix",
	.open_flags = PS4_OPENF_WRITE,
	.remove_empty_arguments = 1,
	.context_size = sizeof(struct fix_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = fix_main,
};

PS4_DEFINE_APPLET(ps4_fix);

