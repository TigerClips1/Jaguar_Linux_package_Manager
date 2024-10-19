/* app_version.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_version.h"
#include "ps4_print.h"

struct ver_ctx {
	int (*action)(struct ps4_database *db, struct ps4_string_array *args);
	const char *limchars;
	unsigned int max_pkg_len;
	unsigned short all_tags : 1;
};

static int ver_indexes(struct ps4_database *db, struct ps4_string_array *args)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_repository *repo;
	int i;

	for (i = 0; i < db->num_repos; i++) {
		repo = &db->repos[i];

		if (ps4_BLOB_IS_NULL(repo->description))
			continue;

		ps4_out(out, BLOB_FMT " [%s]",
			BLOB_PRINTF(repo->description),
			db->repos[i].url);
	}

	return 0;
}

static int ver_test(struct ps4_database *db, struct ps4_string_array *args)
{
	struct ps4_out *out = &db->ctx->out;
	int r;

	if (ps4_array_len(args) != 2) return 1;
	r = ps4_version_compare(PS4_BLOB_STR(args->item[0]), PS4_BLOB_STR(args->item[1]));
	ps4_out(out, "%s", ps4_version_op_string(r));
	return 0;
}

static int ver_validate(struct ps4_database *db, struct ps4_string_array *args)
{
	struct ps4_out *out = &db->ctx->out;
	char **parg;
	int errors = 0;

	foreach_array_item(parg, args) {
		if (!ps4_version_validate(PS4_BLOB_STR(*parg))) {
			ps4_msg(out, "%s", *parg);
			errors++;
		}
	}
	return errors;
}

#define VERSION_OPTIONS(OPT) \
	OPT(OPT_VERSION_all,		PS4_OPT_SH("a") "all") \
	OPT(OPT_VERSION_check,		PS4_OPT_SH("c") "check") \
	OPT(OPT_VERSION_indexes,	PS4_OPT_SH("I") "indexes") \
	OPT(OPT_VERSION_limit,		PS4_OPT_ARG PS4_OPT_SH("l") "limit") \
	OPT(OPT_VERSION_test,		PS4_OPT_SH("t") "test")

PS4_OPT_APPLET(option_desc, VERSION_OPTIONS);

static int option_parse_applet(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct ver_ctx *ictx = (struct ver_ctx *) ctx;
	switch (opt) {
	case OPT_VERSION_all:
		ictx->all_tags = 1;
		break;
	case OPT_VERSION_check:
		ictx->action = ver_validate;
		ac->open_flags |= PS4_OPENF_NO_STATE | PS4_OPENF_NO_REPOS;
		break;
	case OPT_VERSION_indexes:
		ictx->action = ver_indexes;
		break;
	case OPT_VERSION_limit:
		ictx->limchars = optarg;
		break;
	case OPT_VERSION_test:
		ictx->action = ver_test;
		ac->open_flags |= PS4_OPENF_NO_STATE | PS4_OPENF_NO_REPOS;
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

struct ver_name_state {
	struct ps4_package *installed, *latest;
	unsigned short tag, ver_result;
};

static struct ver_name_state *state_from_name(struct ps4_name *name)
{
	static_assert(sizeof name->state_buf >= sizeof(struct ver_name_state), "buffer size mismatch");
	return (struct ver_name_state *) &name->state_buf[0];
}

static int ver_calculate_length(struct ps4_database *db, const char *match, struct ps4_name *name, void *pctx)
{
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;
	struct ps4_package *installed, *latest;
	struct ps4_provider *p0;
	struct ver_name_state *ns;
	unsigned int latest_repos = 0;
	unsigned short tag, allowed_repos;
	const char *opstr;
	int i, r, len;

	if (!name) return 0;

	installed = latest = ps4_pkg_get_installed(name);
	if (!installed) return 0;

	allowed_repos = db->repo_tags[installed->ipkg->repository_tag].allowed_repos;
	foreach_array_item(p0, name->providers) {
		struct ps4_package *pkg0 = p0->pkg;
		if (pkg0->name != name || pkg0->repos == 0)
			continue;
		if (!(ctx->all_tags || (pkg0->repos & allowed_repos)))
			continue;
		r = ps4_version_compare(*pkg0->version, *latest->version);
		switch (r) {
		case PS4_VERSION_GREATER:
			latest = pkg0;
			latest_repos = pkg0->repos;
			break;
		case PS4_VERSION_EQUAL:
			latest_repos |= pkg0->repos;
			break;
		}
	}

	ns = state_from_name(name);
	r = ps4_version_compare(*installed->version, *latest->version);
	opstr = ps4_version_op_string(r);
	if ((ctx->limchars != NULL) && (strchr(ctx->limchars, *opstr) == NULL))
		return 0;

	tag = PS4_DEFAULT_REPOSITORY_TAG;
	for (i = 1; i < db->num_repo_tags; i++) {
		if (latest_repos & db->repo_tags[i].allowed_repos) {
			tag = i;
			break;
		}
	}

	*ns = (struct ver_name_state) {
		.installed = installed,
		.latest = latest,
		.tag = tag,
		.ver_result = r,
	};

	len = PKG_VER_STRLEN(installed);
	if (len > ctx->max_pkg_len) ctx->max_pkg_len = len;
	return 0;
}

static int ver_print_package_status(struct ps4_database *db, const char *match, struct ps4_name *name, void *pctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;
	struct ver_name_state *ns;

	if (!name) return 0;

	ns = state_from_name(name);
	if (!ns->installed) return 0;

	if (ps4_out_verbosity(out) <= 0) {
		ps4_out(out, "%s", name->name);
		return 0;
	}

	ps4_out(out, PKG_VER_FMT "%*s %s " BLOB_FMT " " BLOB_FMT,
		PKG_VER_PRINTF(ns->installed),
		(int)(ctx->max_pkg_len - PKG_VER_STRLEN(ns->installed)), "",
		ps4_version_op_string(ns->ver_result),
		BLOB_PRINTF(*ns->latest->version),
		BLOB_PRINTF(db->repo_tags[ns->tag].tag));
	return 0;
}

static int ver_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;

	ctx->max_pkg_len = 39;
	if (ctx->limchars) {
		if (strlen(ctx->limchars) == 0)
			ctx->limchars = NULL;
	} else if (ps4_array_len(args) == 0 && ps4_out_verbosity(out) == 1) {
		ctx->limchars = "<";
	}

	if (ctx->action != NULL)
		return ctx->action(db, args);

	ps4_db_foreach_matching_name(db, args, ver_calculate_length, ctx);

	ps4_msg(out, "%*s   %s", -ctx->max_pkg_len, "Installed:", "Available:");
	ps4_db_foreach_sorted_name(db, args, ver_print_package_status, ctx);
	return 0;
}

static struct ps4_applet ps4_ver = {
	.name = "version",
	.open_flags = PS4_OPENF_READ,
	.context_size = sizeof(struct ver_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = ver_main,
};

PS4_DEFINE_APPLET(ps4_ver);
