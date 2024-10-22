/* app_del.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_print.h"
#include "ps4_solver.h"

struct del_ctx {
	struct ps4_dependency_array *world;
	unsigned short recursive_delete : 1;
	unsigned int genid;
	int errors;
};

#define DEL_OPTIONS(OPT) \
	OPT(OPT_DEL_redepends,	PS4_OPT_SH("r") "rdepends")

PS4_OPT_APPLET(option_desc, DEL_OPTIONS);

static int option_parse_applet(void *pctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct del_ctx *ctx = (struct del_ctx *) pctx;

	switch (opt) {
	case OPT_DEL_redepends:
		ctx->recursive_delete = 1;
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

struct not_deleted_ctx {
	struct ps4_out *out;
	struct ps4_indent indent;
	struct ps4_name *name;
	unsigned int matches;
	int header;
};

static inline int name_in_world(struct ps4_name *n)
{
	return n->state_int == 1;
}

static void print_not_deleted_pkg(struct ps4_package *pkg0, struct ps4_dependency *dep0,
				  struct ps4_package *pkg, void *pctx)
{
	struct not_deleted_ctx *ctx = (struct not_deleted_ctx *) pctx;
	struct ps4_out *out = ctx->out;
	struct ps4_dependency *d;
	struct ps4_provider *p;

	if (!ctx->header) {
		ps4_msg(out, "World updated, but the following packages are not removed due to:");
		ctx->header = 1;
	}
	if (!ctx->indent.indent)
		ps4_print_indented_group(&ctx->indent, 0, "  %s:", ctx->name->name);
	if (name_in_world(pkg0->name))
		ps4_print_indented(&ctx->indent, PS4_BLOB_STR(pkg0->name->name));
	foreach_array_item(d, pkg0->provides) {
		if (!name_in_world(d->name)) continue;
		ps4_print_indented(&ctx->indent, PS4_BLOB_STR(d->name->name));
	}

	ps4_pkg_foreach_reverse_dependency(pkg0, ctx->matches, print_not_deleted_pkg, pctx);
	foreach_array_item(d, pkg0->install_if) {
		foreach_array_item(p, d->name->providers) {
			if (!p->pkg->marked) continue;
			if (ps4_pkg_match_genid(p->pkg, ctx->matches)) continue;
			print_not_deleted_pkg(p->pkg, NULL, NULL, pctx);
		}
	}
}

static int print_not_deleted_name(struct ps4_database *db, const char *match,
				  struct ps4_name *name, void *pctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct not_deleted_ctx *ctx = (struct not_deleted_ctx *) pctx;
	struct ps4_provider *p;

	if (!name) return 0;

	ctx->name = name;
	ctx->matches = ps4_foreach_genid() | PS4_FOREACH_MARKED | PS4_DEP_SATISFIES;
	ps4_print_indented_init(&ctx->indent, out, 0);
	foreach_array_item(p, name->providers)
		if (p->pkg->marked)
			print_not_deleted_pkg(p->pkg, NULL, NULL, ctx);
	ps4_print_indented_end(&ctx->indent);
	return 0;
}

static void delete_pkg(struct ps4_package *pkg0, struct ps4_dependency *dep0,
		       struct ps4_package *pkg, void *pctx)
{
	struct del_ctx *ctx = (struct del_ctx *) pctx;
	struct ps4_dependency *d;

	ps4_deps_del(&ctx->world, pkg0->name);
	ps4_solver_set_name_flags(pkg0->name, PS4_SOLVERF_REMOVE, 0);

	if (ctx->recursive_delete) {
		foreach_array_item(d, pkg0->provides)
			ps4_deps_del(&ctx->world, d->name);

		ps4_pkg_foreach_reverse_dependency(
			pkg0, ctx->genid | PS4_FOREACH_INSTALLED | PS4_DEP_SATISFIES,
			delete_pkg, pctx);
	}
}

static int delete_name(struct ps4_database *db, const char *match,
			struct ps4_name *name, void *pctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct del_ctx *ctx = (struct del_ctx *) pctx;
	struct ps4_package *pkg;

	if (!name) {
		ps4_err(out, "No such package: %s", match);
		ctx->errors++;
		return 0;
	}

	pkg = ps4_pkg_get_installed(name);
	if (pkg != NULL)
		delete_pkg(pkg, NULL, NULL, pctx);
	else
		ps4_deps_del(&ctx->world, name);
	return 0;
}

static int del_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_database *db = ac->db;
	struct del_ctx *ctx = (struct del_ctx *) pctx;
	struct not_deleted_ctx ndctx = { .out = &db->ctx->out };
	struct ps4_changeset changeset = {};
	struct ps4_change *change;
	struct ps4_dependency *d;
	int r = 0;

	ps4_change_array_init(&changeset.changes);
	ctx->genid = ps4_foreach_genid();
	ps4_dependency_array_init(&ctx->world);
	ps4_dependency_array_copy(&ctx->world, db->world);
	if (ps4_array_len(args)) ps4_db_foreach_matching_name(db, args, delete_name, ctx);
	if (ctx->errors) return ctx->errors;

	r = ps4_solver_solve(db, 0, ctx->world, &changeset);
	if (r == 0) {
		if (ps4_out_verbosity(&db->ctx->out) >= 1) {
			/* check for non-deleted package names */
			foreach_array_item(change, changeset.changes)
				if (change->new_pkg != NULL)
					change->new_pkg->marked = 1;
			foreach_array_item(d, ctx->world)
				d->name->state_int = 1;
			if (ps4_array_len(args))
				ps4_db_foreach_sorted_name(db, args, print_not_deleted_name, &ndctx);
			if (ndctx.header)
				printf("\n");
		}

		r = ps4_solver_commit_changeset(db, &changeset, ctx->world);
	} else {
		ps4_solver_print_errors(db, &changeset, ctx->world);
	}
	ps4_change_array_free(&changeset.changes);
	ps4_dependency_array_free(&ctx->world);

	return r;
}

static struct ps4_applet ps4_del = {
	.name = "del",
	.open_flags = PS4_OPENF_WRITE | PS4_OPENF_NO_AUTOUPDATE,
	.remove_empty_arguments = 1,
	.context_size = sizeof(struct del_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = del_main,
};

PS4_DEFINE_APPLET(ps4_del);
