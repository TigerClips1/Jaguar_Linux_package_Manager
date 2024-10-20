/* app_info.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2009 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_package.h"
#include "ps4_database.h"
#include "ps4_print.h"

struct info_ctx {
	struct ps4_database *db;
	void (*action)(struct info_ctx *ctx, struct ps4_database *db, struct ps4_string_array *args);
	int subaction_mask;
	int errors;
};

static int verbosity = 0;

/* These need to stay in sync with the function pointer array in
 * info_subaction() */
#define PS4_INFO_DESC		0x01
#define PS4_INFO_URL		0x02
#define PS4_INFO_SIZE		0x04
#define PS4_INFO_DEPENDS	0x08
#define PS4_INFO_PROVIDES	0x10
#define PS4_INFO_RDEPENDS	0x20
#define PS4_INFO_CONTENTS	0x40
#define PS4_INFO_TRIGGERS	0x80
#define PS4_INFO_INSTALL_IF	0x100
#define PS4_INFO_RINSTALL_IF	0x200
#define PS4_INFO_REPLACES	0x400
#define PS4_INFO_LICENSE	0x800

static void verbose_print_pkg(struct ps4_package *pkg, int minimal_verbosity)
{
	int v = min(verbosity, minimal_verbosity);
	if (pkg == NULL || v < 1) return;
	printf("%s", pkg->name->name);
	if (v > 1) printf("-" BLOB_FMT, BLOB_PRINTF(*pkg->version));
	if (v > 2) printf(" - " BLOB_FMT, BLOB_PRINTF(*pkg->description));
	printf("\n");
}

static void info_exists(struct info_ctx *ctx, struct ps4_database *db,
			struct ps4_string_array *args)
{
	struct ps4_name *name;
	struct ps4_dependency dep;
	struct ps4_provider *p;
	char **parg;
	int ok;

	foreach_array_item(parg, args) {
		ps4_blob_t b = PS4_BLOB_STR(*parg);

		ps4_blob_pull_dep(&b, db, &dep);
		if (PS4_BLOB_IS_NULL(b) || b.len > 0)
			continue;

		name = dep.name;
		if (name == NULL)
			continue;

		ok = ps4_dep_is_provided(NULL, &dep, NULL);
		foreach_array_item(p, name->providers) {
			if (!p->pkg->ipkg) continue;
			ok = ps4_dep_is_provided(NULL, &dep, p);
			if (ok) verbose_print_pkg(p->pkg, 0);
			break;
		}
		if (!ok) ctx->errors++;
	}
}

static struct ps4_package *get_owner(struct ps4_database *db, ps4_blob_t fn)
{
	struct ps4_db_dir *dir;

	ps4_blob_pull_blob_match(&fn, PS4_BLOB_STRLIT("/"));
	if (fn.len && fn.ptr[fn.len-1] == '/') fn.len--;

	dir = ps4_db_dir_query(db, fn);
	if (dir) return dir->owner->pkg;
	return ps4_db_get_file_owner(db, fn);
}

static void info_who_owns(struct info_ctx *ctx, struct ps4_database *db,
			  struct ps4_string_array *args)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_package *pkg;
	struct ps4_dependency_array *deps;
	struct ps4_dependency dep;
	struct ps4_ostream *os;
	const char *via;
	char **parg, fnbuf[PATH_MAX], buf[PATH_MAX];
	ps4_blob_t fn;
	ssize_t r;

	ps4_dependency_array_init(&deps);
	foreach_array_item(parg, args) {
		if (*parg[0] != '/' && realpath(*parg, fnbuf))
			fn = ps4_BLOB_STR(fnbuf);
		else
			fn = ps4_BLOB_STR(*parg);

		via = "";

		pkg = get_owner(db, fn);
		if (pkg == NULL) {
			r = readlinkat(db->root_fd, *parg, buf, sizeof(buf));
			if (r > 0 && r < PATH_MAX && buf[0] == '/') {
				pkg = get_owner(db, PS4_BLOB_STR(buf));
				via = "symlink target ";
			}
		}

		if (pkg == NULL) {
			ps4_err(out, BLOB_FMT ": Could not find owner package",
				BLOB_PRINTF(fn));
			ctx->errors++;
			continue;
		}

		if (verbosity < 1) {
			dep = (struct ps4_dependency) {
				.name = pkg->name,
				.version = &ps4_atom_null,
				.op = PS4_DEPMASK_ANY,
			};
			ps4_deps_add(&deps, &dep);
		} else {
			printf(BLOB_FMT " %sis owned by " PKG_VER_FMT "\n",
			       BLOB_PRINTF(fn), via, PKG_VER_PRINTF(pkg));
		}
	}
	if (verbosity < 1 && ps4_array_len(deps) != 0) {
		os = ps4_ostream_to_fd(STDOUT_FILENO);
		if (!IS_ERR(os)) {
			ps4_deps_write(db, deps, os, PS4_BLOB_PTR_LEN(" ", 1));
			ps4_ostream_write(os, "\n", 1);
			ps4_ostream_close(os);
		}
	}
	ps4_dependency_array_free(&deps);
}

static void info_print_description(struct ps4_database *db, struct ps4_package *pkg)
{
	if (verbosity > 1)
		printf("%s: " BLOB_FMT, pkg->name->name, BLOB_PRINTF(*pkg->description));
	else
		printf(PKG_VER_FMT " description:\n" BLOB_FMT "\n",
		       PKG_VER_PRINTF(pkg),
		       BLOB_PRINTF(*pkg->description));
}

static void info_print_url(struct ps4_database *db, struct ps4_package *pkg)
{
	if (verbosity > 1)
		printf("%s: " BLOB_FMT, pkg->name->name, BLOB_PRINTF(*pkg->url));
	else
		printf(PKG_VER_FMT " webpage:\n" BLOB_FMT "\n",
		       PKG_VER_PRINTF(pkg),
		       BLOB_PRINTF(*pkg->url));
}

static void info_print_license(struct ps4_database *db, struct ps4_package *pkg)
{
	if (verbosity > 1)
		printf("%s: " BLOB_FMT , pkg->name->name, BLOB_PRINTF(*pkg->license));
	else
		printf(PKG_VER_FMT " license:\n" BLOB_FMT "\n",
		       PKG_VER_PRINTF(pkg),
		       BLOB_PRINTF(*pkg->license));
}

static void info_print_size(struct ps4_database *db, struct ps4_package *pkg)
{
	off_t size;
	const char *size_unit;

	size_unit = ps4_get_human_size(pkg->installed_size, &size);
	if (verbosity > 1)
		printf("%s: %lld %s", pkg->name->name,
		       (long long)size, size_unit);
	else
		printf(PKG_VER_FMT " installed size:\n%lld %s\n",
		       PKG_VER_PRINTF(pkg), (long long)size, size_unit);
}

static void info_print_dep_array(struct ps4_database *db, struct ps4_package *pkg,
				 struct ps4_dependency_array *deps, const char *dep_text)
{
	struct ps4_dependency *d;
	ps4_blob_t separator = PS4_BLOB_STR(verbosity > 1 ? " " : "\n");
	char buf[256];

	if (verbosity == 1)
		printf(PKG_VER_FMT " %s:\n", PKG_VER_PRINTF(pkg), dep_text);
	if (verbosity > 1)
		printf("%s: ", pkg->name->name);
	foreach_array_item(d, deps) {
		ps4_blob_t b = PS4_BLOB_BUF(buf);
		ps4_blob_push_dep(&b, db, d);
		ps4_blob_push_blob(&b, separator);
		b = ps4_blob_pushed(PS4_BLOB_BUF(buf), b);
		fwrite(b.ptr, b.len, 1, stdout);
	}
}

static void info_print_depends(struct ps4_database *db, struct ps4_package *pkg)
{
	info_print_dep_array(db, pkg, pkg->depends, "depends on");
}

static void info_print_provides(struct ps4_database *db, struct ps4_package *pkg)
{
	info_print_dep_array(db, pkg, pkg->provides, "provides");
}

static void print_rdep_pkg(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *pctx)
{
	printf(PKG_VER_FMT "%s", PKG_VER_PRINTF(pkg0), verbosity > 1 ? " " : "\n");
}

static void info_print_required_by(struct ps4_database *db, struct ps4_package *pkg)
{
	if (verbosity == 1)
		printf(PKG_VER_FMT " is required by:\n", PKG_VER_PRINTF(pkg));
	if (verbosity > 1)
		printf("%s: ", pkg->name->name);
	ps4_pkg_foreach_reverse_dependency(
		pkg,
		PS4_FOREACH_INSTALLED | PS4_DEP_SATISFIES | ps4_foreach_genid(),
		print_rdep_pkg, NULL);
}

static void info_print_install_if(struct ps4_database *db, struct ps4_package *pkg)
{
	info_print_dep_array(db, pkg, pkg->install_if, "has auto-install rule");
}

static void info_print_rinstall_if(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_name **name0;
	struct ps4_dependency *dep;
	char *separator = verbosity > 1 ? " " : "\n";

	if (verbosity == 1)
		printf(PKG_VER_FMT " affects auto-installation of:\n",
		       PKG_VER_PRINTF(pkg));
	if (verbosity > 1)
		printf("%s: ", pkg->name->name);

	foreach_array_item(name0, pkg->name->rinstall_if) {
		/* Check only the package that is installed, and that
		 * it actually has this package in install_if. */
		struct ps4_package *pkg0 = ps4_pkg_get_installed(*name0);
		if (pkg0 == NULL) continue;
		foreach_array_item(dep, pkg0->install_if) {
			if (dep->name != pkg->name) continue;
			printf(PKG_VER_FMT "%s",
			       PKG_VER_PRINTF(pkg0),
			       separator);
			break;
		}
	}
}

static void info_print_contents(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_installed_package *ipkg = pkg->ipkg;
	struct ps4_db_dir_instance *diri;
	struct ps4_db_file *file;
	struct hlist_node *dc, *dn, *fc, *fn;

	if (verbosity == 1)
		printf(PKG_VER_FMT " contains:\n",
		       PKG_VER_PRINTF(pkg));

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs,
				  pkg_dirs_list) {
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files,
					  diri_files_list) {
			if (verbosity > 1)
				printf("%s: ", pkg->name->name);
			printf(DIR_FILE_FMT "\n", DIR_FILE_PRINTF(diri->dir, file));
		}
	}
}

static void info_print_triggers(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_installed_package *ipkg = pkg->ipkg;
	char **trigger;

	if (verbosity == 1)
		printf(PKG_VER_FMT " triggers:\n",
		       PKG_VER_PRINTF(pkg));

	foreach_array_item(trigger, ipkg->triggers) {
		if (verbosity > 1)
			printf("%s: trigger ", pkg->name->name);
		printf("%s\n", *trigger);
	}
}

static void info_print_replaces(struct ps4_database *db, struct ps4_package *pkg)
{
	info_print_dep_array(db, pkg, pkg->ipkg->replaces, "replaces");
}

static void info_subaction(struct info_ctx *ctx, struct ps4_package *pkg)
{
	typedef void (*subaction_t)(struct ps4_database *, struct ps4_package *);
	static subaction_t subactions[] = {
		info_print_description,
		info_print_url,
		info_print_size,
		info_print_depends,
		info_print_provides,
		info_print_required_by,
		info_print_contents,
		info_print_triggers,
		info_print_install_if,
		info_print_rinstall_if,
		info_print_replaces,
		info_print_license,
	};
	const int requireipkg =
		PS4_INFO_CONTENTS | PS4_INFO_TRIGGERS | PS4_INFO_RDEPENDS |
		PS4_INFO_RINSTALL_IF | PS4_INFO_REPLACES;
	int i;

	for (i = 0; i < ARRAY_SIZE(subactions); i++) {
		if (!(BIT(i) & ctx->subaction_mask))
			continue;

		if (pkg->ipkg == NULL && (BIT(i) & requireipkg))
			continue;

		subactions[i](ctx->db, pkg);
		puts("");
	}
}

static int print_name_info(struct ps4_database *db, const char *match, struct ps4_package *pkg, void *pctx)
{
	struct info_ctx *ctx = (struct info_ctx *) pctx;

	if (!pkg) {
		ctx->errors++;
		return 0;
	}

	info_subaction(ctx, pkg);
	return 0;
}

#define INFO_OPTIONS(OPT) \
	OPT(OPT_INFO_all,		PS4_OPT_SH("a") "all") \
	OPT(OPT_INFO_contents,		PS4_OPT_SH("L") "contents") \
	OPT(OPT_INFO_depends,		PS4_OPT_SH("R") "depends") \
	OPT(OPT_INFO_description,	PS4_OPT_SH("d") "description") \
	OPT(OPT_INFO_install_if,	"install-if") \
	OPT(OPT_INFO_installed,		PS4_OPT_SH("e") "installed") \
	OPT(OPT_INFO_license,		"license") \
	OPT(OPT_INFO_provides,		PS4_OPT_SH("P") "provides") \
	OPT(OPT_INFO_rdepends,		PS4_OPT_SH("r") "rdepends") \
	OPT(OPT_INFO_replaces,		"replaces") \
	OPT(OPT_INFO_rinstall_if,	"rinstall-if") \
	OPT(OPT_INFO_size,		PS4_OPT_SH("s") "size") \
	OPT(OPT_INFO_triggers,		PS4_OPT_SH("t") "triggers") \
	OPT(OPT_INFO_webpage,		PS4_OPT_SH("w") "webpage") \
	OPT(OPT_INFO_who_owns,		PS4_OPT_SH("W") "who-owns")

PS4_OPT_APPLET(option_desc, INFO_OPTIONS);

static int option_parse_applet(void *pctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct info_ctx *ctx = (struct info_ctx *) pctx;

	ctx->action = NULL;
	switch (opt) {
	case OPT_INFO_installed:
		ctx->action = info_exists;
		ac->open_flags |= PS4_OPENF_NO_REPOS;
		break;
	case OPT_INFO_who_owns:
		ctx->action = info_who_owns;
		ac->open_flags |= PS4_OPENF_NO_REPOS;
		break;
	case OPT_INFO_webpage:
		ctx->subaction_mask |= PS4_INFO_URL;
		break;
	case OPT_INFO_depends:
		ctx->subaction_mask |= PS4_INFO_DEPENDS;
		break;
	case OPT_INFO_provides:
		ctx->subaction_mask |= PS4_INFO_PROVIDES;
		break;
	case OPT_INFO_rdepends:
		ctx->subaction_mask |= PS4_INFO_RDEPENDS;
		break;
	case OPT_INFO_install_if:
		ctx->subaction_mask |= PS4_INFO_INSTALL_IF;
		break;
	case OPT_INFO_rinstall_if:
		ctx->subaction_mask |= PS4_INFO_RINSTALL_IF;
		break;
	case OPT_INFO_size:
		ctx->subaction_mask |= PS4_INFO_SIZE;
		break;
	case OPT_INFO_description:
		ctx->subaction_mask |= PS4_INFO_DESC;
		break;
	case OPT_INFO_contents:
		ctx->subaction_mask |= PS4_INFO_CONTENTS;
		break;
	case OPT_INFO_triggers:
		ctx->subaction_mask |= PS4_INFO_TRIGGERS;
		break;
	case OPT_INFO_replaces:
		ctx->subaction_mask |= PS4_INFO_REPLACES;
		break;
	case OPT_INFO_license:
		ctx->subaction_mask |= PS4_INFO_LICENSE;
		break;
	case OPT_INFO_all:
		ctx->subaction_mask = 0xffffffff;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static int info_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;
	struct info_ctx *ictx = (struct info_ctx *) ctx;

	verbosity = ps4_out_verbosity(out);
	ictx->db = db;
	if (ictx->subaction_mask == 0)
		ictx->subaction_mask = PS4_INFO_DESC | PS4_INFO_URL | PS4_INFO_SIZE;
	if (ictx->action != NULL) {
		ictx->action(ictx, db, args);
	} else if (ps4_array_len(args) > 0) {
		/* Print info on given packages */
		ps4_db_foreach_sorted_providers(db, args, print_name_info, ctx);
	} else {
		/* Print all installed packages */
		struct ps4_package_array *pkgs = ps4_db_sorted_installed_packages(db);
		struct ps4_package **ppkg;
		foreach_array_item(ppkg, pkgs)
			verbose_print_pkg(*ppkg, 1);
	}

	return ictx->errors;
}

static const struct ps4_option_group optgroup_applet = {
	.desc = option_desc,
	.parse = option_parse_applet,
};

static struct ps4_applet ps4_info = {
	.name = "info",
	.open_flags = PS4_OPENF_READ | PS4_OPENF_ALLOW_ARCH,
	.context_size = sizeof(struct info_ctx),
	.optgroups = { &optgroup_global, &optgroup_source, &optgroup_applet },
	.main = info_main,
};

PS4_DEFINE_APPLET(ps4_info);

