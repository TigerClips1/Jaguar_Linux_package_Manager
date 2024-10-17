/* package.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ps4_defines.h"
#include "ps4_package.h"
#include "ps4_database.h"
#include "ps4_ctype.h"
#include "ps4_print.h"
#include "ps4_extract.h"
#include "ps4_adb.h"

struct ps4_package *ps4_pkg_get_installed(struct ps4_name *name)
{
	struct ps4_provider *p;

	foreach_array_item(p, name->providers)
		if (p->pkg->name == name && p->pkg->ipkg != NULL)
			return p->pkg;

	return NULL;
}

struct ps4_installed_package *ps4_pkg_install(struct ps4_database *db,
					      struct ps4_package *pkg)
{
	struct ps4_installed_package *ipkg;

	if (pkg->ipkg != NULL)
		return pkg->ipkg;

	pkg->ipkg = ipkg = calloc(1, sizeof(struct ps4_installed_package));
	ipkg->pkg = pkg;
	ps4_string_array_init(&ipkg->triggers);
	ps4_string_array_init(&ipkg->pending_triggers);
	ps4_dependency_array_init(&ipkg->replaces);

	/* Overlay override information resides in a nameless package */
	if (pkg->name != NULL) {
		db->sorted_installed_packages = 0;
		db->installed.stats.packages++;
		db->installed.stats.bytes += pkg->installed_size;
		list_add_tail(&ipkg->installed_pkgs_list,
			      &db->installed.packages);
	}

	return ipkg;
}

void ps4_pkg_uninstall(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_installed_package *ipkg = pkg->ipkg;
	char **trigger;
	int i;

	if (ipkg == NULL)
		return;

	if (db != NULL) {
		db->sorted_installed_packages = 0;
		db->installed.stats.packages--;
		db->installed.stats.bytes -= pkg->installed_size;
	}

	list_del(&ipkg->installed_pkgs_list);

	if (ps4_array_len(ipkg->triggers) != 0) {
		list_del(&ipkg->trigger_pkgs_list);
		list_init(&ipkg->trigger_pkgs_list);
		foreach_array_item(trigger, ipkg->triggers)
			free(*trigger);
	}
	ps4_string_array_free(&ipkg->triggers);
	ps4_string_array_free(&ipkg->pending_triggers);
	ps4_dependency_array_free(&ipkg->replaces);

	for (i = 0; i < PS4_SCRIPT_MAX; i++)
		if (ipkg->script[i].ptr != NULL)
			free(ipkg->script[i].ptr);
	free(ipkg);
	pkg->ipkg = NULL;
}

int ps4_pkg_parse_name(ps4_blob_t ps4name,
		       ps4_blob_t *name,
		       ps4_blob_t *version)
{
	int i, dash = 0;

	if (PS4_BLOB_IS_NULL(ps4name))
		return -1;

	for (i = ps4name.len - 2; i >= 0; i--) {
		if (ps4name.ptr[i] != '-')
			continue;
		if (isdigit(ps4name.ptr[i+1]))
			break;
		if (++dash >= 2)
			return -1;
	}
	if (i < 0)
		return -1;

	if (name != NULL)
		*name = PS4_BLOB_PTR_LEN(ps4name.ptr, i);
	if (version != NULL)
		*version = PS4_BLOB_PTR_PTR(&ps4name.ptr[i+1],
					    &ps4name.ptr[ps4name.len-1]);

	return 0;
}

int ps4_dep_parse(ps4_blob_t spec, ps4_blob_t *name, int *rop, ps4_blob_t *version)
{
	ps4_blob_t bop;
	int op = 0;

	/* [!]name[[op]ver] */
	if (PS4_BLOB_IS_NULL(spec)) goto fail;
	if (ps4_blob_pull_blob_match(&spec, PS4_BLOB_STRLIT("!")))
		op |= PS4_VERSION_CONFLICT;
	if (ps4_blob_cspn(spec, PS4_CTYPE_DEPENDENCY_COMPARER, name, &bop)) {
		if (!ps4_blob_spn(bop, PS4_CTYPE_DEPENDENCY_COMPARER, &bop, version)) goto fail;
		op |= ps4_version_result_mask_blob(bop);
		if ((op & ~PS4_VERSION_CONFLICT) == 0) goto fail;
	} else {
		*name = spec;
		op |= PS4_DEPMASK_ANY;
		*version = PS4_BLOB_NULL;
	}
	*rop = op;
	return 0;
fail:
	*name = PS4_BLOB_NULL;
	*version = PS4_BLOB_NULL;
	*rop = PS4_DEPMASK_ANY;
	return -PS4E_DEPENDENCY_FORMAT;
}

struct ps4_dependency_array *ps4_deps_bclone(struct ps4_dependency_array *deps, struct ps4_balloc *ba)
{
	if (!deps->hdr.allocated) return deps;
	uint32_t num = ps4_array_len(deps);
	size_t sz = num * sizeof(struct ps4_dependency);
	struct ps4_dependency_array *ndeps = ps4_balloc_new_extra(ba, struct ps4_dependency_array, sz);
	ndeps->hdr = (struct ps4_array) {
		.capacity = num,
		.num = num,
	};
	memcpy(ndeps->item, deps->item, sz);
	return ndeps;
}

int ps4_deps_balloc(struct ps4_dependency_array **deps, uint32_t capacity, struct ps4_balloc *ba)
{
	struct ps4_dependency_array *ndeps;

	ps4_dependency_array_free(deps);
	ndeps = *deps = ps4_balloc_new_extra(ba, struct ps4_dependency_array, capacity * sizeof(struct ps4_dependency));
	if (!ndeps) return -ENOMEM;
	ndeps->hdr = (struct ps4_array) {
		.num = 0,
		.capacity = capacity,
	};
	return 0;
}

void ps4_deps_add(struct ps4_dependency_array **deps, struct ps4_dependency *dep)
{
	struct ps4_dependency *d0;

	foreach_array_item(d0, *deps) {
		if (d0->name != dep->name) continue;
		*d0 = *dep;
		return;
	}
	ps4_dependency_array_add(deps, *dep);
}

void ps4_deps_del(struct ps4_dependency_array **pdeps, struct ps4_name *name)
{
	struct ps4_dependency_array *deps = *pdeps;
	struct ps4_dependency *d0;

	foreach_array_item(d0, deps) {
		if (d0->name != name) continue;
		size_t nlen = ps4_array_len(deps) - 1;
		*d0 = deps->item[nlen];
		ps4_array_truncate(*pdeps, nlen);
		return;
	}
}

void ps4_blob_pull_dep(ps4_blob_t *b, struct ps4_database *db, struct ps4_dependency *dep)
{
	struct ps4_name *name;
	ps4_blob_t bdep, bname, bver, btag;
	int op, tag = 0, broken = 0;

	/* grap one token, and skip all separators */
	if (PS4_BLOB_IS_NULL(*b)) goto fail;
	ps4_blob_cspn(*b, PS4_CTYPE_DEPENDENCY_SEPARATOR, &bdep, b);
	ps4_blob_spn(*b, PS4_CTYPE_DEPENDENCY_SEPARATOR, NULL, b);

	if (ps4_dep_parse(bdep, &bname, &op, &bver) != 0) goto fail;
	if ((op & PS4_DEPMASK_CHECKSUM) != PS4_DEPMASK_CHECKSUM &&
	    !ps4_version_validate(bver)) broken = 1;
	if (ps4_blob_split(bname, PS4_BLOB_STRLIT("@"), &bname, &btag))
		tag = ps4_db_get_tag_id(db, btag);

	/* convert to ps4_dependency */
	name = ps4_db_get_name(db, bname);
	if (name == NULL) goto fail;

	*dep = (struct ps4_dependency){
		.name = name,
		.version = ps4_atomize_dup(&db->atoms, bver),
		.repository_tag = tag,
		.op = op,
		.broken = broken,
	};
	return;
fail:
	*dep = (struct ps4_dependency){ .name = NULL };
	*b = PS4_BLOB_NULL;
}

int ps4_blob_pull_deps(ps4_blob_t *b, struct ps4_database *db, struct ps4_dependency_array **deps)
{
	int rc = 0;

	while (b->len > 0) {
		struct ps4_dependency dep;

		ps4_blob_pull_dep(b, db, &dep);
		if (PS4_BLOB_IS_NULL(*b) || dep.name == NULL) {
			rc = -PS4E_DEPENDENCY_FORMAT;
			continue;
		}
		if (dep.broken) rc = -PS4E_PKGVERSION_FORMAT;
		ps4_dependency_array_add(deps, dep);
	}
	return rc;
}

void ps4_dep_from_pkg(struct ps4_dependency *dep, struct ps4_database *db,
		      struct ps4_package *pkg)
{
	char buf[64];
	ps4_blob_t b = PS4_BLOB_BUF(buf);

	ps4_blob_push_hash(&b, ps4_pkg_hash_blob(pkg));
	b = ps4_blob_pushed(PS4_BLOB_BUF(buf), b);

	*dep = (struct ps4_dependency) {
		.name = pkg->name,
		.version = ps4_atomize_dup(&db->atoms, b),
		.op = PS4_DEPMASK_CHECKSUM,
	};
}

static int ps4_dep_match_checksum(const struct ps4_dependency *dep, const struct ps4_package *pkg)
{
	struct ps4_digest d;
	ps4_blob_t b = *dep->version;

	ps4_blob_pull_digest(&b, &d);
	return ps4_blob_compare(PS4_DIGEST_BLOB(d), ps4_pkg_hash_blob(pkg)) == 0;
}

int ps4_dep_is_provided(const struct ps4_package *deppkg, const struct ps4_dependency *dep, const struct ps4_provider *p)
{
	if (p == NULL || p->pkg == NULL) return ps4_dep_conflict(dep);
	if (ps4_dep_conflict(dep) && deppkg == p->pkg) return 1;
	if (dep->op == PS4_DEPMASK_CHECKSUM) return ps4_dep_match_checksum(dep, p->pkg);
	return ps4_version_match(*p->version, dep->op, *dep->version);
}

int ps4_dep_is_materialized(const struct ps4_dependency *dep, const struct ps4_package *pkg)
{
	if (pkg == NULL || dep->name != pkg->name) return ps4_dep_conflict(dep);
	if (dep->op == PS4_DEPMASK_CHECKSUM) return ps4_dep_match_checksum(dep, pkg);
	return ps4_version_match(*pkg->version, dep->op, *dep->version);
}

int ps4_dep_analyze(const struct ps4_package *deppkg, struct ps4_dependency *dep, struct ps4_package *pkg)
{
	struct ps4_dependency *p;
	struct ps4_provider provider;

	if (pkg == NULL)
		return PS4_DEP_IRRELEVANT;

	if (dep->name == pkg->name)
		return ps4_dep_is_materialized(dep, pkg) ? PS4_DEP_SATISFIES : PS4_DEP_CONFLICTS;

	foreach_array_item(p, pkg->provides) {
		if (p->name != dep->name)
			continue;
		provider = PS4_PROVIDER_FROM_PROVIDES(pkg, p);
		return ps4_dep_is_provided(deppkg, dep, &provider) ? PS4_DEP_SATISFIES : PS4_DEP_CONFLICTS;
	}

	return PS4_DEP_IRRELEVANT;
}

void ps4_blob_push_dep(ps4_blob_t *to, struct ps4_database *db, struct ps4_dependency *dep)
{
	if (ps4_dep_conflict(dep))
		ps4_blob_push_blob(to, PS4_BLOB_PTR_LEN("!", 1));

	ps4_blob_push_blob(to, PS4_BLOB_STR(dep->name->name));
	if (dep->repository_tag && db != NULL)
		ps4_blob_push_blob(to, db->repo_tags[dep->repository_tag].tag);
	if (!PS4_BLOB_IS_NULL(*dep->version)) {
		ps4_blob_push_blob(to, PS4_BLOB_STR(ps4_version_op_string(dep->op)));
		ps4_blob_push_blob(to, *dep->version);
	}
}

void ps4_blob_push_deps(ps4_blob_t *to, struct ps4_database *db, struct ps4_dependency_array *deps)
{
	struct ps4_dependency *dep;

	if (deps == NULL) return;

	foreach_array_item(dep, deps) {
		if (dep != &deps->item[0]) ps4_blob_push_blob(to, PS4_BLOB_PTR_LEN(" ", 1));
		ps4_blob_push_dep(to, db, dep);
	}
}

int ps4_deps_write_layer(struct ps4_database *db, struct ps4_dependency_array *deps, struct ps4_ostream *os, ps4_blob_t separator, unsigned layer)
{
	struct ps4_dependency *dep;
	ps4_blob_t blob;
	char tmp[256];
	int n = 0;

	if (deps == NULL) return 0;
	foreach_array_item(dep, deps) {
		if (layer != -1 && dep->layer != layer) continue;

		blob = PS4_BLOB_BUF(tmp);
		if (n) ps4_blob_push_blob(&blob, separator);
		ps4_blob_push_dep(&blob, db, dep);

		blob = ps4_blob_pushed(PS4_BLOB_BUF(tmp), blob);
		if (PS4_BLOB_IS_NULL(blob) || 
		    ps4_ostream_write(os, blob.ptr, blob.len) < 0)
			return -1;

		n += blob.len;
	}

	return n;
}

int ps4_deps_write(struct ps4_database *db, struct ps4_dependency_array *deps, struct ps4_ostream *os, ps4_blob_t separator)
{
	return ps4_deps_write_layer(db, deps, os, separator, -1);
}

void ps4_dep_from_adb(struct ps4_dependency *dep, struct ps4_database *db, struct adb_obj *d)
{
	int op = adb_ro_int(d, ADBI_DEP_MATCH);
	ps4_blob_t ver = adb_ro_blob(d, ADBI_DEP_VERSION);

	if (PS4_BLOB_IS_NULL(ver)) op |= PS4_DEPMASK_ANY;
	else if (op == 0) op = PS4_VERSION_EQUAL;

	*dep = (struct ps4_dependency) {
		.name = ps4_db_get_name(db, adb_ro_blob(d, ADBI_DEP_NAME)),
		.version = ps4_atomize_dup(&db->atoms, ver),
		.op = op,
	};
}

void ps4_deps_from_adb(struct ps4_dependency_array **deps, struct ps4_database *db, struct adb_obj *da)
{
	struct adb_obj obj;
	struct ps4_dependency d;
	int i, num = adb_ra_num(da);

	ps4_deps_balloc(deps, num, &db->ba_deps);
	for (i = ADBI_FIRST; i <= adb_ra_num(da); i++) {
		adb_ro_obj(da, i, &obj);
		ps4_dep_from_adb(&d, db, &obj);
		ps4_dependency_array_add(deps, d);
	}
}

const char *ps4_script_types[] = {
	[PS4_SCRIPT_PRE_INSTALL]	= "pre-install",
	[PS4_SCRIPT_POST_INSTALL]	= "post-install",
	[PS4_SCRIPT_PRE_DEINSTALL]	= "pre-deinstall",
	[PS4_SCRIPT_POST_DEINSTALL]	= "post-deinstall",
	[PS4_SCRIPT_PRE_UPGRADE]	= "pre-upgrade",
	[PS4_SCRIPT_POST_UPGRADE]	= "post-upgrade",
	[PS4_SCRIPT_TRIGGER]		= "trigger",
};

int ps4_script_type(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ps4_script_types); i++)
		if (ps4_script_types[i] &&
		    strcmp(ps4_script_types[i], name) == 0)
			return i;

	return PS4_SCRIPT_INVALID;
}

void ps4_pkgtmpl_init(struct ps4_package_tmpl *tmpl)
{
	memset(tmpl, 0, sizeof *tmpl);
	ps4_dependency_array_init(&tmpl->pkg.depends);
	ps4_dependency_array_init(&tmpl->pkg.install_if);
	ps4_dependency_array_init(&tmpl->pkg.provides);
	ps4_pkgtmpl_reset(tmpl);
}

void ps4_pkgtmpl_free(struct ps4_package_tmpl *tmpl)
{
	ps4_dependency_array_free(&tmpl->pkg.depends);
	ps4_dependency_array_free(&tmpl->pkg.install_if);
	ps4_dependency_array_free(&tmpl->pkg.provides);
}

void ps4_pkgtmpl_reset(struct ps4_package_tmpl *tmpl)
{
	*tmpl = (struct ps4_package_tmpl) {
		.pkg = (struct ps4_package) {
			.depends = ps4_array_reset(tmpl->pkg.depends),
			.install_if = ps4_array_reset(tmpl->pkg.install_if),
			.provides = ps4_array_reset(tmpl->pkg.provides),
			.arch = &ps4_atom_null,
			.license = &ps4_atom_null,
			.origin = &ps4_atom_null,
			.maintainer = &ps4_atom_null,
			.url = &ps4_atom_null,
			.description = &ps4_atom_null,
			.commit = &ps4_atom_null,
		},
	};
}

struct read_info_ctx {
	struct ps4_database *db;
	struct ps4_extract_ctx ectx;
	struct ps4_package_tmpl tmpl;
	int v3ok;
};

int ps4_pkgtmpl_add_info(struct ps4_database *db, struct ps4_package_tmpl *tmpl, char field, ps4_blob_t value)
{
	struct ps4_package *pkg = &tmpl->pkg;

	switch (field) {
	case 'P':
		pkg->name = ps4_db_get_name(db, value);
		break;
	case 'V':
		pkg->version = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'T':
		pkg->description = ps4_atomize_dup0(&db->atoms, value);
		break;
	case 'U':
		pkg->url = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'L':
		pkg->license = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'A':
		pkg->arch = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'D':
		if (ps4_blob_pull_deps(&value, db, &pkg->depends)) {
			db->compat_depversions = 1;
			db->compat_notinstallable = pkg->uninstallable = 1;
			return 2;
		}
		break;
	case 'C':
		ps4_blob_pull_digest(&value, &tmpl->id);
		break;
	case 'S':
		pkg->size = ps4_blob_pull_uint(&value, 10);
		break;
	case 'I':
		pkg->installed_size = ps4_blob_pull_uint(&value, 10);
		break;
	case 'p':
		if (ps4_blob_pull_deps(&value, db, &pkg->provides)) {
			db->compat_depversions = 1;
			return 2;
		}
		break;
	case 'i':
		if (ps4_blob_pull_deps(&value, db, &pkg->install_if)) {
			// Disable partial install_if rules
			ps4_array_truncate(pkg->install_if, 0);
			db->compat_depversions = 1;
			return 2;
		}
		break;
	case 'o':
		pkg->origin = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'm':
		pkg->maintainer = ps4_atomize_dup(&db->atoms, value);
		break;
	case 't':
		pkg->build_time = ps4_blob_pull_uint(&value, 10);
		break;
	case 'c':
		pkg->commit = ps4_atomize_dup(&db->atoms, value);
		break;
	case 'k':
		pkg->provider_priority = ps4_blob_pull_uint(&value, 10);
		break;
	case 'F': case 'M': case 'R': case 'Z': case 'r': case 'q':
	case 'a': case 's': case 'f':
		/* installed db entries which are handled in database.c */
		return 1;
	default:
		/* lower case index entries are safe to be ignored */
		if (!islower(field)) db->compat_notinstallable = pkg->uninstallable = 1;
		db->compat_newfeatures = 1;
		return 2;
	}
	if (PS4_BLOB_IS_NULL(value))
		return -PS4E_V2PKG_FORMAT;
	return 0;
}

static ps4_blob_t *commit_id(struct ps4_atom_pool *atoms, ps4_blob_t b)
{
	char buf[80];
	ps4_blob_t to = PS4_BLOB_BUF(buf);

	ps4_blob_push_hexdump(&to, b);
	to = ps4_blob_pushed(PS4_BLOB_BUF(buf), to);
	if (PS4_BLOB_IS_NULL(to)) return &ps4_atom_null;
	return ps4_atomize_dup(atoms, to);
}

void ps4_pkgtmpl_from_adb(struct ps4_database *db, struct ps4_package_tmpl *tmpl, struct adb_obj *pkginfo)
{
	struct adb_obj obj;
	struct ps4_package *pkg = &tmpl->pkg;
	ps4_blob_t uid;

	uid = adb_ro_blob(pkginfo, ADBI_PI_HASHES);
	if (uid.len >= PS4_DIGEST_LENGTH_SHA1) ps4_digest_from_blob(&tmpl->id, uid);

	pkg->name = ps4_db_get_name(db, adb_ro_blob(pkginfo, ADBI_PI_NAME));
	pkg->version = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_VERSION));
	pkg->description = ps4_atomize_dup0(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_DESCRIPTION));
	pkg->url = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_URL));
	pkg->license = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_LICENSE));
	pkg->arch = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_ARCH));
	pkg->installed_size = adb_ro_int(pkginfo, ADBI_PI_INSTALLED_SIZE);
	pkg->size = adb_ro_int(pkginfo, ADBI_PI_FILE_SIZE);
	pkg->provider_priority = adb_ro_int(pkginfo, ADBI_PI_PROVIDER_PRIORITY);
	pkg->origin = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_ORIGIN));
	pkg->maintainer = ps4_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_MAINTAINER));
	pkg->build_time = adb_ro_int(pkginfo, ADBI_PI_BUILD_TIME);
	pkg->commit = commit_id(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_REPO_COMMIT));
	pkg->layer = adb_ro_int(pkginfo, ADBI_PI_LAYER);

	ps4_deps_from_adb(&pkg->depends, db, adb_ro_obj(pkginfo, ADBI_PI_DEPENDS, &obj));
	ps4_deps_from_adb(&pkg->provides, db, adb_ro_obj(pkginfo, ADBI_PI_PROVIDES, &obj));
	ps4_deps_from_adb(&pkg->install_if, db, adb_ro_obj(pkginfo, ADBI_PI_INSTALL_IF, &obj));
}

static int read_info_line(struct read_info_ctx *ri, ps4_blob_t line)
{
	static struct {
		const char *str;
		char field;
	} fields[] = {
		{ "pkgname",	'P' },
		{ "pkgver", 	'V' },
		{ "pkgdesc",	'T' },
		{ "url",	'U' },
		{ "size",	'I' },
		{ "license",	'L' },
		{ "arch",	'A' },
		{ "depend",	'D' },
		{ "install_if",	'i' },
		{ "provides",	'p' },
		{ "origin",	'o' },
		{ "maintainer",	'm' },
		{ "builddate",	't' },
		{ "commit",	'c' },
		{ "provider_priority", 'k' },
	};
	ps4_blob_t l, r;
	int i;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!ps4_blob_split(line, PS4_BLOB_STR(" = "), &l, &r))
		return 0;

	ps4_extract_v2_control(&ri->ectx, l, r);

	for (i = 0; i < ARRAY_SIZE(fields); i++)
		if (ps4_blob_compare(PS4_BLOB_STR(fields[i].str), l) == 0)
			return ps4_pkgtmpl_add_info(ri->db, &ri->tmpl, fields[i].field, r);

	return 0;
}

static int ps4_pkg_v2meta(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	struct read_info_ctx *ri = container_of(ectx, struct read_info_ctx, ectx);
	ps4_blob_t l, token = PS4_BLOB_STR("\n");
	int r;

	while (ps4_istream_get_delim(is, token, &l) == 0) {
		r = read_info_line(ri, l);
		if (r < 0) return r;
	}

	return 0;
}

static int ps4_pkg_v3meta(struct ps4_extract_ctx *ectx, struct adb_obj *pkg)
{
	struct read_info_ctx *ri = container_of(ectx, struct read_info_ctx, ectx);
	struct adb_obj pkginfo;

	if (!ri->v3ok) return -PS4E_FORMAT_NOT_SUPPORTED;

	adb_ro_obj(pkg, ADBI_PKG_PKGINFO, &pkginfo);
	ps4_pkgtmpl_from_adb(ri->db, &ri->tmpl, &pkginfo);

	return -ECANCELED;
}

static const struct ps4_extract_ops extract_pkgmeta_ops = {
	.v2meta = ps4_pkg_v2meta,
	.v3meta = ps4_pkg_v3meta,
};

int ps4_pkg_read(struct ps4_database *db, const char *file, struct ps4_package **pkg, int v3ok)
{
	struct read_info_ctx ctx = {
		.db = db,
		.v3ok = v3ok,
	};
	struct ps4_file_info fi;
	int r;

	r = ps4_fileinfo_get(AT_FDCWD, file, 0, &fi, &db->atoms);
	if (r != 0) return r;

	ps4_pkgtmpl_init(&ctx.tmpl);
	ctx.tmpl.pkg.size = fi.size;
	ps4_extract_init(&ctx.ectx, db->ctx, &extract_pkgmeta_ops);
	ps4_extract_generate_identity(&ctx.ectx, PS4_DIGEST_SHA256, &ctx.tmpl.id);

	r = ps4_extract(&ctx.ectx, ps4_istream_from_file(AT_FDCWD, file));
	if (r < 0 && r != -ECANCELED) goto err;
	if (ctx.tmpl.id.alg == PS4_DIGEST_NONE ||
	    ctx.tmpl.pkg.name == NULL ||
	    ctx.tmpl.pkg.uninstallable) {
		r = -PS4E_V2PKG_FORMAT;
		goto err;
	}

	ps4_string_array_add(&db->filename_array, (char*) file);
	ctx.tmpl.pkg.filename_ndx = ps4_array_len(db->filename_array);

	if (pkg) *pkg = ps4_db_pkg_add(db, &ctx.tmpl);
	else ps4_db_pkg_add(db, &ctx.tmpl);
	r = 0;
err:
	ps4_pkgtmpl_free(&ctx.tmpl);
	return r;
}

int ps4_ipkg_assign_script(struct ps4_installed_package *ipkg, unsigned int type, ps4_blob_t b)
{
	if (ps4_BLOB_IS_NULL(b)) return -1;
	if (type >= PS4_SCRIPT_MAX) {
		free(b.ptr);
		return -1;
	}
	if (ipkg->script[type].ptr) free(ipkg->script[type].ptr);
	ipkg->script[type] = b;
	return 0;
}

int ps4_ipkg_add_script(struct ps4_installed_package *ipkg,
			struct ps4_istream *is,
			unsigned int type, unsigned int size)
{
	ps4_blob_t b;
	ps4_blob_from_istream(is, size, &b);
	return ps4_ipkg_assign_script(ipkg, type, b);
}

#ifdef __linux__
static inline int make_device_tree(struct ps4_database *db)
{
	if (faccessat(db->root_fd, "dev", F_OK, 0) == 0) return 0;
	if (mkdirat(db->root_fd, "dev", 0755) < 0 ||
	    mknodat(db->root_fd, "dev/null", S_IFCHR | 0666, makedev(1, 3)) < 0 ||
	    mknodat(db->root_fd, "dev/zero", S_IFCHR | 0666, makedev(1, 5)) < 0 ||
	    mknodat(db->root_fd, "dev/random", S_IFCHR | 0666, makedev(1, 8)) < 0 ||
	    mknodat(db->root_fd, "dev/urandom", S_IFCHR | 0666, makedev(1, 9)) < 0 ||
	    mknodat(db->root_fd, "dev/console", S_IFCHR | 0600, makedev(5, 1)) < 0)
		return -1;
	return 0;
}
#else
static inline int make_device_tree(struct ps4_database *db)
{
	(void) db;
	return 0;
}
#endif

int ps4_ipkg_run_script(struct ps4_installed_package *ipkg,
			struct ps4_database *db,
			unsigned int type, char **argv)
{
	// script_exec_dir is the directory to which the script is extracted,
	// executed from, and removed. It needs to not be 'noexec' mounted, and
	// preferably a tmpfs disk, or something that could be wiped in boot.
	// Originally this was /tmp, but it is often suggested to be 'noexec'.
	// Then changed ro /var/cache/misc, but that is also often 'noexec'.
	// /run was consider as it's tmpfs, but it also might be changing to 'noexec'.
	// So use for now /lib/ps4/exec even if it is not of temporary nature.
	static const char script_exec_dir[] = "lib/ps4/exec";
	struct ps4_out *out = &db->ctx->out;
	struct ps4_package *pkg = ipkg->pkg;
	char fn[PATH_MAX];
	int fd, root_fd = db->root_fd, ret = 0;

	if (type >= PS4_SCRIPT_MAX || ipkg->script[type].ptr == NULL)
		return 0;

	argv[0] = (char *) ps4_script_types[type];

	snprintf(fn, sizeof(fn), "%s/" PKG_VER_FMT ".%s",
		script_exec_dir, PKG_VER_PRINTF(pkg),
		ps4_script_types[type]);

	if ((db->ctx->flags & (PS4_NO_SCRIPTS | PS4_SIMULATE)) != 0)
		return 0;

	if (!db->script_dirs_checked) {
		if (ps4_make_dirs(root_fd, script_exec_dir, 0700, 0755) < 0) {
			ps4_err(out, "failed to prepare dirs for hook scripts: %s",
				ps4_error_str(errno));
			goto err;
		}
		if (make_device_tree(db) < 0) {
			ps4_warn(out, "failed to create initial device nodes for scripts: %s",
				ps4_error_str(errno));
		}
		db->script_dirs_checked = 1;
	}

	ps4_msg(out, "Executing %s", ps4_last_path_segment(fn));
	fd = openat(root_fd, fn, O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC, 0755);
	if (fd < 0) {
		fd = openat(root_fd, fn, O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC, 0755);
		if (fd < 0) goto err_log;
	}
	if (write(fd, ipkg->script[type].ptr, ipkg->script[type].len) < 0) {
		close(fd);
		goto err_log;
	}
	close(fd);

	if (ps4_db_run_script(db, fn, argv) < 0)
		goto err;

	/* Script may have done something that changes id cache contents */
	ps4_id_cache_reset(db->id_cache);

	goto cleanup;

err_log:
	ps4_err(out, "%s: failed to execute: %s", ps4_last_path_segment(fn), ps4_error_str(errno));
err:
	ipkg->broken_script = 1;
	ret = 1;
cleanup:
	unlinkat(root_fd, fn, 0);
	return ret;
}

static int write_depends(struct ps4_ostream *os, const char *field,
			 struct ps4_dependency_array *deps)
{
	int r;

	if (ps4_array_len(deps) == 0) return 0;
	if (ps4_ostream_write(os, field, 2) < 0) return -1;
	if ((r = ps4_deps_write(NULL, deps, os, PS4_BLOB_PTR_LEN(" ", 1))) < 0) return r;
	if (ps4_ostream_write(os, "\n", 1) < 0) return -1;
	return 0;
}

int ps4_pkg_write_index_header(struct ps4_package *info, struct ps4_ostream *os)
{
	char buf[2048];
	ps4_blob_t bbuf = PS4_BLOB_BUF(buf);

	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("C:"));
	ps4_blob_push_hash(&bbuf, ps4_pkg_hash_blob(info));
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nP:"));
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR(info->name->name));
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nV:"));
	ps4_blob_push_blob(&bbuf, *info->version);
	if (info->arch != NULL) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nA:"));
		ps4_blob_push_blob(&bbuf, *info->arch);
	}
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nS:"));
	ps4_blob_push_uint(&bbuf, info->size, 10);
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nI:"));
	ps4_blob_push_uint(&bbuf, info->installed_size, 10);
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nT:"));
	ps4_blob_push_blob(&bbuf, *info->description);
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nU:"));
	ps4_blob_push_blob(&bbuf, *info->url);
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nL:"));
	ps4_blob_push_blob(&bbuf, *info->license);
	if (info->origin) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\no:"));
		ps4_blob_push_blob(&bbuf, *info->origin);
	}
	if (info->maintainer) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nm:"));
		ps4_blob_push_blob(&bbuf, *info->maintainer);
	}
	if (info->build_time) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nt:"));
		ps4_blob_push_uint(&bbuf, info->build_time, 10);
	}
	if (!PS4_BLOB_IS_NULL(*info->commit)) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nc:"));
		ps4_blob_push_blob(&bbuf, *info->commit);
	}
	if (info->provider_priority) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\nk:"));
		ps4_blob_push_uint(&bbuf, info->provider_priority, 10);
	}
	ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));

	if (PS4_BLOB_IS_NULL(bbuf))
		return ps4_ostream_cancel(os, -ENOBUFS);

	bbuf = ps4_blob_pushed(PS4_BLOB_BUF(buf), bbuf);
	if (ps4_ostream_write(os, bbuf.ptr, bbuf.len) < 0 ||
	    write_depends(os, "D:", info->depends) ||
	    write_depends(os, "p:", info->provides) ||
	    write_depends(os, "i:", info->install_if))
		return ps4_ostream_cancel(os, -EIO);

	return 0;
}

int ps4_pkg_write_index_entry(struct ps4_package *pkg, struct ps4_ostream *os)
{
	int r = ps4_pkg_write_index_header(pkg, os);
	if (r < 0) return r;
	return ps4_ostream_write(os, "\n", 1);
}

int ps4_pkg_version_compare(const struct ps4_package *a, const struct ps4_package *b)
{
	if (a->version == b->version) return PS4_VERSION_EQUAL;
	return ps4_version_compare(*a->version, *b->version);
}

int ps4_pkg_cmp_display(const struct ps4_package *a, const struct ps4_package *b)
{
	if (a->name != b->name)
		return ps4_name_cmp_display(a->name, b->name);
	switch (ps4_pkg_version_compare(a, b)) {
	case PS4_VERSION_LESS:
		return -1;
	case PS4_VERSION_GREATER:
		return 1;
	default:
		return 0;
	}
}

int ps4_pkg_replaces_dir(const struct ps4_package *a, const struct ps4_package *b)
{
	struct ps4_installed_package *ai = a->ipkg, *bi = b->ipkg;

	/* Prefer overlay */
	if (a->name == NULL) return PS4_PKG_REPLACES_NO;
	if (b->name == NULL) return PS4_PKG_REPLACES_YES;

	/* Upgrading package? */
	if (a->name == b->name) return PS4_PKG_REPLACES_YES;

	/* Highest replaces_priority wins */
	if (ai->replaces_priority > bi->replaces_priority) return PS4_PKG_REPLACES_NO;
	if (ai->replaces_priority < bi->replaces_priority) return PS4_PKG_REPLACES_YES;

	/* If both have the same origin... */
	if (a->origin && a->origin == b->origin) {
		/* .. and either has origin equal to package name, prefer it. */
		if (ps4_blob_compare(*a->origin, PS4_BLOB_STR(a->name->name)) == 0)
			return PS4_PKG_REPLACES_NO;
		if (ps4_blob_compare(*b->origin, PS4_BLOB_STR(b->name->name)) == 0)
			return PS4_PKG_REPLACES_YES;
	}

	/* Fall back to package name to have stable sort */
	if (strcmp(a->name->name, b->name->name) <= 0) return PS4_PKG_REPLACES_NO;
	return PS4_PKG_REPLACES_YES;
}

int ps4_pkg_replaces_file(const struct ps4_package *a, const struct ps4_package *b)
{
	struct ps4_dependency *dep;
	int a_prio = -1, b_prio = -1;

	/* Overlay file? Replace the ownership, but extraction will keep the overlay file. */
	if (a->name == NULL) return PS4_PKG_REPLACES_YES;

	/* Upgrading package? */
	if (a->name == b->name) return PS4_PKG_REPLACES_YES;

	/* Or same source package? */
	if (a->origin && a->origin == b->origin) return PS4_PKG_REPLACES_YES;

	/* Does the original package replace the new one? */
	foreach_array_item(dep, a->ipkg->replaces) {
		if (ps4_dep_is_materialized(dep, b)) {
			a_prio = a->ipkg->replaces_priority;
			break;
		}
	}

	/* Does the new package replace the original one? */
	foreach_array_item(dep, b->ipkg->replaces) {
		if (ps4_dep_is_materialized(dep, a)) {
			b_prio = b->ipkg->replaces_priority;
			break;
		}
	}

	/* If the original package is more important, skip this file */
	if (a_prio > b_prio) return PS4_PKG_REPLACES_NO;

	/* If the new package has valid 'replaces', we will overwrite
	 * the file without warnings. */
	if (b_prio >= 0) return PS4_PKG_REPLACES_YES;

	/* Both ship same file, but metadata is inconclusive. */
	return PS4_PKG_REPLACES_CONFLICT;
}

unsigned int ps4_foreach_genid(void)
{
	static unsigned int foreach_genid;
	foreach_genid += (~PS4_FOREACH_GENID_MASK) + 1;
	return foreach_genid;
}

int ps4_pkg_match_genid(struct ps4_package *pkg, unsigned int match)
{
	unsigned int genid = match & PS4_FOREACH_GENID_MASK;
	if (pkg && genid) {
		if (pkg->foreach_genid >= genid)
			return 1;
		pkg->foreach_genid = genid;
	}
	return 0;
}

void ps4_pkg_foreach_matching_dependency(
		struct ps4_package *pkg, struct ps4_dependency_array *deps,
		unsigned int match, struct ps4_package *mpkg,
		void cb(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *ctx),
		void *ctx)
{
	unsigned int one_dep_only = (match & PS4_FOREACH_GENID_MASK) && !(match & PS4_FOREACH_DEP);
	struct ps4_dependency *d;

	if (ps4_pkg_match_genid(pkg, match)) return;

	foreach_array_item(d, deps) {
		if (ps4_dep_analyze(pkg, d, mpkg) & match) {
			cb(pkg, d, mpkg, ctx);
			if (one_dep_only) break;
		}
	}
}

static void foreach_reverse_dependency(
		struct ps4_package *pkg,
		struct ps4_name_array *rdepends,
		unsigned int match,
		void cb(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *ctx),
		void *ctx)
{
	unsigned int marked = match & PS4_FOREACH_MARKED;
	unsigned int installed = match & PS4_FOREACH_INSTALLED;
	unsigned int one_dep_only = (match & PS4_FOREACH_GENID_MASK) && !(match & PS4_FOREACH_DEP);
	struct ps4_name **pname0, *name0;
	struct ps4_provider *p0;
	struct ps4_package *pkg0;
	struct ps4_dependency *d0;

	foreach_array_item(pname0, rdepends) {
		name0 = *pname0;
		foreach_array_item(p0, name0->providers) {
			pkg0 = p0->pkg;
			if (installed && pkg0->ipkg == NULL) continue;
			if (marked && !pkg0->marked) continue;
			if (ps4_pkg_match_genid(pkg0, match)) continue;
			foreach_array_item(d0, pkg0->depends) {
				if (ps4_dep_analyze(pkg0, d0, pkg) & match) {
					cb(pkg0, d0, pkg, ctx);
					if (one_dep_only) break;
				}
			}
		}
	}
}

void ps4_pkg_foreach_reverse_dependency(
		struct ps4_package *pkg, unsigned int match,
		void cb(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *ctx),
		void *ctx)
{
	struct ps4_dependency *p;

	foreach_reverse_dependency(pkg, pkg->name->rdepends, match, cb, ctx);
	foreach_array_item(p, pkg->provides)
		foreach_reverse_dependency(pkg, p->name->rdepends, match, cb, ctx);
}
