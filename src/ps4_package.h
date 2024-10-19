/* ps4_package.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_PKG_H
#define PS4_PKG_H

#include "ps4_version.h"
#include "ps4_hash.h"
#include "ps4_io.h"
#include "ps4_solver_data.h"

struct adb_obj;
struct ps4_database;
struct ps4_balloc;
struct ps4_name;
struct ps4_provider;
struct ps4_trust;

#define PS4_SCRIPT_INVALID		-1
#define PS4_SCRIPT_PRE_INSTALL		0
#define PS4_SCRIPT_POST_INSTALL		1
#define PS4_SCRIPT_PRE_DEINSTALL	2
#define PS4_SCRIPT_POST_DEINSTALL	3
#define PS4_SCRIPT_PRE_UPGRADE		4
#define PS4_SCRIPT_POST_UPGRADE		5
#define PS4_SCRIPT_TRIGGER		6
#define PS4_SCRIPT_MAX			7

#define PS4_DEP_IRRELEVANT		0x01
#define PS4_DEP_SATISFIES		0x02
#define PS4_DEP_CONFLICTS		0x04
#define PS4_FOREACH_INSTALLED		0x10
#define PS4_FOREACH_MARKED		0x20
#define PS4_FOREACH_NULL_MATCHES_ALL	0x40
#define PS4_FOREACH_DEP			0x80
#define PS4_FOREACH_GENID_MASK		0xffffff00

struct ps4_dependency {
	struct ps4_name *name;
	ps4_blob_t *version;
	uint8_t op;
	uint16_t broken : 1;		// solver state
	uint16_t repository_tag : 6;	// world dependency only: tag
	uint16_t layer : 4;		// solver sets for 'world' dependencies only
};
PS4_ARRAY(ps4_dependency_array, struct ps4_dependency);

struct ps4_installed_package {
	struct ps4_package *pkg;
	struct list_head installed_pkgs_list;
	struct list_head trigger_pkgs_list;
	struct hlist_head owned_dirs;
	ps4_blob_t script[PS4_SCRIPT_MAX];
	struct ps4_string_array *triggers;
	struct ps4_string_array *pending_triggers;
	struct ps4_dependency_array *replaces;

	unsigned short replaces_priority;
	unsigned repository_tag : 6;
	unsigned run_all_triggers : 1;
	unsigned broken_files : 1;
	unsigned broken_script : 1;
	unsigned broken_xattr : 1;
	unsigned sha256_160 : 1;
};

struct ps4_package {
	ps4_hash_node hash_node;
	struct ps4_name *name;
	struct ps4_installed_package *ipkg;
	struct ps4_dependency_array *depends, *install_if, *provides;
	ps4_blob_t *version;
	ps4_blob_t *arch, *license, *origin, *maintainer, *url, *description, *commit;
	size_t installed_size, size;
	time_t build_time;

	union {
		struct ps4_solver_package_state ss;
		int state_int;
	};
	unsigned int foreach_genid;
	unsigned short provider_priority;
	unsigned short repos;
	unsigned short filename_ndx;

	unsigned char seen : 1;
	unsigned char marked : 1;
	unsigned char uninstallable : 1;
	unsigned char cached_non_repository : 1;
	unsigned char layer : 4;
	uint8_t digest_alg;
	uint8_t digest[];
};

static inline ps4_blob_t ps4_pkg_hash_blob(const struct ps4_package *pkg) {
	return PS4_BLOB_PTR_LEN((char*) pkg->digest, PS4_DIGEST_LENGTH_SHA1);
}

static inline ps4_blob_t ps4_pkg_digest_blob(const struct ps4_package *pkg) {
	return PS4_BLOB_PTR_LEN((char*) pkg->digest, ps4_digest_alg_len(pkg->digest_alg));
}

PS4_ARRAY(ps4_package_array, struct ps4_package *);

#define PS4_PROVIDER_FROM_PACKAGE(pkg)	  (struct ps4_provider){(pkg),(pkg)->version}
#define PS4_PROVIDER_FROM_PROVIDES(pkg,p) (struct ps4_provider){(pkg),(p)->version}

#define PKG_VER_FMT		"%s-" BLOB_FMT
#define PKG_VER_PRINTF(pkg)	(pkg)->name->name, BLOB_PRINTF(*(pkg)->version)
#define PKG_VER_STRLEN(pkg)	(strlen(pkg->name->name) + 1 + pkg->version->len)
#define PKG_FILE_FMT		PKG_VER_FMT ".ps4"
#define PKG_FILE_PRINTF(pkg)	PKG_VER_PRINTF(pkg)

#define DEP_FMT			"%s%s%s" BLOB_FMT
#define DEP_PRINTF(dep)		ps4_dep_conflict(dep) ? "!" : "", (dep)->name->name, \
				ps4_BLOB_IS_NULL(*(dep)->version) ? "" : ps4_version_op_string((dep)->op), \
				BLOB_PRINTF(*(dep)->version)

extern const char *ps4_script_types[];

static inline int ps4_dep_conflict(const struct ps4_dependency *dep) { return !!(dep->op & PS4_VERSION_CONFLICT); }
void ps4_dep_from_pkg(struct ps4_dependency *dep, struct ps4_database *db,
		      struct ps4_package *pkg);
int ps4_dep_is_materialized(const struct ps4_dependency *dep, const struct ps4_package *pkg);
int ps4_dep_is_provided(const struct ps4_package *deppkg, const struct ps4_dependency *dep, const struct ps4_provider *p);
int ps4_dep_analyze(const struct ps4_package *deppkg, struct ps4_dependency *dep, struct ps4_package *pkg);

void ps4_blob_push_dep(ps4_blob_t *to, struct ps4_database *, struct ps4_dependency *dep);
void ps4_blob_push_deps(ps4_blob_t *to, struct ps4_database *, struct ps4_dependency_array *deps);
void ps4_blob_pull_dep(ps4_blob_t *from, struct ps4_database *, struct ps4_dependency *);
int ps4_blob_pull_deps(ps4_blob_t *from, struct ps4_database *, struct ps4_dependency_array **);

int ps4_deps_write_layer(struct ps4_database *db, struct ps4_dependency_array *deps,
			 struct ps4_ostream *os, ps4_blob_t separator, unsigned layer);
int ps4_deps_write(struct ps4_database *db, struct ps4_dependency_array *deps,
		   struct ps4_ostream *os, ps4_blob_t separator);

void ps4_dep_from_adb(struct ps4_dependency *dep, struct ps4_database *db, struct adb_obj *d);
void ps4_deps_from_adb(struct ps4_dependency_array **deps, struct ps4_database *db, struct adb_obj *da);

int ps4_dep_parse(ps4_blob_t spec, ps4_blob_t *name, int *op, ps4_blob_t *version);
struct ps4_dependency_array *ps4_deps_bclone(struct ps4_dependency_array *deps, struct ps4_balloc *ba);
int ps4_deps_balloc(struct ps4_dependency_array **deps, uint32_t capacity, struct ps4_balloc *ba);
void ps4_deps_add(struct ps4_dependency_array **deps, struct ps4_dependency *dep);
void ps4_deps_del(struct ps4_dependency_array **deps, struct ps4_name *name);
int ps4_script_type(const char *name);

struct ps4_package_tmpl {
	struct ps4_package pkg;
	struct ps4_digest id;
};
void ps4_pkgtmpl_init(struct ps4_package_tmpl *tmpl);
void ps4_pkgtmpl_free(struct ps4_package_tmpl *tmpl);
void ps4_pkgtmpl_reset(struct ps4_package_tmpl *tmpl);
int ps4_pkgtmpl_add_info(struct ps4_database *db, struct ps4_package_tmpl *tmpl, char field, ps4_blob_t value);
void ps4_pkgtmpl_from_adb(struct ps4_database *db, struct ps4_package_tmpl *tmpl, struct adb_obj *pkginfo);

int ps4_pkg_read(struct ps4_database *db, const char *name, struct ps4_package **pkg, int v3ok);
int ps4_pkg_parse_name(ps4_blob_t ps4name, ps4_blob_t *name, ps4_blob_t *version);

struct ps4_package *ps4_pkg_get_installed(struct ps4_name *name);
struct ps4_installed_package *ps4_pkg_install(struct ps4_database *db, struct ps4_package *pkg);
void ps4_pkg_uninstall(struct ps4_database *db, struct ps4_package *pkg);

int ps4_ipkg_assign_script(struct ps4_installed_package *ipkg, unsigned int type, ps4_blob_t blob);
int ps4_ipkg_add_script(struct ps4_installed_package *ipkg,
			struct ps4_istream *is,
			unsigned int type, unsigned int size);
int ps4_ipkg_run_script(struct ps4_installed_package *ipkg, struct ps4_database *db,
			unsigned int type, char **argv);

int ps4_pkg_write_index_header(struct ps4_package *pkg, struct ps4_ostream *os);
int ps4_pkg_write_index_entry(struct ps4_package *pkg, struct ps4_ostream *os);

int ps4_pkg_version_compare(const struct ps4_package *a, const struct ps4_package *b);
int ps4_pkg_cmp_display(const struct ps4_package *a, const struct ps4_package *b);

enum {
	PS4_PKG_REPLACES_YES,
	PS4_PKG_REPLACES_NO,
	PS4_PKG_REPLACES_CONFLICT,
};
int ps4_pkg_replaces_dir(const struct ps4_package *a, const struct ps4_package *b);
int ps4_pkg_replaces_file(const struct ps4_package *a, const struct ps4_package *b);

unsigned int ps4_foreach_genid(void);
int ps4_pkg_match_genid(struct ps4_package *pkg, unsigned int match);
void ps4_pkg_foreach_matching_dependency(
		struct ps4_package *pkg, struct ps4_dependency_array *deps,
		unsigned int match, struct ps4_package *mpkg,
		void cb(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *ctx),
		void *ctx);
void ps4_pkg_foreach_reverse_dependency(
		struct ps4_package *pkg, unsigned int match,
		void cb(struct ps4_package *pkg0, struct ps4_dependency *dep0, struct ps4_package *pkg, void *ctx),
		void *ctx);

#endif
