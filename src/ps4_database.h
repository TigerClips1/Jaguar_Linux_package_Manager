/* ps4_database.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_PKGDB_H
#define PS4_PKGDB_H

#include "ps4_version.h"
#include "ps4_hash.h"
#include "ps4_atom.h"
#include "ps4_balloc.h"
#include "ps4_package.h"
#include "ps4_io.h"
#include "ps4_context.h"

#include "ps4_provider_data.h"
#include "ps4_solver_data.h"

struct ps4_name;
PS4_ARRAY(ps4_name_array, struct ps4_name *);

struct ps4_db_acl {
	mode_t mode;
	uid_t uid;
	gid_t gid;
	uint8_t xattr_hash_len;
	uint8_t xattr_hash[];
} __attribute__((packed));

static inline ps4_blob_t ps4_acl_digest_blob(struct ps4_db_acl *acl) {
	return PS4_BLOB_PTR_LEN((char*) acl->xattr_hash, acl->xattr_hash_len);
}

struct ps4_db_file {
	struct hlist_node hash_node;
	struct hlist_node diri_files_list;

	struct ps4_db_dir_instance *diri;
	struct ps4_db_acl *acl;

	unsigned char audited : 1;
	unsigned char digest_alg : 7;
	unsigned char namelen;
	uint8_t digest[20]; // sha1 length
	char name[];
};

static inline ps4_blob_t ps4_dbf_digest_blob(struct ps4_db_file *file) {
	return PS4_BLOB_PTR_LEN((char*) file->digest, ps4_digest_alg_len(file->digest_alg));
}
static inline void ps4_dbf_digest_set(struct ps4_db_file *file, uint8_t alg, const uint8_t *data) {
	uint8_t len = ps4_digest_alg_len(alg);
	if (len > sizeof file->digest) {
		file->digest_alg = PS4_DIGEST_NONE;
		return;
	}
	file->digest_alg = alg;
	memcpy(file->digest, data, len);
}

enum ps4_protect_mode {
	PS4_PROTECT_NONE = 0,
	PS4_PROTECT_IGNORE,
	PS4_PROTECT_CHANGED,
	PS4_PROTECT_SYMLINKS_ONLY,
	PS4_PROTECT_ALL,
};

static inline int ps4_protect_mode_none(enum ps4_protect_mode mode)
{
	return mode == PS4_PROTECT_NONE || mode == PS4_PROTECT_IGNORE;
}

struct ps4_protected_path {
	char *relative_pattern;
	unsigned protect_mode : 3;
};
PS4_ARRAY(ps4_protected_path_array, struct ps4_protected_path);

struct ps4_db_dir {
	ps4_hash_node hash_node;
	unsigned long hash;

	struct ps4_db_dir *parent;
	struct ps4_db_dir_instance *owner;
	struct list_head diris;
	struct ps4_protected_path_array *protected_paths;

	unsigned short refs;
	unsigned short namelen;

	unsigned char protect_mode : 3;
	unsigned char has_protected_children : 1;

	unsigned char created : 1;
	unsigned char modified : 1;
	unsigned char permissions_ok : 1;

	char rooted_name[1];
	char name[];
};

#define DIR_FILE_FMT			"%s%s%s"
#define DIR_FILE_PRINTF(dir,file)	(dir)->name, (dir)->namelen ? "/" : "", (file)->name

struct ps4_db_dir_instance {
	struct list_head dir_diri_list;
	struct hlist_node pkg_dirs_list;
	struct hlist_head owned_files;
	struct ps4_package *pkg;
	struct ps4_db_dir *dir;
	struct ps4_db_acl *acl;
};

struct ps4_name {
	ps4_hash_node hash_node;
	struct ps4_provider_array *providers;
	struct ps4_name_array *rdepends;
	struct ps4_name_array *rinstall_if;
	unsigned is_dependency : 1;
	unsigned auto_select_virtual: 1;
	unsigned priority : 2;
	unsigned solver_flags_set : 1;
	unsigned providers_sorted : 1;
	unsigned int foreach_genid;
	union {
		struct ps4_solver_name_state ss;
		unsigned long state_buf[4];
		int state_int;
	};
	char name[];
};

struct ps4_repository {
	const char *url;
	struct ps4_digest hash;
	ps4_blob_t description;
};

#define PS4_DB_LAYER_ROOT		0
#define PS4_DB_LAYER_UVOL		1
#define PS4_DB_LAYER_NUM		2

#define PS4_REPOSITORY_CACHED		0
#define PS4_REPOSITORY_FIRST_CONFIGURED	1

#define PS4_DEFAULT_REPOSITORY_TAG	0
#define PS4_DEFAULT_PINNING_MASK	BIT(PS4_DEFAULT_REPOSITORY_TAG)

struct ps4_repository_tag {
	unsigned int allowed_repos;
	ps4_blob_t tag, plain_name;
};

struct ps4_database {
	struct ps4_ctx *ctx;
	struct ps4_balloc ba_names;
	struct ps4_balloc ba_pkgs;
	struct ps4_balloc ba_files;
	struct ps4_balloc ba_deps;
	int root_fd, lock_fd, cache_fd;
	unsigned num_repos, num_repo_tags;
	const char *cache_dir;
	char *cache_remount_dir, *root_proc_dir;
	unsigned long cache_remount_flags;
	ps4_blob_t *arch;
	unsigned int local_repos, available_repos;
	unsigned int pending_triggers;
	unsigned int extract_flags;
	unsigned int active_layers;
	unsigned int num_dir_update_errors;

	unsigned int performing_self_upgrade : 1;
	unsigned int usermode : 1;
	unsigned int permanent : 1;
	unsigned int autoupdate : 1;
	unsigned int write_arch : 1;
	unsigned int script_dirs_checked : 1;
	unsigned int open_complete : 1;
	unsigned int compat_newfeatures : 1;
	unsigned int compat_notinstallable : 1;
	unsigned int compat_depversions : 1;
	unsigned int sorted_names : 1;
	unsigned int sorted_installed_packages : 1;

	struct ps4_dependency_array *world;
	struct ps4_id_cache *id_cache;
	struct ps4_protected_path_array *protected_paths;
	struct ps4_repository repos[PS4_MAX_REPOS];
	struct ps4_repository_tag repo_tags[PS4_MAX_TAGS];
	struct ps4_atom_pool atoms;
	struct ps4_string_array *filename_array;
	struct ps4_package_tmpl overlay_tmpl;

	struct {
		unsigned stale, updated, unavailable;
	} repositories;

	struct {
		struct ps4_name_array *sorted_names;
		struct ps4_hash names;
		struct ps4_hash packages;
	} available;

	struct {
		struct ps4_package_array *sorted_packages;
		struct list_head packages;
		struct list_head triggers;
		struct ps4_hash dirs;
		struct ps4_hash files;
		struct {
			unsigned files;
			unsigned dirs;
			unsigned packages;
			size_t bytes;
		} stats;
	} installed;
};

typedef union ps4_database_or_void {
	struct ps4_database *db;
	void *ptr;
} ps4_database_t __attribute__ ((__transparent_union__));

static inline int ps4_name_cmp_display(const struct ps4_name *a, const struct ps4_name *b) {
	return strcasecmp(a->name, b->name) ?: strcmp(a->name, b->name);
}
struct ps4_provider_array *ps4_name_sorted_providers(struct ps4_name *);

struct ps4_name *ps4_db_get_name(struct ps4_database *db, ps4_blob_t name);
struct ps4_name *ps4_db_query_name(struct ps4_database *db, ps4_blob_t name);
int ps4_db_get_tag_id(struct ps4_database *db, ps4_blob_t tag);

void ps4_db_dir_update_permissions(struct ps4_database *db, struct ps4_db_dir_instance *diri);
void ps4_db_dir_prepare(struct ps4_database *db, struct ps4_db_dir *dir, struct ps4_db_acl *expected_acl, struct ps4_db_acl *new_acl);
void ps4_db_dir_unref(struct ps4_database *db, struct ps4_db_dir *dir, int allow_rmdir);
struct ps4_db_dir *ps4_db_dir_ref(struct ps4_db_dir *dir);
struct ps4_db_dir *ps4_db_dir_get(struct ps4_database *db, ps4_blob_t name);
struct ps4_db_dir *ps4_db_dir_query(struct ps4_database *db, ps4_blob_t name);
struct ps4_db_file *ps4_db_file_query(struct ps4_database *db,
				      ps4_blob_t dir, ps4_blob_t name);

const char *ps4_db_layer_name(int layer);
void ps4_db_init(struct ps4_database *db);
int ps4_db_open(struct ps4_database *db, struct ps4_ctx *ctx);
void ps4_db_close(struct ps4_database *db);
int ps4_db_write_config(struct ps4_database *db);
int ps4_db_permanent(struct ps4_database *db);
int ps4_db_check_world(struct ps4_database *db, struct ps4_dependency_array *world);
int ps4_db_fire_triggers(struct ps4_database *db);
int ps4_db_run_script(struct ps4_database *db, char *fn, char **argv);
static inline time_t ps4_db_url_since(struct ps4_database *db, time_t since) {
	return ps4_ctx_since(db->ctx, since);
}

struct ps4_package *ps4_db_pkg_add(struct ps4_database *db, struct ps4_package_tmpl *tmpl);
struct ps4_package *ps4_db_get_pkg(struct ps4_database *db, struct ps4_digest *id);
struct ps4_package *ps4_db_get_file_owner(struct ps4_database *db, ps4_blob_t filename);

int ps4_db_index_read(struct ps4_database *db, struct ps4_istream *is, int repo);
int ps4_db_index_read_file(struct ps4_database *db, const char *file, int repo);

int ps4_db_repository_check(struct ps4_database *db);
int ps4_db_add_repository(ps4_database_t db, ps4_blob_t repository);
struct ps4_repository *ps4_db_select_repo(struct ps4_database *db,
					  struct ps4_package *pkg);

int ps4_repo_format_cache_index(ps4_blob_t to, struct ps4_repository *repo);
int ps4_repo_format_item(struct ps4_database *db, struct ps4_repository *repo, struct ps4_package *pkg,
			 int *fd, char *buf, size_t len);

unsigned int ps4_db_get_pinning_mask_repos(struct ps4_database *db, unsigned short pinning_mask);

int ps4_db_cache_active(struct ps4_database *db);
int ps4_cache_download(struct ps4_database *db, struct ps4_repository *repo,
		       struct ps4_package *pkg, int autoupdate,
		       ps4_progress_cb cb, void *cb_ctx);

typedef void (*ps4_cache_item_cb)(struct ps4_database *db, int static_cache,
				  int dirfd, const char *name,
				  struct ps4_package *pkg);
int ps4_db_cache_foreach_item(struct ps4_database *db, ps4_cache_item_cb cb, int static_cache);

int ps4_db_install_pkg(struct ps4_database *db,
		       struct ps4_package *oldpkg,
		       struct ps4_package *newpkg,
		       ps4_progress_cb cb, void *cb_ctx);


struct ps4_package_array *ps4_db_sorted_installed_packages(struct ps4_database *db);

typedef int (*ps4_db_foreach_name_cb)(struct ps4_database *db, const char *match, struct ps4_name *name, void *ctx);

int ps4_db_foreach_matching_name(struct ps4_database *db, struct ps4_string_array *filter,
				 ps4_db_foreach_name_cb cb, void *ctx);

int ps4_db_foreach_sorted_name(struct ps4_database *db, struct ps4_string_array *filter,
			       ps4_db_foreach_name_cb cb, void *ctx);

typedef int (*ps4_db_foreach_package_cb)(struct ps4_database *db, const char *match, struct ps4_package *pkg, void *ctx);

int __ps4_db_foreach_sorted_package(struct ps4_database *db, struct ps4_string_array *filter,
				    ps4_db_foreach_package_cb cb, void *cb_ctx, int provides);

static inline int ps4_db_foreach_sorted_package(struct ps4_database *db, struct ps4_string_array *filter,
						ps4_db_foreach_package_cb cb, void *cb_ctx) {
	return __ps4_db_foreach_sorted_package(db, filter, cb, cb_ctx, 0);
}

static inline int ps4_db_foreach_sorted_providers(struct ps4_database *db, struct ps4_string_array *filter,
						  ps4_db_foreach_package_cb cb, void *cb_ctx) {
	return __ps4_db_foreach_sorted_package(db, filter, cb, cb_ctx, 1);
}

#endif
