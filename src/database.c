/* database.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifdef __linux__
# include <mntent.h>
# include <sys/vfs.h>
# include <sys/mount.h>
# include <sys/statvfs.h>
# include <linux/magic.h>
#endif

#include "ps4_defines.h"
#include "ps4_package.h"
#include "ps4_database.h"
#include "ps4_applet.h"
#include "ps4_ctype.h"
#include "ps4_extract.h"
#include "ps4_print.h"
#include "ps4_tar.h"
#include "ps4_adb.h"
#include "ps4_fs.h"

enum {
	PS4_DIR_FREE = 0,
	PS4_DIR_REMOVE
};

static const char * const ps4index_tar_gz = "PS4INDEX.tar.gz";
static const char * const ps4_static_cache_dir = "var/cache/ps4";
static const char * const ps4_world_file = "etc/ps4/world";
static const char * const ps4_arch_file = "etc/ps4/arch";
static const char * const ps4_lock_file = "lib/ps4/db/lock";

static struct ps4_db_acl *ps4_default_acl_dir, *ps4_default_acl_file;

struct install_ctx {
	struct ps4_database *db;
	struct ps4_package *pkg;
	struct ps4_installed_package *ipkg;

	int script;
	char **script_args;
	unsigned int script_pending : 1;
	unsigned int missing_checksum : 1;

	struct ps4_db_dir_instance *diri;
	struct ps4_extract_ctx ectx;

	ps4_progress_cb cb;
	void *cb_ctx;
	size_t installed_size;
	size_t current_file_size;

	struct hlist_node **diri_node;
	struct hlist_node **file_diri_node;
};

static mode_t ps4_db_dir_get_mode(struct ps4_database *db, mode_t mode)
{
	// in usermode, return mode that makes the file readable for user
	if (db->usermode) return mode | S_IWUSR | S_IXUSR;
	return mode;
}

static ps4_blob_t ps4_pkg_ctx(struct ps4_package *pkg)
{
	return PS4_BLOB_PTR_LEN(pkg->name->name, strlen(pkg->name->name)+1);
}

static ps4_blob_t pkg_name_get_key(ps4_hash_item item)
{
	return PS4_BLOB_STR(((struct ps4_name *) item)->name);
}

static void pkg_name_free(struct ps4_name *name)
{
	ps4_provider_array_free(&name->providers);
	ps4_name_array_free(&name->rdepends);
	ps4_name_array_free(&name->rinstall_if);
}

static const struct ps4_hash_ops pkg_name_hash_ops = {
	.node_offset = offsetof(struct ps4_name, hash_node),
	.get_key = pkg_name_get_key,
	.hash_key = ps4_blob_hash,
	.compare = ps4_blob_compare,
	.delete_item = (ps4_hash_delete_f) pkg_name_free,
};

static ps4_blob_t pkg_info_get_key(ps4_hash_item item)
{
	return ps4_pkg_hash_blob(item);
}

static unsigned long csum_hash(ps4_blob_t csum)
{
	/* Checksum's highest bits have the most "randomness", use that
	 * directly as hash */
	if (csum.len >= sizeof(uint32_t))
		return get_unaligned32(csum.ptr);
	return 0;
}

static const struct ps4_hash_ops pkg_info_hash_ops = {
	.node_offset = offsetof(struct ps4_package, hash_node),
	.get_key = pkg_info_get_key,
	.hash_key = csum_hash,
	.compare = ps4_blob_compare,
};

static ps4_blob_t ps4_db_dir_get_key(ps4_hash_item item)
{
	struct ps4_db_dir *dir = (struct ps4_db_dir *) item;
	return PS4_BLOB_PTR_LEN(dir->name, dir->namelen);
}

static const struct ps4_hash_ops dir_hash_ops = {
	.node_offset = offsetof(struct ps4_db_dir, hash_node),
	.get_key = ps4_db_dir_get_key,
	.hash_key = ps4_blob_hash,
	.compare = ps4_blob_compare,
};

struct ps4_db_file_hash_key {
	ps4_blob_t dirname;
	ps4_blob_t filename;
};

static unsigned long ps4_db_file_hash_key(ps4_blob_t _key)
{
	struct ps4_db_file_hash_key *key = (struct ps4_db_file_hash_key *) _key.ptr;

	return ps4_blob_hash_seed(key->filename, ps4_blob_hash(key->dirname));
}

static unsigned long ps4_db_file_hash_item(ps4_hash_item item)
{
	struct ps4_db_file *dbf = (struct ps4_db_file *) item;

	return ps4_blob_hash_seed(PS4_BLOB_PTR_LEN(dbf->name, dbf->namelen),
				  dbf->diri->dir->hash);
}

static int ps4_db_file_compare_item(ps4_hash_item item, ps4_blob_t _key)
{
	struct ps4_db_file *dbf = (struct ps4_db_file *) item;
	struct ps4_db_file_hash_key *key = (struct ps4_db_file_hash_key *) _key.ptr;
	struct ps4_db_dir *dir = dbf->diri->dir;
	int r;

	r = ps4_blob_compare(key->filename,
			     PS4_BLOB_PTR_LEN(dbf->name, dbf->namelen));
	if (r != 0)
		return r;

	r = ps4_blob_compare(key->dirname,
			     PS4_BLOB_PTR_LEN(dir->name, dir->namelen));
	return r;
}

static const struct ps4_hash_ops file_hash_ops = {
	.node_offset = offsetof(struct ps4_db_file, hash_node),
	.hash_key = ps4_db_file_hash_key,
	.hash_item = ps4_db_file_hash_item,
	.compare_item = ps4_db_file_compare_item,
};

struct ps4_name *ps4_db_query_name(struct ps4_database *db, ps4_blob_t name)
{
	return (struct ps4_name *) ps4_hash_get(&db->available.names, name);
}

struct ps4_name *ps4_db_get_name(struct ps4_database *db, ps4_blob_t name)
{
	struct ps4_name *pn;
	unsigned long hash = ps4_hash_from_key(&db->available.names, name);

	pn = (struct ps4_name *) ps4_hash_get_hashed(&db->available.names, name, hash);
	if (pn != NULL)
		return pn;

	pn = ps4_balloc_new_extra(&db->ba_names, struct ps4_name, name.len+1);
	if (pn == NULL) return NULL;

	memset(pn, 0, sizeof *pn);
	memcpy(pn->name, name.ptr, name.len);
	pn->name[name.len] = 0;
	ps4_provider_array_init(&pn->providers);
	ps4_name_array_init(&pn->rdepends);
	ps4_name_array_init(&pn->rinstall_if);
	ps4_hash_insert_hashed(&db->available.names, pn, hash);
	db->sorted_names = 0;

	return pn;
}

static int cmp_provider(const void *a, const void *b)
{
	const struct ps4_provider *pa = a, *pb = b;
	return ps4_pkg_cmp_display(pa->pkg, pb->pkg);
}

struct ps4_provider_array *ps4_name_sorted_providers(struct ps4_name *name)
{
	if (!name->providers_sorted) {
		ps4_array_qsort(name->providers, cmp_provider);
		name->providers_sorted = 0;
	}
	return name->providers;
}

static struct ps4_db_acl *__ps4_db_acl_atomize(struct ps4_database *db, mode_t mode, uid_t uid, gid_t gid, uint8_t hash_len, const uint8_t *hash)
{
	struct {
		struct ps4_db_acl acl;
		uint8_t digest[PS4_DIGEST_LENGTH_MAX];
	} data;
	ps4_blob_t *b;

	data.acl = (struct ps4_db_acl) { .mode = mode & 07777, .uid = uid, .gid = gid, .xattr_hash_len = hash_len };
	if (hash_len) memcpy(data.digest, hash, hash_len);

	b = ps4_atomize_dup(&db->atoms, PS4_BLOB_PTR_LEN((char*) &data, sizeof(data.acl) + hash_len));
	return (struct ps4_db_acl *) b->ptr;
}

static struct ps4_db_acl *ps4_db_acl_atomize(struct ps4_database *db, mode_t mode, uid_t uid, gid_t gid)
{
	return __ps4_db_acl_atomize(db, mode, uid, gid, 0, 0);
}

static struct ps4_db_acl *ps4_db_acl_atomize_digest(struct ps4_database *db, mode_t mode, uid_t uid, gid_t gid, const struct ps4_digest *dig)
{
	return __ps4_db_acl_atomize(db, mode, uid, gid, dig->len, dig->data);
}

static int ps4_db_dir_mkdir(struct ps4_database *db, struct ps4_fsdir *d, struct ps4_db_acl *acl)
{
	if (db->ctx->flags & PS4_SIMULATE) return 0;
	return ps4_fsdir_create(d, ps4_db_dir_get_mode(db, acl->mode), acl->uid, acl->gid);
}

void ps4_db_dir_prepare(struct ps4_database *db, struct ps4_db_dir *dir, struct ps4_db_acl *expected_acl, struct ps4_db_acl *new_acl)
{
	struct ps4_fsdir d;

	if (dir->namelen == 0) return;
	if (dir->created) return;
	dir->created = 1;

	ps4_fsdir_get(&d, PS4_BLOB_PTR_LEN(dir->name, dir->namelen), db->extract_flags, db->ctx, PS4_BLOB_NULL);
	if (!expected_acl) {
		/* Directory should not exist. Create it. */
		if (ps4_db_dir_mkdir(db, &d, new_acl) == 0)
			dir->permissions_ok = 1;
		return;
	}

	switch (ps4_fsdir_check(&d, ps4_db_dir_get_mode(db, expected_acl->mode), expected_acl->uid, expected_acl->gid)) {
	case -ENOENT:
		if (ps4_db_dir_mkdir(db, &d, new_acl) == 0)
			dir->permissions_ok = 1;
		break;
	case 0:
		dir->permissions_ok = 1;
		break;
	case PS4_FS_DIR_MODIFIED:
	default:
		break;
	}
}

void ps4_db_dir_unref(struct ps4_database *db, struct ps4_db_dir *dir, int rmdir_mode)
{
	if (--dir->refs > 0) return;
	db->installed.stats.dirs--;
	ps4_protected_path_array_free(&dir->protected_paths);
	list_del(&dir->diris);
	if (dir->namelen != 0) {
		if (rmdir_mode == PS4_DIR_REMOVE) {
			dir->modified = 1;
			if (!(db->ctx->flags & PS4_SIMULATE)) {
				struct ps4_fsdir d;
				ps4_fsdir_get(&d, PS4_BLOB_PTR_LEN(dir->name, dir->namelen),
					      db->extract_flags, db->ctx, PS4_BLOB_NULL);
				ps4_fsdir_delete(&d);
			}
		}
		ps4_db_dir_unref(db, dir->parent, rmdir_mode);
		dir->parent = NULL;
	}
	dir->created = dir->permissions_ok = 0;
}

struct ps4_db_dir *ps4_db_dir_ref(struct ps4_db_dir *dir)
{
	dir->refs++;
	return dir;
}

struct ps4_db_dir *ps4_db_dir_query(struct ps4_database *db,
				    ps4_blob_t name)
{
	return (struct ps4_db_dir *) ps4_hash_get(&db->installed.dirs, name);
}

struct ps4_db_dir *ps4_db_dir_get(struct ps4_database *db, ps4_blob_t name)
{
	struct ps4_db_dir *dir;
	struct ps4_protected_path_array *ppaths;
	struct ps4_protected_path *ppath;
	ps4_blob_t bparent;
	unsigned long hash = ps4_hash_from_key(&db->installed.dirs, name);
	char *relative_name;

	if (name.len && name.ptr[name.len-1] == '/') name.len--;

	dir = (struct ps4_db_dir *) ps4_hash_get_hashed(&db->installed.dirs, name, hash);
	if (dir != NULL && dir->refs) return ps4_db_dir_ref(dir);
	if (dir == NULL) {
		dir = ps4_balloc_new_extra(&db->ba_files, struct ps4_db_dir, name.len+1);
		memset(dir, 0, sizeof *dir);
		dir->rooted_name[0] = '/';
		memcpy(dir->name, name.ptr, name.len);
		dir->name[name.len] = 0;
		dir->namelen = name.len;
		dir->hash = hash;
		ps4_protected_path_array_init(&dir->protected_paths);
		ps4_hash_insert_hashed(&db->installed.dirs, dir, hash);
	}

	db->installed.stats.dirs++;
	dir->refs = 1;
	list_init(&dir->diris);

	if (name.len == 0) {
		dir->parent = NULL;
		dir->has_protected_children = 1;
		ppaths = NULL;
	} else if (ps4_blob_rsplit(name, '/', &bparent, NULL)) {
		dir->parent = ps4_db_dir_get(db, bparent);
		dir->protect_mode = dir->parent->protect_mode;
		dir->has_protected_children = !ps4_protect_mode_none(dir->protect_mode);
		ppaths = dir->parent->protected_paths;
	} else {
		dir->parent = ps4_db_dir_get(db, PS4_BLOB_NULL);
		ppaths = db->protected_paths;
	}

	if (ppaths == NULL)
		return dir;

	relative_name = strrchr(dir->rooted_name, '/') + 1;
	foreach_array_item(ppath, ppaths) {
		char *slash = strchr(ppath->relative_pattern, '/');
		if (slash != NULL) {
			*slash = 0;
			if (fnmatch(ppath->relative_pattern, relative_name, FNM_PATHNAME) != 0) {
				*slash = '/';
				continue;
			}
			*slash = '/';

			ps4_protected_path_array_add(&dir->protected_paths, (struct ps4_protected_path) {
				.relative_pattern = slash + 1,
				.protect_mode = ppath->protect_mode,
			});
		} else {
			if (fnmatch(ppath->relative_pattern, relative_name, FNM_PATHNAME) != 0)
				continue;

			dir->protect_mode = ppath->protect_mode;
		}
		dir->has_protected_children |= !ps4_protect_mode_none(ppath->protect_mode);
	}

	return dir;
}

static struct ps4_db_dir_instance *ps4_db_diri_new(struct ps4_database *db,
						   struct ps4_package *pkg,
						   ps4_blob_t name,
						   struct hlist_node ***after)
{
	struct ps4_db_dir_instance *diri;

	diri = calloc(1, sizeof(struct ps4_db_dir_instance));
	if (diri != NULL) {
		struct ps4_db_dir *dir = ps4_db_dir_get(db, name);
		list_init(&diri->dir_diri_list);
		list_add(&diri->dir_diri_list, &dir->diris);
		hlist_add_after(&diri->pkg_dirs_list, *after);
		*after = &diri->pkg_dirs_list.next;
		diri->dir = dir;
		diri->pkg = pkg;
		diri->acl = ps4_default_acl_dir;
	}

	return diri;
}

void ps4_db_dir_update_permissions(struct ps4_database *db, struct ps4_db_dir_instance *diri)
{
	struct ps4_db_dir *dir = diri->dir;
	struct ps4_db_acl *acl = diri->acl;
	struct ps4_fsdir d;

	if (!dir->permissions_ok) return;
	if (db->ctx->flags & PS4_SIMULATE) return;

	dir->modified = 1;
	ps4_fsdir_get(&d, PS4_BLOB_PTR_LEN(dir->name, dir->namelen), db->extract_flags, db->ctx, PS4_BLOB_NULL);
	if (ps4_fsdir_update_perms(&d, ps4_db_dir_get_mode(db, acl->mode), acl->uid, acl->gid) != 0)
		db->num_dir_update_errors++;
}

static void ps4_db_dir_apply_diri_permissions(struct ps4_database *db, struct ps4_db_dir_instance *diri)
{
	struct ps4_db_dir *dir = diri->dir;
	struct ps4_db_acl *acl = diri->acl;

	if (dir->owner && ps4_pkg_replaces_dir(dir->owner->pkg, diri->pkg) != PS4_PKG_REPLACES_YES)
		return;

	// Check if the ACL changed and the directory needs update
	if (dir->owner && dir->owner->acl != acl) ps4_db_dir_update_permissions(db, diri);
	dir->owner = diri;
}

static void ps4_db_diri_free(struct ps4_database *db,
			     struct ps4_db_dir_instance *diri,
			     int rmdir_mode)
{
	list_del(&diri->dir_diri_list);
	if (rmdir_mode == PS4_DIR_REMOVE && diri->dir->owner == diri) {
		// Walk the directory instance to determine new owner
		struct ps4_db_dir *dir = diri->dir;
		struct ps4_db_dir_instance *di;
		dir->owner = NULL;
		list_for_each_entry(di, &dir->diris, dir_diri_list) {
			if (dir->owner == NULL ||
			    ps4_pkg_replaces_dir(dir->owner->pkg, di->pkg) == PS4_PKG_REPLACES_YES)
				dir->owner = di;
		}
		if (dir->owner) ps4_db_dir_update_permissions(db, dir->owner);
	}
	ps4_db_dir_unref(db, diri->dir, rmdir_mode);
	free(diri);
}

struct ps4_db_file *ps4_db_file_query(struct ps4_database *db,
				      ps4_blob_t dir,
				      ps4_blob_t name)
{
	struct ps4_db_file_hash_key key;

	if (dir.len && dir.ptr[dir.len-1] == '/')
		dir.len--;

	key = (struct ps4_db_file_hash_key) {
		.dirname = dir,
		.filename = name,
	};

	return (struct ps4_db_file *) ps4_hash_get(&db->installed.files,
						   PS4_BLOB_BUF(&key));
}

static struct ps4_db_file *ps4_db_file_new(struct ps4_database *db,
					   struct ps4_db_dir_instance *diri,
					   ps4_blob_t name,
					   struct hlist_node ***after)
{
	struct ps4_db_file *file;

	file = ps4_balloc_new_extra(&db->ba_files, struct ps4_db_file, name.len+1);
	if (file == NULL) return NULL;

	memset(file, 0, sizeof(*file));
	memcpy(file->name, name.ptr, name.len);
	file->name[name.len] = 0;
	file->namelen = name.len;
	file->diri = diri;
	file->acl = ps4_default_acl_file;
	hlist_add_after(&file->diri_files_list, *after);
	*after = &file->diri_files_list.next;

	return file;
}

static struct ps4_db_file *ps4_db_file_get(struct ps4_database *db,
					   struct ps4_db_dir_instance *diri,
					   ps4_blob_t name,
					   struct hlist_node ***after)
{
	struct ps4_db_file *file;
	struct ps4_db_file_hash_key key;
	struct ps4_db_dir *dir = diri->dir;
	unsigned long hash;

	key = (struct ps4_db_file_hash_key) {
		.dirname = PS4_BLOB_PTR_LEN(dir->name, dir->namelen),
		.filename = name,
	};

	hash = ps4_blob_hash_seed(name, dir->hash);
	file = (struct ps4_db_file *) ps4_hash_get_hashed(
		&db->installed.files, PS4_BLOB_BUF(&key), hash);
	if (file != NULL)
		return file;

	file = ps4_db_file_new(db, diri, name, after);
	ps4_hash_insert_hashed(&db->installed.files, file, hash);
	db->installed.stats.files++;

	return file;
}

static void add_name_to_array(struct ps4_name *name, struct ps4_name_array **a)
{
	struct ps4_name **n;

	foreach_array_item(n, *a)
		if (*n == name) return;
	ps4_name_array_add(a, name);
}

static void ps4_db_pkg_rdepends(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_name *rname;
	struct ps4_dependency *d;

	foreach_array_item(d, pkg->depends) {
		rname = d->name;
		rname->is_dependency |= !ps4_dep_conflict(d);
		add_name_to_array(pkg->name, &rname->rdepends);
	}
	foreach_array_item(d, pkg->install_if) {
		rname = d->name;
		add_name_to_array(pkg->name, &rname->rinstall_if);
	}
}

struct ps4_package *ps4_db_pkg_add(struct ps4_database *db, struct ps4_package_tmpl *tmpl)
{
	struct ps4_package *pkg = &tmpl->pkg, *idb;
	struct ps4_dependency *dep;

	if (!pkg->name || !pkg->version || tmpl->id.len < PS4_DIGEST_LENGTH_SHA1) return NULL;

	// Set as "cached" if installing from specified file
	if (pkg->filename_ndx) pkg->repos |= BIT(ps4_REPOSITORY_CACHED);

	idb = ps4_hash_get(&db->available.packages, PS4_BLOB_PTR_LEN((char*)tmpl->id.data, PS4_DIGEST_LENGTH_SHA1));
	if (idb == NULL) {
		idb = ps4_balloc_new_extra(&db->ba_pkgs, struct ps4_package, tmpl->id.len);
		memcpy(idb, pkg, sizeof *pkg);
		memcpy(idb->digest, tmpl->id.data, tmpl->id.len);
		idb->digest_alg = tmpl->id.alg;
		if (idb->digest_alg == PS4_DIGEST_SHA1 && idb->ipkg && idb->ipkg->sha256_160)
			idb->digest_alg = PS4_DIGEST_SHA256_160;
		idb->ipkg = NULL;
		idb->depends = ps4_deps_bclone(pkg->depends, &db->ba_deps);
		idb->install_if = ps4_deps_bclone(pkg->install_if, &db->ba_deps);
		idb->provides = ps4_deps_bclone(pkg->provides, &db->ba_deps);

		ps4_hash_insert(&db->available.packages, idb);
		ps4_provider_array_add(&idb->name->providers, PS4_PROVIDER_FROM_PACKAGE(idb));
		foreach_array_item(dep, idb->provides)
			ps4_provider_array_add(&dep->name->providers, PS4_PROVIDER_FROM_PROVIDES(idb, dep));
		if (db->open_complete)
			ps4_db_pkg_rdepends(db, idb);
	} else {
		idb->repos |= pkg->repos;
		if (!idb->filename_ndx) idb->filename_ndx = pkg->filename_ndx;
	}
	if (idb->ipkg == NULL && pkg->ipkg != NULL) {
		struct ps4_db_dir_instance *diri;
		struct hlist_node *n;

		hlist_for_each_entry(diri, n, &pkg->ipkg->owned_dirs, pkg_dirs_list)
			diri->pkg = idb;
		idb->ipkg = pkg->ipkg;
		idb->ipkg->pkg = idb;
		pkg->ipkg = NULL;
	}
	ps4_pkgtmpl_reset(tmpl);
	return idb;
}

static int ps4_pkg_format_cache_pkg(ps4_blob_t to, struct ps4_package *pkg)
{
	/* pkgname-1.0_alpha1.12345678.ps4 */
	ps4_blob_push_blob(&to, PS4_BLOB_STR(pkg->name->name));
	ps4_blob_push_blob(&to, PS4_BLOB_STR("-"));
	ps4_blob_push_blob(&to, *pkg->version);
	ps4_blob_push_blob(&to, PS4_BLOB_STR("."));
	ps4_blob_push_hexdump(&to, PS4_BLOB_PTR_LEN((char *) pkg->digest, PS4_CACHE_CSUM_BYTES));
	ps4_blob_push_blob(&to, PS4_BLOB_STR(".ps4"));
	ps4_blob_push_blob(&to, PS4_BLOB_PTR_LEN("", 1));
	if (ps4_BLOB_IS_NULL(to))
		return -ENOBUFS;
	return 0;
}

int ps4_repo_format_cache_index(ps4_blob_t to, struct ps4_repository *repo)
{
	/* ps4INDEX.12345678.tar.gz */
	ps4_blob_push_blob(&to, PS4_BLOB_STR("PS4INDEX."));
	ps4_blob_push_hexdump(&to, PS4_BLOB_PTR_LEN((char *) repo->hash.data, PS4_CACHE_CSUM_BYTES));
	ps4_blob_push_blob(&to, PS4_BLOB_STR(".tar.gz"));
	ps4_blob_push_blob(&to, PS4_BLOB_PTR_LEN("", 1));
	if (PS4_BLOB_IS_NULL(to))
		return -ENOBUFS;
	return 0;
}

int ps4_repo_format_real_url(ps4_blob_t *default_arch, struct ps4_repository *repo,
			     struct ps4_package *pkg, char *buf, size_t len,
			     struct ps4_url_print *urlp)
{

	ps4_blob_t uri = PS4_BLOB_STR(repo->url);
	ps4_blob_t arch;
	int r;

	if (pkg && pkg->arch) arch = *pkg->arch;
	else arch = *default_arch;

	if (ps4_blob_ends_with(uri, PS4_BLOB_STR(".adb"))) {
		if (pkg != NULL) {
			ps4_blob_rsplit(uri, '/', &uri, NULL);
			r = snprintf(buf, len, BLOB_FMT "/" PKG_FILE_FMT,
				BLOB_PRINTF(uri), PKG_FILE_PRINTF(pkg));
		} else {
			r = snprintf(buf, len, BLOB_FMT, BLOB_PRINTF(uri));
		}
	} else {
		while (uri.len && uri.ptr[uri.len-1] == '/') uri.len--;
		if (pkg != NULL)
			r = snprintf(buf, len, BLOB_FMT "/" BLOB_FMT "/" PKG_FILE_FMT,
				BLOB_PRINTF(uri), BLOB_PRINTF(arch), PKG_FILE_PRINTF(pkg));
		else
			r = snprintf(buf, len, BLOB_FMT "/" BLOB_FMT "/%s",
				BLOB_PRINTF(uri), BLOB_PRINTF(arch), ps4index_tar_gz);
	}

	if (r >= len)
		return -ENOBUFS;

	if (urlp) ps4_url_parse(urlp, buf);
	return 0;
}

int ps4_repo_format_item(struct ps4_database *db, struct ps4_repository *repo, struct ps4_package *pkg,
			 int *fd, char *buf, size_t len)
{
	if (repo->url == db->repos[PS4_REPOSITORY_CACHED].url) {
		if (db->cache_fd < 0) return db->cache_fd;
		*fd = db->cache_fd;
		return ps4_pkg_format_cache_pkg(PS4_BLOB_PTR_LEN(buf, len), pkg);
	}

	*fd = AT_FDCWD;
	return ps4_repo_format_real_url(db->arch, repo, pkg, buf, len, 0);
}

int ps4_cache_download(struct ps4_database *db, struct ps4_repository *repo,
		       struct ps4_package *pkg, int autoupdate,
		       ps4_progress_cb cb, void *cb_ctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct stat st = {0};
	struct ps4_url_print urlp;
	struct ps4_istream *is;
	struct ps4_ostream *os;
	struct ps4_extract_ctx ectx;
	char url[PATH_MAX];
	char cacheitem[128];
	int r;
	time_t now = time(NULL);

	if (db->cache_fd < 0) return db->cache_fd;

	if (pkg != NULL)
		r = ps4_pkg_format_cache_pkg(PS4_BLOB_BUF(cacheitem), pkg);
	else
		r = ps4_repo_format_cache_index(PS4_BLOB_BUF(cacheitem), repo);
	if (r < 0) return r;

	r = ps4_repo_format_real_url(db->arch, repo, pkg, url, sizeof(url), &urlp);
	if (r < 0) return r;

	if (autoupdate && !(db->ctx->force & PS4_FORCE_REFRESH)) {
		if (fstatat(db->cache_fd, cacheitem, &st, 0) == 0 &&
		    now - st.st_mtime <= db->ctx->cache_max_age)
			return -EALREADY;
	}
	ps4_notice(out, "fetch " URL_FMT, URL_PRINTF(urlp));

	if (db->ctx->flags & PS4_SIMULATE) return 0;

	os = ps4_ostream_to_file(db->cache_fd, cacheitem, 0644);
	if (IS_ERR(os)) return PTR_ERR(os);

	if (cb) cb(cb_ctx, 0);

	is = ps4_istream_from_url(url, ps4_db_url_since(db, st.st_mtime));
	is = ps4_istream_tee(is, os, autoupdate ? 0 : PS4_ISTREAM_TEE_COPY_META, cb, cb_ctx);
	ps4_extract_init(&ectx, db->ctx, NULL);
	if (pkg) ps4_extract_verify_identity(&ectx, pkg->digest_alg, ps4_pkg_digest_blob(pkg));
	r = ps4_extract(&ectx, is);
	if (r == -EALREADY) {
		if (autoupdate) utimensat(db->cache_fd, cacheitem, NULL, 0);
		return r;
	}
	return r;
}

static struct ps4_db_dir_instance *find_diri(struct ps4_installed_package *ipkg,
					     ps4_blob_t dirname,
					     struct ps4_db_dir_instance *curdiri,
					     struct hlist_node ***tail)
{
	struct hlist_node *n;
	struct ps4_db_dir_instance *diri;

	if (curdiri != NULL &&
	    ps4_blob_compare(PS4_BLOB_PTR_LEN(curdiri->dir->name,
					      curdiri->dir->namelen),
			     dirname) == 0)
		return curdiri;

	hlist_for_each_entry(diri, n, &ipkg->owned_dirs, pkg_dirs_list) {
		if (ps4_blob_compare(PS4_BLOB_PTR_LEN(diri->dir->name,
						      diri->dir->namelen), dirname) == 0) {
			if (tail != NULL)
				*tail = hlist_tail_ptr(&diri->owned_files);
			return diri;
		}
	}
	return NULL;
}

int ps4_db_read_overlay(struct ps4_database *db, struct ps4_istream *is)
{
	struct ps4_db_dir_instance *diri = NULL;
	struct hlist_node **diri_node = NULL, **file_diri_node = NULL;
	struct ps4_package *pkg = &db->overlay_tmpl.pkg;
	struct ps4_installed_package *ipkg;
	ps4_blob_t token = PS4_BLOB_STR("\n"), line, bdir, bfile;

	if (IS_ERR(is)) return PTR_ERR(is);

	ipkg = ps4_pkg_install(db, pkg);
	if (ipkg == NULL) {
		ps4_istream_error(is, -ENOMEM);
		goto err;
	}

	diri_node = hlist_tail_ptr(&ipkg->owned_dirs);

	while (ps4_istream_get_delim(is, token, &line) == 0) {
		if (!ps4_blob_rsplit(line, '/', &bdir, &bfile)) {
			ps4_istream_error(is, -PS4E_V2PKG_FORMAT);
			break;
		}

		if (bfile.len == 0) {
			diri = ps4_db_diri_new(db, pkg, bdir, &diri_node);
			file_diri_node = &diri->owned_files.first;
			diri->dir->created = 1;
		} else {
			diri = find_diri(ipkg, bdir, diri, &file_diri_node);
			if (diri == NULL) {
				diri = ps4_db_diri_new(db, pkg, bdir, &diri_node);
				file_diri_node = &diri->owned_files.first;
			}
			(void) ps4_db_file_get(db, diri, bfile, &file_diri_node);
		}
	}
err:
	return ps4_istream_close(is);
}

static int ps4_db_fdb_read(struct ps4_database *db, struct ps4_istream *is, int repo, unsigned layer)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_package_tmpl tmpl;
	struct ps4_installed_package *ipkg = NULL;
	struct ps4_db_dir_instance *diri = NULL;
	struct ps4_db_file *file = NULL;
	struct ps4_db_acl *acl;
	struct hlist_node **diri_node = NULL;
	struct hlist_node **file_diri_node = NULL;
	struct ps4_digest file_digest, xattr_digest;
	ps4_blob_t token = PS4_BLOB_STR("\n"), l;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int field, r, lineno = 0;

	if (IS_ERR(is)) return PTR_ERR(is);

	ps4_pkgtmpl_init(&tmpl);
	tmpl.pkg.layer = layer;

	while (ps4_istream_get_delim(is, token, &l) == 0) {
		lineno++;

		if (l.len < 2) {
			if (!tmpl.pkg.name) continue;
			if (diri) ps4_db_dir_apply_diri_permissions(db, diri);

			if (repo >= 0) {
				tmpl.pkg.repos |= BIT(repo);
			} else if (repo == -2) {
				tmpl.pkg.cached_non_repository = 1;
			} else if (repo == -1 && ipkg == NULL) {
				/* Installed package without files */
				ipkg = ps4_pkg_install(db, &tmpl.pkg);
			}

			if (ps4_db_pkg_add(db, &tmpl) == NULL)
				goto err_fmt;

			tmpl.pkg.layer = layer;
			ipkg = NULL;
			diri = NULL;
			file_diri_node = NULL;
			continue;
		}

		/* Get field */
		field = l.ptr[0];
		if (l.ptr[1] != ':') goto err_fmt;
		l.ptr += 2;
		l.len -= 2;

		/* Standard index line? */
		r = ps4_pkgtmpl_add_info(db, &tmpl, field, l);
		if (r == 0) continue;
		if (r == 1 && repo == -1 && ipkg == NULL) {
			/* Instert to installed database; this needs to
			 * happen after package name has been read, but
			 * before first FDB entry. */
			ipkg = ps4_pkg_install(db, &tmpl.pkg);
			diri_node = hlist_tail_ptr(&ipkg->owned_dirs);
		}
		if (repo != -1 || ipkg == NULL) continue;

		/* Check FDB special entries */
		switch (field) {
		case 'F':
			if (diri) ps4_db_dir_apply_diri_permissions(db, diri);
			if (tmpl.pkg.name == NULL) goto bad_entry;
			diri = find_diri(ipkg, l, NULL, &diri_node);
			if (!diri) diri = ps4_db_diri_new(db, &tmpl.pkg, l, &diri_node);
			file_diri_node = hlist_tail_ptr(&diri->owned_files);
			break;
		case 'a':
			if (file == NULL) goto bad_entry;
		case 'M':
			if (diri == NULL) goto bad_entry;
			uid = ps4_blob_pull_uint(&l, 10);
			ps4_blob_pull_char(&l, ':');
			gid = ps4_blob_pull_uint(&l, 10);
			ps4_blob_pull_char(&l, ':');
			mode = ps4_blob_pull_uint(&l, 8);
			if (ps4_blob_pull_blob_match(&l, PS4_BLOB_STR(":")))
				ps4_blob_pull_digest(&l, &xattr_digest);
			else
				ps4_digest_reset(&xattr_digest);

			acl = ps4_db_acl_atomize_digest(db, mode, uid, gid, &xattr_digest);
			if (field == 'M')
				diri->acl = acl;
			else
				file->acl = acl;
			break;
		case 'R':
			if (diri == NULL) goto bad_entry;
			file = ps4_db_file_get(db, diri, l, &file_diri_node);
			break;
		case 'Z':
			if (file == NULL) goto bad_entry;
			ps4_blob_pull_digest(&l, &file_digest);
			if (file_digest.alg == PS4_DIGEST_SHA1 && ipkg->sha256_160)
				ps4_digest_set(&file_digest, PS4_DIGEST_SHA256_160);
			ps4_dbf_digest_set(file, file_digest.alg, file_digest.data);
			break;
		case 'r':
			ps4_blob_pull_deps(&l, db, &ipkg->replaces);
			break;
		case 'q':
			ipkg->replaces_priority = ps4_blob_pull_uint(&l, 10);
			break;
		case 's':
			ipkg->repository_tag = ps4_db_get_tag_id(db, l);
			break;
		case 'f':
			for (r = 0; r < l.len; r++) {
				switch (l.ptr[r]) {
				case 'f': ipkg->broken_files = 1; break;
				case 's': ipkg->broken_script = 1; break;
				case 'x': ipkg->broken_xattr = 1; break;
				case 'S': ipkg->sha256_160 = 1; break;
				default:
					if (!(db->ctx->force & PS4_FORCE_OLD_PS4))
						goto old_ps4_tools;
				}
			}
			break;
		default:
			if (r != 0 && !(db->ctx->force & PS4_FORCE_OLD_PS4))
				goto old_ps4_tools;
			/* Installed. So mark the package as installable. */
			tmpl.pkg.filename_ndx = 0;
			continue;
		}
		if (ps4_BLOB_IS_NULL(l)) goto bad_entry;
	}
	ps4_pkgtmpl_free(&tmpl);
	return ps4_istream_close(is);
old_ps4_tools:
	/* Installed db should not have unsupported fields */
	ps4_err(out, "This ps4-tools is too old to handle installed packages");
	goto err_fmt;
bad_entry:
	ps4_err(out, "FDB format error (line %d, entry '%c')", lineno, field);
err_fmt:
	is->err = -PS4E_V2DB_FORMAT;
	ps4_pkgtmpl_free(&tmpl);
	return ps4_istream_close(is);
}

int ps4_db_index_read(struct ps4_database *db, struct ps4_istream *is, int repo)
{
	return ps4_db_fdb_read(db, is, repo, 0);
}

static void ps4_blob_push_db_acl(ps4_blob_t *b, char field, struct ps4_db_acl *acl)
{
	char hdr[2] = { field, ':' };

	ps4_blob_push_blob(b, PS4_BLOB_BUF(hdr));
	ps4_blob_push_uint(b, acl->uid, 10);
	ps4_blob_push_blob(b, PS4_BLOB_STR(":"));
	ps4_blob_push_uint(b, acl->gid, 10);
	ps4_blob_push_blob(b, PS4_BLOB_STR(":"));
	ps4_blob_push_uint(b, acl->mode, 8);
	if (acl->xattr_hash_len != 0) {
		ps4_blob_push_blob(b, PS4_BLOB_STR(":"));
		ps4_blob_push_hash(b, ps4_acl_digest_blob(acl));
	}
	ps4_blob_push_blob(b, PS4_BLOB_STR("\n"));
}

static int ps4_db_fdb_write(struct ps4_database *db, struct ps4_installed_package *ipkg, struct ps4_ostream *os)
{
	struct ps4_package *pkg = ipkg->pkg;
	struct ps4_db_dir_instance *diri;
	struct ps4_db_file *file;
	struct hlist_node *c1, *c2;
	char buf[1024+PATH_MAX];
	ps4_blob_t bbuf = PS4_BLOB_BUF(buf);
	int r = 0;

	if (IS_ERR(os)) return PTR_ERR(os);

	r = ps4_pkg_write_index_header(pkg, os);
	if (r < 0) goto err;

	if (ps4_array_len(ipkg->replaces) != 0) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("r:"));
		ps4_blob_push_deps(&bbuf, db, ipkg->replaces);
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));
	}
	if (ipkg->replaces_priority) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("q:"));
		ps4_blob_push_uint(&bbuf, ipkg->replaces_priority, 10);
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));
	}
	if (ipkg->repository_tag) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("s:"));
		ps4_blob_push_blob(&bbuf, db->repo_tags[ipkg->repository_tag].plain_name);
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));
	}
	if (ipkg->broken_files || ipkg->broken_script || ipkg->broken_xattr || ipkg->sha256_160) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("f:"));
		if (ipkg->broken_files)
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("f"));
		if (ipkg->broken_script)
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("s"));
		if (ipkg->broken_xattr)
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("x"));
		if (ipkg->sha256_160)
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("S"));
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));
	}
	hlist_for_each_entry(diri, c1, &ipkg->owned_dirs, pkg_dirs_list) {
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("F:"));
		ps4_blob_push_blob(&bbuf, PS4_BLOB_PTR_LEN(diri->dir->name, diri->dir->namelen));
		ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));

		if (diri->acl != ps4_default_acl_dir)
			ps4_blob_push_db_acl(&bbuf, 'M', diri->acl);

		bbuf = ps4_blob_pushed(PS4_BLOB_BUF(buf), bbuf);
		if (PS4_BLOB_IS_NULL(bbuf)) {
			r = -ENOBUFS;
			goto err;
		}
		r = ps4_ostream_write(os, bbuf.ptr, bbuf.len);
		if (r < 0) goto err;
		bbuf = PS4_BLOB_BUF(buf);

		hlist_for_each_entry(file, c2, &diri->owned_files, diri_files_list) {
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("R:"));
			ps4_blob_push_blob(&bbuf, PS4_BLOB_PTR_LEN(file->name, file->namelen));
			ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));

			if (file->acl != ps4_default_acl_file)
				ps4_blob_push_db_acl(&bbuf, 'a', file->acl);

			if (file->digest_alg != PS4_DIGEST_NONE) {
				ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("Z:"));
				ps4_blob_push_hash(&bbuf, ps4_dbf_digest_blob(file));
				ps4_blob_push_blob(&bbuf, PS4_BLOB_STR("\n"));
			}

			bbuf = ps4_blob_pushed(PS4_BLOB_BUF(buf), bbuf);
			if (PS4_BLOB_IS_NULL(bbuf)) {
				r = -ENOBUFS;
				goto err;
			}
			r = ps4_ostream_write(os, bbuf.ptr, bbuf.len);
			if (r < 0) goto err;
			bbuf = PS4_BLOB_BUF(buf);
		}
	}
	r = ps4_ostream_write(os, "\n", 1);
err:
	if (r < 0) ps4_ostream_cancel(os, r);
	return r;
}

static int ps4_db_scriptdb_write(struct ps4_database *db, struct ps4_installed_package *ipkg, struct ps4_ostream *os)
{
	struct ps4_package *pkg = ipkg->pkg;
	struct ps4_file_info fi;
	char filename[256];
	ps4_blob_t bfn;
	int r, i;

	if (IS_ERR(os)) return PTR_ERR(os);

	for (i = 0; i < PS4_SCRIPT_MAX; i++) {
		if (!ipkg->script[i].ptr) continue;

		fi = (struct ps4_file_info) {
			.name = filename,
			.size = ipkg->script[i].len,
			.mode = 0755 | S_IFREG,
			.mtime = pkg->build_time,
		};
		/* The scripts db expects file names in format:
		 * pkg-version.<hexdump of package checksum>.action */
		bfn = PS4_BLOB_BUF(filename);
		ps4_blob_push_blob(&bfn, PS4_BLOB_STR(pkg->name->name));
		ps4_blob_push_blob(&bfn, PS4_BLOB_STR("-"));
		ps4_blob_push_blob(&bfn, *pkg->version);
		ps4_blob_push_blob(&bfn, PS4_BLOB_STR("."));
		ps4_blob_push_hash_hex(&bfn, ps4_pkg_hash_blob(pkg));
		ps4_blob_push_blob(&bfn, PS4_BLOB_STR("."));
		ps4_blob_push_blob(&bfn, PS4_BLOB_STR(ps4_script_types[i]));
		ps4_blob_push_blob(&bfn, PS4_BLOB_PTR_LEN("", 1));

		r = ps4_tar_write_entry(os, &fi, ipkg->script[i].ptr);
		if (r < 0) {
			ps4_ostream_cancel(os, -PS4E_V2DB_FORMAT);
			break;
		}
	}

	return r;
}

static int ps4_read_script_archive_entry(void *ctx,
					 const struct ps4_file_info *ae,
					 struct ps4_istream *is)
{
	struct ps4_database *db = (struct ps4_database *) ctx;
	struct ps4_package *pkg;
	char *fncsum, *fnaction;
	struct ps4_digest digest;
	ps4_blob_t blob;
	int type;

	if (!S_ISREG(ae->mode))
		return 0;

	/* The scripts db expects file names in format:
	 * pkgname-version.<hexdump of package checksum>.action */
	fnaction = memrchr(ae->name, '.', strlen(ae->name));
	if (fnaction == NULL || fnaction == ae->name)
		return 0;
	fncsum = memrchr(ae->name, '.', fnaction - ae->name - 1);
	if (fncsum == NULL)
		return 0;
	fnaction++;
	fncsum++;

	/* Parse it */
	type = ps4_script_type(fnaction);
	if (type == PS4_SCRIPT_INVALID)
		return 0;
	blob = PS4_BLOB_PTR_PTR(fncsum, fnaction - 2);
	ps4_blob_pull_digest(&blob, &digest);

	/* Attach script */
	pkg = ps4_db_get_pkg(db, &digest);
	if (pkg != NULL && pkg->ipkg != NULL)
		ps4_ipkg_add_script(pkg->ipkg, is, type, ae->size);

	return 0;
}

static int parse_triggers(void *ctx, ps4_blob_t blob)
{
	struct ps4_installed_package *ipkg = ctx;

	if (blob.len == 0) return 0;
	ps4_string_array_add(&ipkg->triggers, ps4_blob_cstr(blob));
	return 0;
}

static int ps4_db_triggers_write(struct ps4_database *db, struct ps4_installed_package *ipkg, struct ps4_ostream *os)
{
	char buf[PS4_BLOB_DIGEST_BUF];
	ps4_blob_t bfn;
	char **trigger;

	if (IS_ERR(os)) return PTR_ERR(os);
	if (ps4_array_len(ipkg->triggers) == 0) return 0;

	bfn = PS4_BLOB_BUF(buf);
	ps4_blob_push_hash(&bfn, ps4_pkg_hash_blob(ipkg->pkg));
	bfn = ps4_blob_pushed(PS4_BLOB_BUF(buf), bfn);
	ps4_ostream_write(os, bfn.ptr, bfn.len);

	foreach_array_item(trigger, ipkg->triggers) {
		ps4_ostream_write(os, " ", 1);
		ps4_ostream_write_string(os, *trigger);
	}
	ps4_ostream_write(os, "\n", 1);
	return 0;
}

static int ps4_db_triggers_read(struct ps4_database *db, struct ps4_istream *is)
{
	struct ps4_digest digest;
	struct ps4_package *pkg;
	struct ps4_installed_package *ipkg;
	ps4_blob_t l;

	if (IS_ERR(is)) return PTR_ERR(is);

	while (ps4_istream_get_delim(is, PS4_BLOB_STR("\n"), &l) == 0) {
		ps4_blob_pull_digest(&l, &digest);
		ps4_blob_pull_char(&l, ' ');

		pkg = ps4_db_get_pkg(db, &digest);
		if (pkg == NULL || pkg->ipkg == NULL)
			continue;

		ipkg = pkg->ipkg;
		ps4_blob_for_each_segment(l, " ", parse_triggers, ipkg);
		if (ps4_array_len(ipkg->triggers) != 0 &&
		    !list_hashed(&ipkg->trigger_pkgs_list))
			list_add_tail(&ipkg->trigger_pkgs_list,
				      &db->installed.triggers);
	}
	return ps4_istream_close(is);
}

static int ps4_db_read_layer(struct ps4_database *db, unsigned layer)
{
	ps4_blob_t blob, world;
	int r, fd, ret = 0, flags = db->ctx->open_flags;

	/* Read:
	 * 1. world
	 * 2. installed packages db
	 * 3. triggers db
	 * 4. scripts db
	 */

	fd = openat(db->root_fd, ps4_db_layer_name(layer), O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;

	if (!(flags & PS4_OPENF_NO_WORLD)) {
		if (layer == PS4_DB_LAYER_ROOT)
			ret = ps4_blob_from_file(db->root_fd, ps4_world_file, &world);
		else
			ret = ps4_blob_from_file(fd, "world", &world);

		if (!ret) {
			blob = ps4_blob_trim(world);
			ret = ps4_blob_pull_deps(&blob, db, &db->world);
			free(world.ptr);
		} else if (layer == PS4_DB_LAYER_ROOT) {
			ret = -ENOENT;
		}
	}

	if (!(flags & PS4_OPENF_NO_INSTALLED)) {
		r = ps4_db_fdb_read(db, ps4_istream_from_file(fd, "installed"), -1, layer);
		if (!ret && r != -ENOENT) ret = r;
		r = ps4_db_triggers_read(db, ps4_istream_from_file(fd, "triggers"));
		if (!ret && r != -ENOENT) ret = r;
	}

	if (!(flags & PS4_OPENF_NO_SCRIPTS)) {
		r = ps4_tar_parse(ps4_istream_from_file(fd, "scripts.tar"),
				  ps4_read_script_archive_entry, db, db->id_cache);
		if (!ret && r != -ENOENT) ret = r;
	}

	close(fd);
	return ret;
}

static int ps4_db_index_write_nr_cache(struct ps4_database *db)
{
	struct ps4_package_array *pkgs;
	struct ps4_package **ppkg;
	struct ps4_ostream *os;

	if (!ps4_db_cache_active(db)) return 0;

	/* Write list of installed non-repository packages to
	 * cached index file */
	os = ps4_ostream_to_file(db->cache_fd, "installed", 0644);
	if (IS_ERR(os)) return PTR_ERR(os);

	pkgs = ps4_db_sorted_installed_packages(db);
	foreach_array_item(ppkg, pkgs) {
		struct ps4_package *pkg = *ppkg;
		if ((pkg->repos == BIT(PS4_REPOSITORY_CACHED) ||
		     (pkg->repos == 0 && !pkg->installed_size))) {
			if (ps4_pkg_write_index_entry(pkg, os) < 0) break;
		}
	}
	return ps4_ostream_close(os);
}

static int add_protected_path(void *ctx, ps4_blob_t blob)
{
	struct ps4_database *db = (struct ps4_database *) ctx;
	int protect_mode = PS4_PROTECT_NONE;

	/* skip empty lines and comments */
	if (blob.len == 0)
		return 0;

	switch (blob.ptr[0]) {
	case '#':
		return 0;
	case '-':
		protect_mode = PS4_PROTECT_IGNORE;
		break;
	case '+':
		protect_mode = PS4_PROTECT_CHANGED;
		break;
	case '@':
		protect_mode = PS4_PROTECT_SYMLINKS_ONLY;
		break;
	case '!':
		protect_mode = PS4_PROTECT_ALL;
		break;
	default:
		protect_mode = PS4_PROTECT_CHANGED;
		goto no_mode_char;
	}
	blob.ptr++;
	blob.len--;

no_mode_char:
	/* skip leading and trailing path separators */
	while (blob.len && blob.ptr[0] == '/')
		blob.ptr++, blob.len--;
	while (blob.len && blob.ptr[blob.len-1] == '/')
		blob.len--;

	ps4_protected_path_array_add(&db->protected_paths, (struct ps4_protected_path) {
		.relative_pattern = ps4_blob_cstr(blob),
		.protect_mode = protect_mode,
	});
	return 0;
}

static int file_ends_with_dot_list(const char *file)
{
	const char *ext = strrchr(file, '.');
	if (ext == NULL || strcmp(ext, ".list") != 0)
		return FALSE;
	return TRUE;
}

static int add_protected_paths_from_istream(struct ps4_database *db, struct ps4_istream *is)
{
	ps4_blob_t token = PS4_BLOB_STRLIT("\n"), line;
	if (IS_ERR(is)) return PTR_ERR(is);
	while (ps4_istream_get_delim(is, token, &line) == 0)
		add_protected_path(db, line);
	return ps4_istream_close(is);
}

static int add_protected_paths_from_file(void *ctx, int dirfd, const char *file)
{
	struct ps4_database *db = (struct ps4_database *) ctx;

	if (!file_ends_with_dot_list(file)) return 0;
	add_protected_paths_from_istream(db, ps4_istream_from_file(dirfd, file));
	return 0;
}

static void handle_alarm(int sig)
{
}

static void mark_in_cache(struct ps4_database *db, int static_cache, int dirfd, const char *name, struct ps4_package *pkg)
{
	if (pkg == NULL)
		return;

	pkg->repos |= BIT(PS4_REPOSITORY_CACHED);
}

static int add_repos_from_file(void *ctx, int dirfd, const char *file)
{
	struct ps4_database *db = (struct ps4_database *) ctx;
	struct ps4_out *out = &db->ctx->out;
	ps4_blob_t blob;

	if (dirfd != AT_FDCWD && dirfd != db->root_fd) {
		/* loading from repositories.d; check extension */
		if (!file_ends_with_dot_list(file))
			return 0;
	}

	if (ps4_blob_from_file(dirfd, file, &blob)) {
		if (dirfd != AT_FDCWD) return 0;
		ps4_err(out, "failed to read repositories: %s", file);
		ps4_notice(out, "NOTE: --repositories-file is relative to the startup directory since ps4 1.0.0_ps4");
		return -ENOENT;
	}

	ps4_blob_for_each_segment(blob, "\n", ps4_db_add_repository, db);
	free(blob.ptr);

	return 0;
}

static void ps4_db_setup_repositories(struct ps4_database *db, const char *cache_dir)
{
	/* This is the SHA-1 of the string 'cache'. Repo hashes like this
	 * are truncated to PS4_CACHE_CSUM_BYTES and always use SHA-1. */
	db->repos[PS4_REPOSITORY_CACHED] = (struct ps4_repository) {
		.url = cache_dir,
		.hash.data = {
			0xb0,0x35,0x92,0x80,0x6e,0xfa,0xbf,0xee,0xb7,0x09,
			0xf5,0xa7,0x0a,0x7c,0x17,0x26,0x69,0xb0,0x05,0x38 },
		.hash.len = PS4_DIGEST_LENGTH_SHA1,
		.hash.alg = PS4_DIGEST_SHA1,
	};

	db->num_repos = PS4_REPOSITORY_FIRST_CONFIGURED;
	db->local_repos |= BIT(PS4_REPOSITORY_CACHED);
	db->available_repos |= BIT(PS4_REPOSITORY_CACHED);

	db->num_repo_tags = 1;
}

static int ps4_db_name_rdepends(ps4_hash_item item, void *pctx)
{
	struct ps4_name *name = item, *rname;
	struct ps4_provider *p;
	struct ps4_dependency *dep;
	struct ps4_name *touched[128];
	unsigned num_touched = 0;

	foreach_array_item(p, name->providers) {
		foreach_array_item(dep, p->pkg->depends) {
			rname = dep->name;
			rname->is_dependency |= !ps4_dep_conflict(dep);
			if (!(rname->state_int & 1)) {
				if (!rname->state_int) {
					if (num_touched < ARRAY_SIZE(touched))
						touched[num_touched] = rname;
					num_touched++;
				}
				rname->state_int |= 1;
				ps4_name_array_add(&rname->rdepends, name);
			}
		}
		foreach_array_item(dep, p->pkg->install_if) {
			rname = dep->name;
			if (!(rname->state_int & 2)) {
				if (!rname->state_int) {
					if (num_touched < ARRAY_SIZE(touched))
						touched[num_touched] = rname;
					num_touched++;
				}
				rname->state_int |= 2;
				ps4_name_array_add(&rname->rinstall_if, name);
			}
		}
	}

	if (num_touched > ARRAY_SIZE(touched)) {
		foreach_array_item(p, name->providers) {
			foreach_array_item(dep, p->pkg->depends)
				dep->name->state_int = 0;
			foreach_array_item(dep, p->pkg->install_if)
				dep->name->state_int = 0;
		}
	} else for (unsigned i = 0; i < num_touched; i++)
		touched[i]->state_int = 0;

	return 0;
}

static inline int setup_static_cache(struct ps4_database *db, struct ps4_ctx *ac)
{
	db->cache_dir = ps4_static_cache_dir;
	db->cache_fd = openat(db->root_fd, db->cache_dir, O_RDONLY | O_CLOEXEC);
	if (db->cache_fd < 0) {
		ps4_make_dirs(db->root_fd, db->cache_dir, 0755, 0755);
		db->cache_fd = openat(db->root_fd, db->cache_dir, O_RDONLY | O_CLOEXEC);
		if (db->cache_fd < 0) {
			if (ac->open_flags & PS4_OPENF_WRITE) return -EROFS;
			db->cache_fd = -PS4E_CACHE_NOT_AVAILABLE;
		}
	}

	return 0;
}

#ifdef __linux__
static int detect_tmpfs_root(struct ps4_database *db)
{
	struct statfs stfs;

	return fstatfs(db->root_fd, &stfs) == 0 && stfs.f_type == TMPFS_MAGIC;
}

static unsigned long map_statfs_flags(unsigned long f_flag)
{
	unsigned long mnt_flags = 0;
	if (f_flag & ST_RDONLY) mnt_flags |= MS_RDONLY;
	if (f_flag & ST_NOSUID) mnt_flags |= MS_NOSUID;
	if (f_flag & ST_NODEV)  mnt_flags |= MS_NODEV;
	if (f_flag & ST_NOEXEC) mnt_flags |= MS_NOEXEC;
	if (f_flag & ST_NOATIME) mnt_flags |= MS_NOATIME;
	if (f_flag & ST_NODIRATIME)mnt_flags |= MS_NODIRATIME;
#ifdef ST_RELATIME
	if (f_flag & ST_RELATIME) mnt_flags |= MS_RELATIME;
#endif
	if (f_flag & ST_SYNCHRONOUS) mnt_flags |= MS_SYNCHRONOUS;
	if (f_flag & ST_MANDLOCK) mnt_flags |= ST_MANDLOCK;
	return mnt_flags;
}

static char *find_mountpoint(int atfd, const char *rel_path)
{
	struct mntent *me;
	struct stat st;
	FILE *f;
	char *ret = NULL;
	dev_t dev;

	if (fstatat(atfd, rel_path, &st, 0) != 0)
		return NULL;
	dev = st.st_dev;

	f = setmntent("/proc/mounts", "r");
	if (f == NULL)
		return NULL;
	while ((me = getmntent(f)) != NULL) {
		if (strcmp(me->mnt_fsname, "rootfs") == 0)
			continue;
		if (fstatat(atfd, me->mnt_dir, &st, 0) == 0 &&
		    st.st_dev == dev) {
			ret = strdup(me->mnt_dir);
			break;
		}
	}
	endmntent(f);

	return ret;
}

static int setup_cache(struct ps4_database *db, struct ps4_ctx *ac)
{
	struct ps4_out *out = &ac->out;
	int fd;
	struct statfs stfs;

	fd = openat(db->root_fd, ac->cache_dir, O_RDONLY | O_CLOEXEC);
	if (fd >= 0 && fstatfs(fd, &stfs) == 0) {
		db->cache_dir = ac->cache_dir;
		db->cache_fd = fd;
		db->cache_remount_flags = map_statfs_flags(stfs.f_flags);
		if ((ac->open_flags & (PS4_OPENF_WRITE | PS4_OPENF_CACHE_WRITE)) &&
		    (db->cache_remount_flags & MS_RDONLY) != 0) {
			/* remount cache read/write */
			db->cache_remount_dir = find_mountpoint(db->root_fd, db->cache_dir);
			if (db->cache_remount_dir == NULL) {
				ps4_warn(out, "Unable to find cache directory mount point");
			} else if (mount(0, db->cache_remount_dir, 0, MS_REMOUNT | (db->cache_remount_flags & ~MS_RDONLY), 0) != 0) {
				free(db->cache_remount_dir);
				db->cache_remount_dir = NULL;
				return -EROFS;
			}
		}
	} else {
		if (fd >= 0) close(fd);
		if (setup_static_cache(db, ac) < 0) return -EROFS;
	}

	return 0;
}

static void remount_cache(struct ps4_database *db)
{
	if (db->cache_remount_dir) {
		mount(0, db->cache_remount_dir, 0, MS_REMOUNT | db->cache_remount_flags, 0);
		free(db->cache_remount_dir);
		db->cache_remount_dir = NULL;
	}
}

static int mount_proc(struct ps4_database *db)
{
	struct statfs stfs;

	/* mount /proc */
	if (asprintf(&db->root_proc_dir, "%s/proc", db->ctx->root) == -1)
		return -1;
	if (statfs(db->root_proc_dir, &stfs) != 0) {
		if (errno == ENOENT) mkdir(db->root_proc_dir, 0555);
		stfs.f_type = 0;
	}
	if (stfs.f_type != PROC_SUPER_MAGIC) {
		mount("proc", db->root_proc_dir, "proc", 0, 0);
	} else {
		/* was already mounted. prevent umount on close */
		free(db->root_proc_dir);
		db->root_proc_dir = NULL;
	}

	return 0;
}

static void unmount_proc(struct ps4_database *db)
{
	if (db->root_proc_dir) {
		umount2(db->root_proc_dir, MNT_DETACH|UMOUNT_NOFOLLOW);
		free(db->root_proc_dir);
		db->root_proc_dir = NULL;
	}
}
#else
static int detect_tmpfs_root(struct ps4_database *db)
{
	(void) db;
	return 0;
}

static int setup_cache(struct ps4_database *db, struct ps4_ctx *ac)
{
	return setup_static_cache(db, ac);
}

static void remount_cache(struct ps4_database *db)
{
	(void) db;
}

static int mount_proc(struct ps4_database *db)
{
	(void) db;
	return 0;
}

static void unmount_proc(struct ps4_database *db)
{
	(void) db;
}
#endif

const char *ps4_db_layer_name(int layer)
{
	switch (layer) {
	case PS4_DB_LAYER_ROOT: return "lib/ps4/db";
	case PS4_DB_LAYER_UVOL: return "lib/ps4/db-uvol";
	default:
		assert(!"invalid layer");
		return 0;
	}
}

#ifdef PS4_UVOL_DB_TARGET
static void setup_uvol_target(struct ps4_database *db)
{
	const struct ps4_ctx *ac = db->ctx;
	const char *uvol_db = ps4_db_layer_name(PS4_DB_LAYER_UVOL);
	const char *uvol_target = PS4_UVOL_DB_TARGET;
	const char *uvol_symlink_target = "../../" PS4_UVOL_DB_TARGET;

	if (!(ac->open_flags & (PS4_OPENF_WRITE|PS4_OPENF_CREATE))) return;
	if (IS_ERR(ac->uvol)) return;
	if (faccessat(db->root_fd, uvol_db, F_OK, 0) == 0) return;
	if (faccessat(db->root_fd, uvol_target, F_OK, 0) != 0) return;

	// Create symlink from uvol_db to uvol_target in relative form
	symlinkat(uvol_symlink_target, db->root_fd, uvol_db);
}
#else
static void setup_uvol_target(struct ps4_database *db) { }
#endif

void ps4_db_init(struct ps4_database *db)
{
	memset(db, 0, sizeof(*db));
	ps4_balloc_init(&db->ba_names, (sizeof(struct ps4_name) + 16) * 256);
	ps4_balloc_init(&db->ba_pkgs, sizeof(struct ps4_package) * 256);
	ps4_balloc_init(&db->ba_deps, sizeof(struct ps4_dependency) * 256);
	ps4_balloc_init(&db->ba_files, (sizeof(struct ps4_db_file) + 32) * 256);
	ps4_hash_init(&db->available.names, &pkg_name_hash_ops, 20000);
	ps4_hash_init(&db->available.packages, &pkg_info_hash_ops, 10000);
	ps4_hash_init(&db->installed.dirs, &dir_hash_ops, 20000);
	ps4_hash_init(&db->installed.files, &file_hash_ops, 200000);
	ps4_atom_init(&db->atoms);
	ps4_dependency_array_init(&db->world);
	ps4_pkgtmpl_init(&db->overlay_tmpl);
	list_init(&db->installed.packages);
	list_init(&db->installed.triggers);
	ps4_protected_path_array_init(&db->protected_paths);
	ps4_string_array_init(&db->filename_array);
	ps4_name_array_init(&db->available.sorted_names);
	ps4_package_array_init(&db->installed.sorted_packages);
	db->permanent = 1;
	db->root_fd = -1;
}

int ps4_db_open(struct ps4_database *db, struct ps4_ctx *ac)
{
	struct ps4_out *out = &ac->out;
	const char *msg = NULL;
	ps4_blob_t blob;
	int r = -1, i;

	ps4_default_acl_dir = ps4_db_acl_atomize(db, 0755, 0, 0);
	ps4_default_acl_file = ps4_db_acl_atomize(db, 0644, 0, 0);

	db->ctx = ac;
	if (ac->open_flags == 0) {
		msg = "Invalid open flags (internal error)";
		goto ret_r;
	}
	if ((ac->open_flags & PS4_OPENF_WRITE) &&
	    !(ac->open_flags & PS4_OPENF_NO_AUTOUPDATE) &&
	    !(ac->flags & PS4_NO_NETWORK))
		db->autoupdate = 1;

	ps4_db_setup_repositories(db, ac->cache_dir);
	db->root_fd = ps4_ctx_fd_root(ac);
	db->cache_fd = -PS4E_CACHE_NOT_AVAILABLE;
	db->permanent = !detect_tmpfs_root(db);
	db->usermode = !!(ac->open_flags & PS4_OPENF_USERMODE);

	if (!(ac->open_flags & PS4_OPENF_CREATE)) {
		// Autodetect usermode from the installeddb owner
		struct stat st;
		if (fstatat(db->root_fd, ps4_db_layer_name(PS4_DB_LAYER_ROOT), &st, 0) == 0 &&
		    st.st_uid != 0)
			db->usermode = 1;
	}
	if (db->usermode) db->extract_flags |= PS4_FSEXTRACTF_NO_CHOWN | PS4_FSEXTRACTF_NO_SYS_XATTRS;

	setup_uvol_target(db);

	if (ac->arch && (ac->root_set || (ac->open_flags & PS4_OPENF_ALLOW_ARCH))) {
		db->arch = ps4_atomize(&db->atoms, PS4_BLOB_STR(ac->arch));
		db->write_arch = ac->root_set;
	} else {
		ps4_blob_t arch;
		if (!ps4_blob_from_file(db->root_fd, ps4_arch_file, &arch)) {
			db->arch = ps4_atomize_dup(&db->atoms, ps4_blob_trim(arch));
			free(arch.ptr);
		} else {
			db->arch = ps4_atomize(&db->atoms, PS4_BLOB_STR(PS4_DEFAULT_ARCH));
			db->write_arch = 1;
		}
	}

	db->id_cache = ps4_ctx_get_id_cache(ac);

	if (ac->open_flags & PS4_OPENF_WRITE) {
		msg = "Unable to lock database";
		db->lock_fd = openat(db->root_fd, ps4_lock_file,
				     O_CREAT | O_RDWR | O_CLOEXEC, 0600);
		if (db->lock_fd < 0) {
			if (!(ac->open_flags & PS4_OPENF_CREATE))
				goto ret_errno;
		} else if (flock(db->lock_fd, LOCK_EX | LOCK_NB) < 0) {
			struct sigaction sa, old_sa;

			if (!ac->lock_wait) goto ret_errno;

			ps4_notice(out, "Waiting for repository lock");
			memset(&sa, 0, sizeof sa);
			sa.sa_handler = handle_alarm;
			sa.sa_flags   = SA_RESETHAND;
			sigaction(SIGALRM, &sa, &old_sa);

			alarm(ac->lock_wait);
			if (flock(db->lock_fd, LOCK_EX) < 0)
				goto ret_errno;

			alarm(0);
			sigaction(SIGALRM, &old_sa, NULL);
		}

		if (mount_proc(db) < 0)
			goto ret_errno;
	}

	if (ac->protected_paths) {
		add_protected_paths_from_istream(db, ac->protected_paths);
		ac->protected_paths = NULL;
	} else {
		blob = PS4_BLOB_STR("+etc\n" "@etc/init.d\n" "!etc/ps4\n");
		ps4_blob_for_each_segment(blob, "\n", add_protected_path, db);

		ps4_dir_foreach_file(openat(db->root_fd, "etc/ps4/protected_paths.d", O_RDONLY | O_CLOEXEC),
				     add_protected_paths_from_file, db);
	}

	/* figure out where to have the cache */
	if (!(db->ctx->flags & PS4_NO_CACHE)) {
		if ((r = setup_cache(db, ac)) < 0) {
			ps4_err(out, "Unable to setup the cache");
			goto ret_r;
		}
	}

	if (db->ctx->flags & PS4_OVERLAY_FROM_STDIN) {
		db->ctx->flags &= ~PS4_OVERLAY_FROM_STDIN;
		ps4_db_read_overlay(db, ps4_istream_from_fd(STDIN_FILENO));
	}

	if ((db->ctx->open_flags & PS4_OPENF_NO_STATE) != PS4_OPENF_NO_STATE) {
		for (i = 0; i < PS4_DB_LAYER_NUM; i++) {
			r = ps4_db_read_layer(db, i);
			if (r) {
				if (i != PS4_DB_LAYER_ROOT) continue;
				if (!(r == -ENOENT && (ac->open_flags & PS4_OPENF_CREATE))) {
					msg = "Unable to read database";
					goto ret_r;
				}
			}
			db->active_layers |= BIT(i);
		}
	}

	if (!(ac->open_flags & PS4_OPENF_NO_INSTALLED_REPO)) {
		if (ps4_db_cache_active(db)) {
			ps4_db_index_read(db, ps4_istream_from_file(db->cache_fd, "installed"), -2);
		}
	}

	if (!(ac->open_flags & PS4_OPENF_NO_CMDLINE_REPOS)) {
		char **repo;
		foreach_array_item(repo, ac->repository_list)
			ps4_db_add_repository(db, PS4_BLOB_STR(*repo));
	}

	if (!(ac->open_flags & PS4_OPENF_NO_SYS_REPOS)) {
		if (ac->repositories_file == NULL) {
			add_repos_from_file(db, db->root_fd, "etc/ps4/repositories");
			ps4_dir_foreach_file(openat(db->root_fd, "etc/ps4/repositories.d", O_RDONLY | O_CLOEXEC),
					     add_repos_from_file, db);
		} else {
			add_repos_from_file(db, AT_FDCWD, ac->repositories_file);
		}

		if (db->repositories.updated > 0)
			ps4_db_index_write_nr_cache(db);
	}

	ps4_hash_foreach(&db->available.names, ps4_db_name_rdepends, db);

	if (ps4_db_cache_active(db) && (ac->open_flags & (PS4_OPENF_NO_REPOS|PS4_OPENF_NO_INSTALLED)) == 0)
		ps4_db_cache_foreach_item(db, mark_in_cache, 0);

	db->open_complete = 1;

	if (db->compat_newfeatures) {
		ps4_warn(out,
			"This ps4-tools is OLD! Some packages %s.",
			db->compat_notinstallable ? "are not installable" : "might not function properly");
	}
	if (db->compat_depversions) {
		ps4_warn(out,
			"The indexes contain broken packages which %s.",
			db->compat_notinstallable ? "are not installable" : "might not function properly");
	}

	ac->db = db;
	return 0;

ret_errno:
	r = -errno;
ret_r:
	if (msg != NULL)
		ps4_err(out, "%s: %s", msg, ps4_error_str(-r));
	ps4_db_close(db);

	return r;
}

struct write_ctx {
	struct ps4_database *db;
	int fd;
};

static int ps4_db_write_layers(struct ps4_database *db)
{
	struct layer_data {
		int fd;
		struct ps4_ostream *installed, *scripts, *triggers;
	} layers[PS4_DB_LAYER_NUM] = {0};
	struct ps4_ostream *os;
	struct ps4_package **ppkg;
	struct ps4_package_array *pkgs;
	int i, r, rr = 0;

	for (i = 0; i < PS4_DB_LAYER_NUM; i++) {
		struct layer_data *ld = &layers[i];
		if (!(db->active_layers & BIT(i))) continue;

		ld->fd = openat(db->root_fd, ps4_db_layer_name(i), O_RDONLY | O_CLOEXEC);
		if (ld->fd < 0) {
			if (i == 0) return -errno;
			continue;
		}
		ld->installed = ps4_ostream_to_file(ld->fd, "installed", 0644);
		ld->scripts   = ps4_ostream_to_file(ld->fd, "scripts.tar", 0644);
		ld->triggers  = ps4_ostream_to_file(ld->fd, "triggers", 0644);

		if (i == 0)
			os = ps4_ostream_to_file(db->root_fd, ps4_world_file, 0644);
		else
			os = ps4_ostream_to_file(ld->fd, "world", 0644);
		if (IS_ERR(os)) {
			if (!rr) rr = PTR_ERR(os);
			continue;
		}
		ps4_deps_write_layer(db, db->world, os, PS4_BLOB_PTR_LEN("\n", 1), i);
		ps4_ostream_write(os, "\n", 1);
		r = ps4_ostream_close(os);
		if (!rr) rr = r;
	}

	pkgs = ps4_db_sorted_installed_packages(db);
	foreach_array_item(ppkg, pkgs) {
		struct ps4_package *pkg = *ppkg;
		struct layer_data *ld = &layers[pkg->layer];
		if (!ld->fd) continue;
		ps4_db_fdb_write(db, pkg->ipkg, ld->installed);
		ps4_db_scriptdb_write(db, pkg->ipkg, ld->scripts);
		ps4_db_triggers_write(db, pkg->ipkg, ld->triggers);
	}

	for (i = 0; i < PS4_DB_LAYER_NUM; i++) {
		struct layer_data *ld = &layers[i];
		if (!(db->active_layers & BIT(i))) continue;

		if (!IS_ERR(ld->installed))
			r = ps4_ostream_close(ld->installed);
		else	r = PTR_ERR(ld->installed);
		if (!rr) rr = r;

		if (!IS_ERR(ld->scripts)) {
			ps4_tar_write_entry(ld->scripts, NULL, NULL);
			r = ps4_ostream_close(ld->scripts);
		} else	r = PTR_ERR(ld->scripts);
		if (!rr) rr = r;

		if (!IS_ERR(ld->triggers))
			r = ps4_ostream_close(ld->triggers);
		else	r = PTR_ERR(ld->triggers);
		if (!rr) rr = r;

		close(ld->fd);
	}
	return rr;
}

int ps4_db_write_config(struct ps4_database *db)
{
	struct ps4_out *out = &db->ctx->out;
	int r, rr = 0;

	if ((db->ctx->flags & PS4_SIMULATE) || db->ctx->root == NULL)
		return 0;

	if (db->ctx->open_flags & PS4_OPENF_CREATE) {
		ps4_make_dirs(db->root_fd, "lib/ps4/db", 0755, 0755);
		ps4_make_dirs(db->root_fd, "etc/ps4", 0755, 0755);
	} else if (db->lock_fd == 0) {
		ps4_err(out, "Refusing to write db without write lock!");
		return -1;
	}

	if (db->write_arch)
		ps4_blob_to_file(db->root_fd, ps4_arch_file, *db->arch, PS4_BTF_ADD_EOL);

	r = ps4_db_write_layers(db);
	if (!rr ) rr = r;

	r = ps4_db_index_write_nr_cache(db);
	if (r < 0 && !rr) rr = r;

	if (rr) {
		ps4_err(out, "System state may be inconsistent: failed to write database: %s",
			ps4_error_str(rr));
	}
	return rr;
}

void ps4_db_close(struct ps4_database *db)
{
	struct ps4_installed_package *ipkg, *ipkgn;
	struct ps4_db_dir_instance *diri;
	struct ps4_protected_path *ppath;
	struct hlist_node *dc, *dn;
	int i;

	/* Cleaning up the directory tree will cause mode, uid and gid
	 * of all modified (package providing that directory got removed)
	 * directories to be reset. */
	list_for_each_entry_safe(ipkg, ipkgn, &db->installed.packages, installed_pkgs_list) {
		hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
			ps4_db_diri_free(db, diri, PS4_DIR_FREE);
		}
		ps4_pkg_uninstall(NULL, ipkg->pkg);
	}

	for (i = PS4_REPOSITORY_FIRST_CONFIGURED; i < db->num_repos; i++) {
		free((void*) db->repos[i].url);
		free(db->repos[i].description.ptr);
	}
	foreach_array_item(ppath, db->protected_paths)
		free(ppath->relative_pattern);
	ps4_protected_path_array_free(&db->protected_paths);

	ps4_string_array_free(&db->filename_array);
	ps4_pkgtmpl_free(&db->overlay_tmpl);
	ps4_dependency_array_free(&db->world);
	ps4_name_array_free(&db->available.sorted_names);
	ps4_package_array_free(&db->installed.sorted_packages);
	ps4_hash_free(&db->available.packages);
	ps4_hash_free(&db->available.names);
	ps4_hash_free(&db->installed.files);
	ps4_hash_free(&db->installed.dirs);
	ps4_atom_free(&db->atoms);
	ps4_balloc_destroy(&db->ba_names);
	ps4_balloc_destroy(&db->ba_pkgs);
	ps4_balloc_destroy(&db->ba_files);
	ps4_balloc_destroy(&db->ba_deps);

	unmount_proc(db);
	remount_cache(db);

	if (db->cache_fd > 0) close(db->cache_fd);
	if (db->lock_fd > 0) close(db->lock_fd);
}

int ps4_db_get_tag_id(struct ps4_database *db, ps4_blob_t tag)
{
	int i;

	if (ps4_BLOB_IS_NULL(tag))
		return PS4_DEFAULT_REPOSITORY_TAG;

	if (tag.ptr[0] == '@') {
		for (i = 1; i < db->num_repo_tags; i++)
			if (ps4_blob_compare(db->repo_tags[i].tag, tag) == 0)
				return i;
	} else {
		for (i = 1; i < db->num_repo_tags; i++)
			if (ps4_blob_compare(db->repo_tags[i].plain_name, tag) == 0)
				return i;
	}
	if (i >= ARRAY_SIZE(db->repo_tags))
		return -1;

	db->num_repo_tags++;

	if (tag.ptr[0] == '@') {
		db->repo_tags[i].tag = *ps4_atomize_dup(&db->atoms, tag);
	} else {
		char *tmp = alloca(tag.len + 1);
		tmp[0] = '@';
		memcpy(&tmp[1], tag.ptr, tag.len);
		db->repo_tags[i].tag = *ps4_atomize_dup(&db->atoms, PS4_BLOB_PTR_LEN(tmp, tag.len+1));
	}

	db->repo_tags[i].plain_name = db->repo_tags[i].tag;
	ps4_blob_pull_char(&db->repo_tags[i].plain_name, '@');

	return i;
}

static int fire_triggers(ps4_hash_item item, void *ctx)
{
	struct ps4_database *db = (struct ps4_database *) ctx;
	struct ps4_db_dir *dbd = (struct ps4_db_dir *) item;
	struct ps4_installed_package *ipkg;
	char **triggerptr, *trigger;

	list_for_each_entry(ipkg, &db->installed.triggers, trigger_pkgs_list) {
		if (!ipkg->run_all_triggers && !dbd->modified) continue;
		foreach_array_item(triggerptr, ipkg->triggers) {
			trigger = *triggerptr;
			if (trigger[0] != '/') continue;
			if (fnmatch(trigger, dbd->rooted_name, FNM_PATHNAME) != 0) continue;

			/* And place holder for script name */
			if (ps4_array_len(ipkg->pending_triggers) == 0) {
				ps4_string_array_add(&ipkg->pending_triggers, NULL);
				db->pending_triggers++;
			}
			ps4_string_array_add(&ipkg->pending_triggers, dbd->rooted_name);
			break;
		}
	}
	return 0;
}

int ps4_db_fire_triggers(struct ps4_database *db)
{
	ps4_hash_foreach(&db->installed.dirs, fire_triggers, db);
	return db->pending_triggers;
}

int ps4_db_run_script(struct ps4_database *db, char *fn, char **argv)
{
	char buf[PS4_EXIT_STATUS_MAX_SIZE];
	struct ps4_out *out = &db->ctx->out;
	int status;
	pid_t pid;
	static char * const clean_environment[] = {
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		NULL
	};

	pid = fork();
	if (pid == -1) {
		ps4_err(out, "%s: fork: %s", ps4_last_path_segment(fn), strerror(errno));
		return -2;
	}
	if (pid == 0) {
		umask(0022);

		if (fchdir(db->root_fd) != 0) {
			ps4_err(out, "%s: fchdir: %s", ps4_last_path_segment(fn), strerror(errno));
			exit(127);
		}

		if (!(db->ctx->flags & PS4_NO_CHROOT) && chroot(".") != 0) {
			ps4_err(out, "%s: chroot: %s", ps4_last_path_segment(fn), strerror(errno));
			exit(127);
		}

		execve(fn, argv, (db->ctx->flags & PS4_PRESERVE_ENV) ? environ : clean_environment);
		exit(127); /* should not get here */
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	if (ps4_exit_status_str(status, buf, sizeof buf)) {
		ps4_err(out, "%s: script %s", ps4_last_path_segment(fn), buf);
		return -1;
	}
	return 0;
}

int ps4_db_cache_active(struct ps4_database *db)
{
	return db->cache_fd > 0 && db->cache_dir != ps4_static_cache_dir;
}

struct foreach_cache_item_ctx {
	struct ps4_database *db;
	ps4_cache_item_cb cb;
	int static_cache;
};

static int foreach_cache_file(void *pctx, int dirfd, const char *name)
{
	struct foreach_cache_item_ctx *ctx = (struct foreach_cache_item_ctx *) pctx;
	struct ps4_database *db = ctx->db;
	struct ps4_package *pkg = NULL;
	struct ps4_provider *p0;
	ps4_blob_t b = PS4_BLOB_STR(name), bname, bver;

	if (ps4_pkg_parse_name(b, &bname, &bver) == 0) {
		/* Package - search for it */
		struct ps4_name *name = ps4_db_get_name(db, bname);
		char tmp[PATH_MAX];
		if (name == NULL)
			goto no_pkg;

		foreach_array_item(p0, name->providers) {
			if (p0->pkg->name != name)
				continue;

			ps4_pkg_format_cache_pkg(PS4_BLOB_BUF(tmp), p0->pkg);
			if (ps4_blob_compare(b, PS4_BLOB_STR(tmp)) == 0) {
				pkg = p0->pkg;
				break;
			}
		}
	}
no_pkg:
	ctx->cb(db, ctx->static_cache, dirfd, name, pkg);

	return 0;
}

int ps4_db_cache_foreach_item(struct ps4_database *db, ps4_cache_item_cb cb, int static_cache)
{
	struct foreach_cache_item_ctx ctx = { db, cb, static_cache };

	if (static_cache) {
		struct stat st1, st2;
		int fd = openat(db->root_fd, ps4_static_cache_dir, O_RDONLY | O_CLOEXEC);
		if (fd < 0) return fd;
		/* Do not handle static cache as static cache if the explicit
		 * cache is enabled at the static cache location */
		if (fstat(fd, &st1) == 0 && fstat(db->cache_fd, &st2) == 0 &&
		    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
			close(fd);
			return 0;
		}
		return ps4_dir_foreach_file(fd, foreach_cache_file, &ctx);
	}
	if (db->cache_fd < 0) return db->cache_fd;
	return ps4_dir_foreach_file(dup(db->cache_fd), foreach_cache_file, &ctx);
}

int ps4_db_permanent(struct ps4_database *db)
{
	return db->permanent;
}

int ps4_db_check_world(struct ps4_database *db, struct ps4_dependency_array *world)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_dependency *dep;
	int bad = 0, tag;

	if (db->ctx->force & PS4_FORCE_BROKEN_WORLD)
		return 0;

	foreach_array_item(dep, world) {
		tag = dep->repository_tag;
		if (tag == 0 || db->repo_tags[tag].allowed_repos != 0)
			continue;
		if (tag < 0)
			tag = 0;
		ps4_warn(out, "The repository tag for world dependency '%s" BLOB_FMT "' does not exist",
			dep->name->name, BLOB_PRINTF(db->repo_tags[tag].tag));
		bad++;
	}

	return bad;
}

struct ps4_package *ps4_db_get_pkg(struct ps4_database *db,
				   struct ps4_digest *id)
{
	if (id->len < PS4_DIGEST_LENGTH_SHA1) return NULL;
	return ps4_hash_get(&db->available.packages, PS4_BLOB_PTR_LEN((char*)id->data, PS4_DIGEST_LENGTH_SHA1));
}

struct ps4_package *ps4_db_get_file_owner(struct ps4_database *db,
					  ps4_blob_t filename)
{
	struct ps4_db_file *dbf;
	struct ps4_db_file_hash_key key;

	if (filename.len && filename.ptr[0] == '/')
		filename.len--, filename.ptr++;

	if (!ps4_blob_rsplit(filename, '/', &key.dirname, &key.filename)) {
		key.dirname = PS4_BLOB_NULL;
		key.filename = filename;
	}

	dbf = (struct ps4_db_file *) ps4_hash_get(&db->installed.files,
						  PS4_BLOB_BUF(&key));
	if (dbf == NULL)
		return NULL;

	return dbf->diri->pkg;
}

unsigned int ps4_db_get_pinning_mask_repos(struct ps4_database *db, unsigned short pinning_mask)
{
	unsigned int repository_mask = 0;
	int i;

	for (i = 0; i < db->num_repo_tags && pinning_mask; i++) {
		if (!(BIT(i) & pinning_mask))
			continue;
		pinning_mask &= ~BIT(i);
		repository_mask |= db->repo_tags[i].allowed_repos;
	}
	return repository_mask;
}

struct ps4_repository *ps4_db_select_repo(struct ps4_database *db,
					  struct ps4_package *pkg)
{
	unsigned int repos;
	int i;

	/* Select repositories to use */
	repos = pkg->repos & db->available_repos;
	if (repos == 0)
		return NULL;

	if (repos & db->local_repos)
		repos &= db->local_repos;

	/* Pick first repository providing this package */
	for (i = PS4_REPOSITORY_FIRST_CONFIGURED; i < PS4_MAX_REPOS; i++) {
		if (repos & BIT(i))
			return &db->repos[i];
	}
	return &db->repos[PS4_REPOSITORY_CACHED];
}

struct ps4index_ctx {
	struct ps4_database *db;
	struct ps4_extract_ctx ectx;
	int repo, found;
};

static int load_v2index(struct ps4_extract_ctx *ectx, ps4_blob_t *desc, struct ps4_istream *is)
{
	struct ps4index_ctx *ctx = container_of(ectx, struct ps4index_ctx, ectx);
	struct ps4_repository *repo = &ctx->db->repos[ctx->repo];

	repo->description = *desc;
	*desc = PS4_BLOB_NULL;
	return ps4_db_index_read(ctx->db, is, ctx->repo);
}

static int load_v3index(struct ps4_extract_ctx *ectx, struct adb_obj *ndx)
{
	struct ps4index_ctx *ctx = container_of(ectx, struct ps4index_ctx, ectx);
	struct ps4_database *db = ctx->db;
	struct ps4_out *out = &db->ctx->out;
	struct ps4_repository *repo = &db->repos[ctx->repo];
	struct ps4_package_tmpl tmpl;
	struct adb_obj pkgs, pkginfo;
	int i, r = 0, num_broken = 0;

	ps4_pkgtmpl_init(&tmpl);

	repo->description = ps4_blob_dup(adb_ro_blob(ndx, ADBI_NDX_DESCRIPTION));
	adb_ro_obj(ndx, ADBI_NDX_PACKAGES, &pkgs);

	for (i = ADBI_FIRST; i <= adb_ra_num(&pkgs); i++) {
		adb_ro_obj(&pkgs, i, &pkginfo);
		ps4_pkgtmpl_from_adb(db, &tmpl, &pkginfo);
		if (tmpl.id.alg == PS4_DIGEST_NONE) {
			num_broken++;
			ps4_pkgtmpl_reset(&tmpl);
			continue;
		}

		tmpl.pkg.repos |= BIT(ctx->repo);
		if (!ps4_db_pkg_add(db, &tmpl)) {
			r = -PS4E_ADB_SCHEMA;
			break;
		}
	}

	ps4_pkgtmpl_free(&tmpl);
	if (num_broken) ps4_warn(out, "Repository %s has %d packages without hash", repo->url, num_broken);
	return r;
}

static const struct ps4_extract_ops extract_index = {
	.v2index = load_v2index,
	.v3index = load_v3index,
};

static int load_index(struct ps4_database *db, struct ps4_istream *is, int repo)
{
	struct ps4index_ctx ctx = {
		.db = db,
		.repo = repo,
	};
	if (IS_ERR(is)) return PTR_ERR(is);
	ps4_extract_init(&ctx.ectx, db->ctx, &extract_index);
	return ps4_extract(&ctx.ectx, is);
}

int ps4_db_index_read_file(struct ps4_database *db, const char *file, int repo)
{
	return load_index(db, ps4_istream_from_file(AT_FDCWD, file), repo);
}

int ps4_db_repository_check(struct ps4_database *db)
{
	if (db->ctx->force & PS4_FORCE_MISSING_REPOSITORIES) return 0;
	if (!db->repositories.stale && !db->repositories.unavailable) return 0;
	ps4_err(&db->ctx->out,
		"Not continuing due to stale/unavailable repositories."
		"Use --force-missing-repositories to continue.");
	return -1;
}

int ps4_db_add_repository(ps4_database_t _db, ps4_blob_t _repository)
{
	struct ps4_database *db = _db.db;
	struct ps4_out *out = &db->ctx->out;
	struct ps4_repository *repo;
	struct ps4_url_print urlp;
	ps4_blob_t brepo, btag;
	int repo_num, r, tag_id = 0, atfd = AT_FDCWD, update_error = 0;
	char buf[PATH_MAX], *url;
	const char *error_action = "constructing url";

	brepo = _repository;
	btag = PS4_BLOB_NULL;
	if (brepo.ptr == NULL || brepo.len == 0 || *brepo.ptr == '#')
		return 0;

	if (brepo.ptr[0] == '@') {
		ps4_blob_cspn(brepo, PS4_CTYPE_REPOSITORY_SEPARATOR, &btag, &brepo);
		ps4_blob_spn(brepo, PS4_CTYPE_REPOSITORY_SEPARATOR, NULL, &brepo);
		tag_id = ps4_db_get_tag_id(db, btag);
	}

	url = ps4_blob_cstr(brepo);
	for (repo_num = 0; repo_num < db->num_repos; repo_num++) {
		repo = &db->repos[repo_num];
		if (strcmp(url, repo->url) == 0) {
			db->repo_tags[tag_id].allowed_repos |=
				BIT(repo_num) & db->available_repos;
			free(url);
			return 0;
		}
	}
	if (db->num_repos >= PS4_MAX_REPOS) {
		free(url);
		return -1;
	}

	repo_num = db->num_repos++;
	repo = &db->repos[repo_num];
	*repo = (struct ps4_repository) {
		.url = url,
	};

	int is_remote = (ps4_url_local_file(repo->url) == NULL);

	r = ps4_repo_format_real_url(db->arch, repo, NULL, buf, sizeof(buf), &urlp);
	if (r != 0) goto err;

	error_action = "opening";
	ps4_digest_calc(&repo->hash, PS4_DIGEST_SHA256, buf, strlen(buf));

	if (is_remote) {
		if (!(db->ctx->flags & PS4_NO_NETWORK))
			db->available_repos |= BIT(repo_num);
		if (db->ctx->flags & PS4_NO_CACHE) {
			error_action = "fetching";
			ps4_notice(out, "fetch " URL_FMT, URL_PRINTF(urlp));
		} else {
			error_action = "opening from cache";
			if (db->autoupdate) {
				update_error = ps4_cache_download(db, repo, NULL, 1, NULL, NULL);
				switch (update_error) {
				case 0:
					db->repositories.updated++;
					break;
				case -EALREADY:
					update_error = 0;
					break;
				}
			}
			r = ps4_repo_format_cache_index(PS4_BLOB_BUF(buf), repo);
			if (r != 0) goto err;
			atfd = db->cache_fd;
		}
	} else {
		db->local_repos |= BIT(repo_num);
		db->available_repos |= BIT(repo_num);
	}
	r = load_index(db, ps4_istream_from_fd_url(atfd, buf, ps4_db_url_since(db, 0)), repo_num);

err:
	if (r || update_error) {
		if (is_remote) {
			if (r) db->repositories.unavailable++;
			else db->repositories.stale++;
		}
		ps4_url_parse(&urlp, repo->url);
		if (update_error)
			error_action = r ? "updating and opening" : "updating";
		else
			update_error = r;
		ps4_warn(out, "%s " URL_FMT ": %s", error_action, URL_PRINTF(urlp),
			ps4_error_str(update_error));
	}

	if (r != 0) {
		db->available_repos &= ~BIT(repo_num);
	} else {
		db->repo_tags[tag_id].allowed_repos |= BIT(repo_num);
	}

	return 0;
}

static void extract_cb(void *_ctx, size_t bytes_done)
{
	struct install_ctx *ctx = (struct install_ctx *) _ctx;
	if (!ctx->cb)
		return;
	ctx->cb(ctx->cb_ctx, min(ctx->installed_size + bytes_done, ctx->pkg->installed_size));
}

static void ps4_db_run_pending_script(struct install_ctx *ctx)
{
	if (!ctx->script_pending) return;
	ctx->script_pending = FALSE;
	ps4_ipkg_run_script(ctx->ipkg, ctx->db, ctx->script, ctx->script_args);
}

static int read_info_line(void *_ctx, ps4_blob_t line)
{
	struct install_ctx *ctx = (struct install_ctx *) _ctx;
	struct ps4_installed_package *ipkg = ctx->ipkg;
	struct ps4_database *db = ctx->db;
	ps4_blob_t l, r;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!ps4_blob_split(line, PS4_BLOB_STR(" = "), &l, &r))
		return 0;

	if (ps4_blob_compare(PS4_BLOB_STR("replaces"), l) == 0) {
		ps4_blob_pull_deps(&r, db, &ipkg->replaces);
	} else if (ps4_blob_compare(PS4_BLOB_STR("replaces_priority"), l) == 0) {
		ipkg->replaces_priority = ps4_blob_pull_uint(&r, 10);
	} else if (ps4_blob_compare(PS4_BLOB_STR("triggers"), l) == 0) {
		ps4_array_truncate(ipkg->triggers, 0);
		ps4_blob_for_each_segment(r, " ", parse_triggers, ctx->ipkg);

		if (ps4_array_len(ctx->ipkg->triggers) != 0 &&
		    !list_hashed(&ipkg->trigger_pkgs_list))
			list_add_tail(&ipkg->trigger_pkgs_list,
				      &db->installed.triggers);
	} else {
		ps4_extract_v2_control(&ctx->ectx, l, r);
	}
	return 0;
}

static struct ps4_db_dir_instance *ps4_db_install_directory_entry(struct install_ctx * ctx, ps4_blob_t dir)
{
	struct ps4_database *db = ctx->db;
	struct ps4_package *pkg = ctx->pkg;
	struct ps4_installed_package *ipkg = pkg->ipkg;
	struct ps4_db_dir_instance *diri;

	if (ctx->diri_node == NULL)
		ctx->diri_node = hlist_tail_ptr(&ipkg->owned_dirs);
	ctx->diri = diri = ps4_db_diri_new(db, pkg, dir, &ctx->diri_node);
	ctx->file_diri_node = hlist_tail_ptr(&diri->owned_files);

	return diri;
}

static int contains_control_character(const char *str)
{
	for (const uint8_t *p = (const uint8_t *) str; *p; p++) {
		if (*p < 0x20 || *p == 0x7f) return 1;
	}
	return 0;
}

static int need_checksum(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		return FALSE;
	default:
		return TRUE;
	}
}

static int ps4_db_install_v2meta(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	ps4_blob_t l, token = PS4_BLOB_STR("\n");
	int r;

	while (ps4_istream_get_delim(is, token, &l) == 0) {
		r = read_info_line(ctx, l);
		if (r < 0) return r;
	}

	return 0;
}

static int ps4_db_install_v3meta(struct ps4_extract_ctx *ectx, struct adb_obj *pkg)
{
	static const int script_type_to_field[] = {
		[PS4_SCRIPT_PRE_INSTALL]	= ADBI_SCRPT_PREINST,
		[PS4_SCRIPT_POST_INSTALL]	= ADBI_SCRPT_POSTINST,
		[PS4_SCRIPT_PRE_DEINSTALL]	= ADBI_SCRPT_PREDEINST,
		[PS4_SCRIPT_POST_DEINSTALL]	= ADBI_SCRPT_POSTDEINST,
		[PS4_SCRIPT_PRE_UPGRADE]	= ADBI_SCRPT_PREUPGRADE,
		[PS4_SCRIPT_POST_UPGRADE]	= ADBI_SCRPT_POSTUPGRADE,
		[PS4_SCRIPT_TRIGGER]		= ADBI_SCRPT_TRIGGER,
	};
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	struct ps4_database *db = ctx->db;
	struct ps4_installed_package *ipkg = ctx->ipkg;
	struct adb_obj scripts, triggers, pkginfo, obj;
	int i;

	// Extract the information not available in index
	adb_ro_obj(pkg, ADBI_PKG_PKGINFO, &pkginfo);
	ps4_deps_from_adb(&ipkg->replaces, db, adb_ro_obj(&pkginfo, ADBI_PI_REPLACES, &obj));
	ipkg->replaces_priority = adb_ro_int(pkg, ADBI_PKG_REPLACES_PRIORITY);
	ipkg->sha256_160 = 1;

	adb_ro_obj(pkg, ADBI_PKG_SCRIPTS, &scripts);
	for (i = 0; i < ARRAY_SIZE(script_type_to_field); i++) {
		ps4_blob_t b = adb_ro_blob(&scripts, script_type_to_field[i]);
		if (PS4_BLOB_IS_NULL(b)) continue;
		ps4_ipkg_assign_script(ipkg, i, ps4_blob_dup(b));
		ctx->script_pending |= (i == ctx->script);
	}

	adb_ro_obj(pkg, ADBI_PKG_TRIGGERS, &triggers);
	ps4_string_array_resize(&ipkg->triggers, 0, adb_ra_num(&triggers));
	for (i = ADBI_FIRST; i <= adb_ra_num(&triggers); i++)
		ps4_string_array_add(&ipkg->triggers, ps4_blob_cstr(adb_ro_blob(&triggers, i)));
	if (ps4_array_len(ctx->ipkg->triggers) != 0 && !list_hashed(&ipkg->trigger_pkgs_list))
		list_add_tail(&ipkg->trigger_pkgs_list, &db->installed.triggers);

	return 0;
}

static int ps4_db_install_script(struct ps4_extract_ctx *ectx, unsigned int type, size_t size, struct ps4_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	struct ps4_package *pkg = ctx->pkg;

	ps4_ipkg_add_script(pkg->ipkg, is, type, size);
	ctx->script_pending |= (type == ctx->script);
	return 0;
}

static int ps4_db_install_file(struct ps4_extract_ctx *ectx, const struct ps4_file_info *ae, struct ps4_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	static const char dot1[] = "/./", dot2[] = "/../";
	struct ps4_database *db = ctx->db;
	struct ps4_ctx *ac = db->ctx;
	struct ps4_out *out = &ac->out;
	struct ps4_package *pkg = ctx->pkg, *opkg;
	struct ps4_installed_package *ipkg = pkg->ipkg;
	ps4_blob_t name = PS4_BLOB_STR(ae->name), bdir, bfile;
	struct ps4_db_dir_instance *diri = ctx->diri;
	struct ps4_db_file *file, *link_target_file = NULL;
	int ret = 0, r;

	ps4_db_run_pending_script(ctx);
	if (ae->name[0] == '.') return 0;

	/* Sanity check the file name */
	if (ae->name[0] == '/' || contains_control_character(ae->name) ||
	    strncmp(ae->name, &dot1[1], 2) == 0 ||
	    strncmp(ae->name, &dot2[1], 3) == 0 ||
	    strstr(ae->name, dot1) || strstr(ae->name, dot2)) {
		ps4_warn(out, PKG_VER_FMT": ignoring malicious file %s",
			PKG_VER_PRINTF(pkg), ae->name);
		ipkg->broken_files = 1;
		return 0;
	}

	/* Installable entry */
	ctx->current_file_size = ps4_calc_installed_size(ae->size);
	if (!S_ISDIR(ae->mode)) {
		if (!ps4_blob_rsplit(name, '/', &bdir, &bfile)) {
			bdir = PS4_BLOB_NULL;
			bfile = name;
		}

		/* Make sure the file is part of the cached directory tree */
		diri = ctx->diri = find_diri(ipkg, bdir, diri, &ctx->file_diri_node);
		if (diri == NULL) {
			if (!PS4_BLOB_IS_NULL(bdir)) {
				ps4_err(out, PKG_VER_FMT": "BLOB_FMT": no dirent in archive",
					PKG_VER_PRINTF(pkg), BLOB_PRINTF(name));
				ipkg->broken_files = 1;
				return 0;
			}
			diri = ps4_db_install_directory_entry(ctx, bdir);
		}

		/* Check hard link target to exist in this package */
		if (S_ISREG(ae->mode) && ae->link_target) {
			do {
				struct ps4_db_file *lfile;
				struct ps4_db_dir_instance *ldiri;
				struct hlist_node *n;
				ps4_blob_t hldir, hlfile;

				if (!ps4_blob_rsplit(PS4_BLOB_STR(ae->link_target),
						     '/', &hldir, &hlfile))
					break;

				ldiri = find_diri(ipkg, hldir, diri, NULL);
				if (ldiri == NULL)
					break;

				hlist_for_each_entry(lfile, n, &ldiri->owned_files,
						     diri_files_list) {
					if (ps4_blob_compare(PS4_BLOB_PTR_LEN(lfile->name, lfile->namelen),
							     hlfile) == 0) {
						link_target_file = lfile;
						break;
					}
				}
			} while (0);

			if (!link_target_file) {
				ps4_err(out, PKG_VER_FMT": "BLOB_FMT": no hard link target (%s) in archive",
					PKG_VER_PRINTF(pkg), BLOB_PRINTF(name), ae->link_target);
				ipkg->broken_files = 1;
				return 0;
			}
		}

		opkg = NULL;
		file = ps4_db_file_query(db, bdir, bfile);
		if (file != NULL) {
			opkg = file->diri->pkg;
			switch (ps4_pkg_replaces_file(opkg, pkg)) {
			case PS4_PKG_REPLACES_CONFLICT:
				if (db->ctx->force & PS4_FORCE_OVERWRITE) {
					ps4_warn(out, PKG_VER_FMT": overwriting %s owned by "PKG_VER_FMT".",
						PKG_VER_PRINTF(pkg), ae->name, PKG_VER_PRINTF(opkg));
					break;
				}
				ps4_err(out, PKG_VER_FMT": trying to overwrite %s owned by "PKG_VER_FMT".",
					PKG_VER_PRINTF(pkg), ae->name, PKG_VER_PRINTF(opkg));
				ipkg->broken_files = 1;
			case PS4_PKG_REPLACES_NO:
				return 0;
			case PS4_PKG_REPLACES_YES:
				break;
			}
		}

		if (opkg != pkg) {
			/* Create the file entry without adding it to hash */
			file = ps4_db_file_new(db, diri, bfile, &ctx->file_diri_node);
		}

		ps4_dbg2(out, "%s", ae->name);

		/* Extract the file with temporary name */
		file->acl = ps4_db_acl_atomize_digest(db, ae->mode, ae->uid, ae->gid, &ae->xattr_digest);
		r = ps4_fs_extract(ac, ae, is, extract_cb, ctx, db->extract_flags, ps4_pkg_ctx(pkg));
		switch (r) {
		case 0:
			// Hardlinks need special care for checksum
			if (link_target_file)
				ps4_dbf_digest_set(file, link_target_file->digest_alg, link_target_file->digest);
			else
				ps4_dbf_digest_set(file, ae->digest.alg, ae->digest.data);

			if (ipkg->sha256_160 && S_ISLNK(ae->mode)) {
				struct ps4_digest d;
				ps4_digest_calc(&d, PS4_DIGEST_SHA256_160,
						ae->link_target, strlen(ae->link_target));
				ps4_dbf_digest_set(file, d.alg, d.data);
			} else if (file->digest_alg == PS4_DIGEST_NONE && ae->digest.alg == PS4_DIGEST_SHA256) {
				ps4_dbf_digest_set(file, PS4_DIGEST_SHA256_160, ae->digest.data);
			} else if (link_target_file == NULL && need_checksum(ae->mode) && !ctx->missing_checksum) {
				if (ae->digest.alg == PS4_DIGEST_NONE) {
					ps4_warn(out,
						PKG_VER_FMT": support for packages without embedded "
						"checksums will be dropped in ps4-tools 3.",
						PKG_VER_PRINTF(pkg));
					ipkg->broken_files = 1;
					ctx->missing_checksum = 1;
				} else if (file->digest_alg == PS4_DIGEST_NONE) {
					ps4_warn(out,
						PKG_VER_FMT": unknown v3 checksum",
						PKG_VER_PRINTF(pkg));
					ipkg->broken_files = 1;
					ctx->missing_checksum = 1;
				}
			}
			break;
		case -ENOTSUP:
			ipkg->broken_xattr = 1;
			break;
		case -ENOSPC:
			ret = r;
		case -PS4E_UVOL_ROOT:
		case -PS4E_UVOL_NOT_AVAILABLE:
		default:
			ipkg->broken_files = 1;
			break;
		}
	} else {
		struct ps4_db_acl *expected_acl;

		ps4_dbg2(out, "%s (dir)", ae->name);
		if (name.ptr[name.len-1] == '/') name.len--;

		diri = ctx->diri = find_diri(ipkg, name, NULL, &ctx->file_diri_node);
		if (!diri) diri = ps4_db_install_directory_entry(ctx, name);
		diri->acl = ps4_db_acl_atomize_digest(db, ae->mode, ae->uid, ae->gid, &ae->xattr_digest);
		expected_acl = diri->dir->owner ? diri->dir->owner->acl : NULL;
		ps4_db_dir_apply_diri_permissions(db, diri);
		ps4_db_dir_prepare(db, diri->dir, expected_acl, diri->dir->owner->acl);

	}
	ctx->installed_size += ctx->current_file_size;

	return ret;
}

static const struct ps4_extract_ops extract_installer = {
	.v2meta = ps4_db_install_v2meta,
	.v3meta = ps4_db_install_v3meta,
	.script = ps4_db_install_script,
	.file = ps4_db_install_file,
};

static int ps4_db_audit_file(struct ps4_fsdir *d, ps4_blob_t filename, struct ps4_db_file *dbf)
{
	struct ps4_file_info fi;
	int r, alg = PS4_DIGEST_NONE;

	// Check file first
	if (dbf) alg = dbf->digest_alg;
	r = ps4_fsdir_file_info(d, filename, PS4_FI_NOFOLLOW | PS4_FI_DIGEST(alg), &fi);
	if (r != 0 || alg == PS4_DIGEST_NONE) return r != -ENOENT;
	if (ps4_digest_cmp_blob(&fi.digest, alg, ps4_dbf_digest_blob(dbf)) != 0) return 1;
	return 0;
}

static void ps4_db_purge_pkg(struct ps4_database *db,
			     struct ps4_installed_package *ipkg,
			     int is_installed)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_db_dir_instance *diri;
	struct ps4_db_file *file;
	struct ps4_db_file_hash_key key;
	struct ps4_fsdir d;
	struct hlist_node *dc, *dn, *fc, *fn;
	unsigned long hash;
	int purge = db->ctx->flags & PS4_PURGE;
	int ctrl = is_installed ? PS4_FS_CTRL_DELETE : PS4_FS_CTRL_CANCEL;

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
		int dirclean = purge || !is_installed || ps4_protect_mode_none(diri->dir->protect_mode);
		int delps4new = is_installed && !ps4_protect_mode_none(diri->dir->protect_mode);
		ps4_blob_t dirname = PS4_BLOB_PTR_LEN(diri->dir->name, diri->dir->namelen);

		if (is_installed) diri->dir->modified = 1;
		ps4_fsdir_get(&d, dirname, db->extract_flags, db->ctx, ps4_pkg_ctx(ipkg->pkg));

		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files, diri_files_list) {
			key = (struct ps4_db_file_hash_key) {
				.dirname = dirname,
				.filename = PS4_BLOB_PTR_LEN(file->name, file->namelen),
			};
			hash = ps4_blob_hash_seed(key.filename, diri->dir->hash);
			if (dirclean || ps4_db_audit_file(&d, key.filename, file) == 0)
				ps4_fsdir_file_control(&d, key.filename, ctrl);
			if (delps4new)
				ps4_fsdir_file_control(&d, key.filename, PS4_FS_CTRL_DELETE_PS4NEW);

			ps4_dbg2(out, DIR_FILE_FMT, DIR_FILE_PRINTF(diri->dir, file));
			__hlist_del(fc, &diri->owned_files.first);
			if (is_installed) {
				ps4_hash_delete_hashed(&db->installed.files, PS4_BLOB_BUF(&key), hash);
				db->installed.stats.files--;
			}
		}
		__hlist_del(dc, &ipkg->owned_dirs.first);
		ps4_db_diri_free(db, diri, PS4_DIR_REMOVE);
	}
}

static uint8_t ps4_db_migrate_files_for_priority(struct ps4_database *db,
						 struct ps4_installed_package *ipkg,
						 uint8_t priority)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_db_dir_instance *diri;
	struct ps4_db_dir *dir;
	struct ps4_db_file *file, *ofile;
	struct ps4_db_file_hash_key key;
	struct hlist_node *dc, *dn, *fc, *fn;
	struct ps4_fsdir d;
	unsigned long hash;
	ps4_blob_t dirname;
	int r, ctrl, inetc;
	uint8_t dir_priority, next_priority = PS4_FS_PRIO_MAX;

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
		dir = diri->dir;
		dirname = PS4_BLOB_PTR_LEN(dir->name, dir->namelen);
		ps4_fsdir_get(&d, dirname, db->extract_flags, db->ctx, ps4_pkg_ctx(ipkg->pkg));
		dir_priority = ps4_fsdir_priority(&d);
		if (dir_priority != priority) {
			if (dir_priority > priority && dir_priority < next_priority)
				next_priority = dir_priority;
			continue;
		}
		// Used for passwd/group check later
		inetc = !ps4_blob_compare(dirname, PS4_BLOB_STRLIT("etc"));

		dir->modified = 1;
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files, diri_files_list) {
			key = (struct ps4_db_file_hash_key) {
				.dirname = dirname,
				.filename = PS4_BLOB_PTR_LEN(file->name, file->namelen),
			};

			hash = ps4_blob_hash_seed(key.filename, dir->hash);

			/* check for existing file */
			ofile = (struct ps4_db_file *) ps4_hash_get_hashed(
				&db->installed.files, PS4_BLOB_BUF(&key), hash);

			ctrl = PS4_FS_CTRL_COMMIT;
			if (ofile && ofile->diri->pkg->name == NULL) {
				// File was from overlay, delete the package's version
				ctrl = PS4_FS_CTRL_CANCEL;
			} else if (!ps4_protect_mode_none(diri->dir->protect_mode) &&
				   ps4_db_audit_file(&d, key.filename, ofile) != 0) {
				// Protected directory, and a file without db entry
				// or with local modifications. Keep the filesystem file.
				// Determine if the package's file should be kept as .ps4-new
				if ((db->ctx->flags & PS4_CLEAN_PROTECTED) ||
				    ps4_db_audit_file(&d, key.filename, file) == 0) {
					// No .ps4-new files allowed, or the file on disk has the same
					// hash as the file from new package. Keep the on disk one.
					ctrl = PS4_FS_CTRL_CANCEL;
				} else {
					// All files differ. Use the package's file as .ps4-new.
					ctrl = PS4_FS_CTRL_PS4NEW;
				}
			}

			// Commit changes
			r = ps4_fsdir_file_control(&d, key.filename, ctrl);
			if (r < 0) {
				ps4_err(out, PKG_VER_FMT": failed to commit " DIR_FILE_FMT ": %s",
					PKG_VER_PRINTF(ipkg->pkg),
					DIR_FILE_PRINTF(diri->dir, file),
					ps4_error_str(r));
				ipkg->broken_files = 1;
			} else if (inetc && ctrl == PS4_FS_CTRL_COMMIT) {
				// This is called when we successfully migrated the files
				// in the filesystem; we explicitly do not care about ps4-new
				// or cancel cases, as that does not change the original file
				if (!ps4_blob_compare(key.filename, PS4_BLOB_STRLIT("passwd")) ||
				    !ps4_blob_compare(key.filename, PS4_BLOB_STRLIT("group"))) {
					// Reset the idcache because we have a new passwd/group
					ps4_id_cache_reset(db->id_cache);
				}
			}

			// Claim ownership of the file in db
			if (ofile != file) {
				if (ofile != NULL) {
					hlist_del(&ofile->diri_files_list,
						&ofile->diri->owned_files);
					ps4_hash_delete_hashed(&db->installed.files,
							       PS4_BLOB_BUF(&key), hash);
				} else
					db->installed.stats.files++;

				ps4_hash_insert_hashed(&db->installed.files, file, hash);
			}
		}
	}
	return next_priority;
}

static void ps4_db_migrate_files(struct ps4_database *db,
				 struct ps4_installed_package *ipkg)
{
	for (uint8_t prio = PS4_FS_PRIO_DISK; prio != PS4_FS_PRIO_MAX; )
		prio = ps4_db_migrate_files_for_priority(db, ipkg, prio);
}

static int ps4_db_unpack_pkg(struct ps4_database *db,
			     struct ps4_installed_package *ipkg,
			     int upgrade, ps4_progress_cb cb, void *cb_ctx,
			     char **script_args)
{
	struct ps4_out *out = &db->ctx->out;
	struct install_ctx ctx;
	struct ps4_istream *is = NULL;
	struct ps4_repository *repo;
	struct ps4_package *pkg = ipkg->pkg;
	char file[PATH_MAX];
	char cacheitem[128];
	int r, filefd = AT_FDCWD, need_copy = FALSE;

	if (!pkg->filename_ndx) {
		repo = ps4_db_select_repo(db, pkg);
		if (repo == NULL) {
			r = -PS4E_PACKAGE_NOT_FOUND;
			goto err_msg;
		}
		r = ps4_repo_format_item(db, repo, pkg, &filefd, file, sizeof(file));
		if (r < 0)
			goto err_msg;
		if (!(pkg->repos & db->local_repos))
			need_copy = TRUE;
	} else {
		if (strlcpy(file, db->filename_array->item[pkg->filename_ndx-1], sizeof file) >= sizeof file) {
			r = -ENAMETOOLONG;
			goto err_msg;
		}
		need_copy = TRUE;
	}
	if (!ps4_db_cache_active(db))
		need_copy = FALSE;

	is = ps4_istream_from_fd_url(filefd, file, ps4_db_url_since(db, 0));
	if (IS_ERR(is)) {
		r = PTR_ERR(is);
		if (r == -ENOENT && !pkg->filename_ndx)
			r = -PS4E_INDEX_STALE;
		goto err_msg;
	}
	if (need_copy) {
		struct ps4_istream *origis = is;
		ps4_pkg_format_cache_pkg(PS4_BLOB_BUF(cacheitem), pkg);
		is = ps4_istream_tee(is, ps4_ostream_to_file(db->cache_fd, cacheitem, 0644),
			PS4_ISTREAM_TEE_COPY_META|PS4_ISTREAM_TEE_OPTIONAL, NULL, NULL);
		if (is == origis)
			ps4_warn(out, PKG_VER_FMT": unable to cache package",
				 PKG_VER_PRINTF(pkg));
	}

	ctx = (struct install_ctx) {
		.db = db,
		.pkg = pkg,
		.ipkg = ipkg,
		.script = upgrade ?
			PS4_SCRIPT_PRE_UPGRADE : PS4_SCRIPT_PRE_INSTALL,
		.script_args = script_args,
		.cb = cb,
		.cb_ctx = cb_ctx,
	};
	ps4_extract_init(&ctx.ectx, db->ctx, &extract_installer);
	ps4_extract_verify_identity(&ctx.ectx, pkg->digest_alg, ps4_pkg_digest_blob(pkg));
	r = ps4_extract(&ctx.ectx, is);
	if (need_copy && r == 0) pkg->repos |= BIT(PS4_REPOSITORY_CACHED);
	if (r != 0) goto err_msg;

	ps4_db_run_pending_script(&ctx);
	return 0;
err_msg:
	ps4_err(out, PKG_VER_FMT": %s", PKG_VER_PRINTF(pkg), ps4_error_str(r));
	return r;
}

int ps4_db_install_pkg(struct ps4_database *db, struct ps4_package *oldpkg,
		       struct ps4_package *newpkg, ps4_progress_cb cb, void *cb_ctx)
{
	char *script_args[] = { NULL, NULL, NULL, NULL };
	struct ps4_installed_package *ipkg;
	int r = 0;

	/* Upgrade script gets two args: <new-pkg> <old-pkg> */
	if (oldpkg != NULL && newpkg != NULL) {
		script_args[1] = ps4_blob_cstr(*newpkg->version);
		script_args[2] = ps4_blob_cstr(*oldpkg->version);
	} else {
		script_args[1] = ps4_blob_cstr(*(oldpkg ? oldpkg->version : newpkg->version));
	}

	/* Just purging? */
	if (oldpkg != NULL && newpkg == NULL) {
		ipkg = oldpkg->ipkg;
		if (ipkg == NULL)
			goto ret_r;
		ps4_ipkg_run_script(ipkg, db, PS4_SCRIPT_PRE_DEINSTALL, script_args);
		ps4_db_purge_pkg(db, ipkg, TRUE);
		ps4_ipkg_run_script(ipkg, db, PS4_SCRIPT_POST_DEINSTALL, script_args);
		ps4_pkg_uninstall(db, oldpkg);
		goto ret_r;
	}

	/* Install the new stuff */
	ipkg = ps4_pkg_install(db, newpkg);
	ipkg->run_all_triggers = 1;
	ipkg->broken_script = 0;
	ipkg->broken_files = 0;
	ipkg->broken_xattr = 0;
	if (ps4_array_len(ipkg->triggers) != 0) {
		char **trigger;
		list_del(&ipkg->trigger_pkgs_list);
		list_init(&ipkg->trigger_pkgs_list);
		foreach_array_item(trigger, ipkg->triggers)
			free(*trigger);
		ps4_array_truncate(ipkg->triggers, 0);
	}

	if (newpkg->installed_size != 0) {
		r = ps4_db_unpack_pkg(db, ipkg, (oldpkg != NULL),
				      cb, cb_ctx, script_args);
		if (r != 0) {
			if (oldpkg != newpkg)
				ps4_db_purge_pkg(db, ipkg, FALSE);
			ps4_pkg_uninstall(db, newpkg);
			goto ret_r;
		}
		ps4_db_migrate_files(db, ipkg);
	}

	if (oldpkg != NULL && oldpkg != newpkg && oldpkg->ipkg != NULL) {
		ps4_db_purge_pkg(db, oldpkg->ipkg, TRUE);
		ps4_pkg_uninstall(db, oldpkg);
	}

	ps4_ipkg_run_script(
		ipkg, db,
		(oldpkg == NULL) ? PS4_SCRIPT_POST_INSTALL : PS4_SCRIPT_POST_UPGRADE,
		script_args);

	if (ipkg->broken_files || ipkg->broken_script)
		r = -1;
ret_r:
	free(script_args[1]);
	free(script_args[2]);
	return r;
}

struct match_ctx {
	struct ps4_database *db;
	struct ps4_string_array *filter;
	ps4_db_foreach_name_cb cb;
	void *cb_ctx;
};

static int ps4_string_match(const char *str, struct ps4_string_array *filter, const char **res)
{
	char **pmatch;

	foreach_array_item(pmatch, filter) {
		if (fnmatch(*pmatch, str, FNM_CASEFOLD) == 0) {
			*res = *pmatch;
			return 1;
		}
	}
	return 0;
}

static int ps4_name_match(struct ps4_name *name, struct ps4_string_array *filter, const char **res)
{
	if (!filter) {
		*res = NULL;
		return 1;
	}
	return ps4_string_match(name->name, filter, res);
}

static int ps4_pkg_match(struct ps4_package *pkg, struct ps4_string_array *filter, const char **res, int provides)
{
	struct ps4_dependency *d;

	if (ps4_name_match(pkg->name, filter, res)) return 1;
	if (!provides) return 0;
	foreach_array_item(d, pkg->provides) {
		if (ps4_string_match(d->name->name, filter, res)) return 1;
	}
	return 0;
}

static int match_names(ps4_hash_item item, void *pctx)
{
	struct match_ctx *ctx = (struct match_ctx *) pctx;
	struct ps4_name *name = (struct ps4_name *) item;
	const char *match;

	if (ps4_name_match(name, ctx->filter, &match))
		return ctx->cb(ctx->db, match, name, ctx->cb_ctx);
	return 0;
}

int ps4_db_foreach_matching_name(
	struct ps4_database *db, struct ps4_string_array *filter,
	ps4_db_foreach_name_cb cb, void *ctx)
{
	char **pmatch;
	struct ps4_name *name;
	struct match_ctx mctx = {
		.db = db,
		.cb = cb,
		.cb_ctx = ctx,
	};
	int r;

	if (!filter || ps4_array_len(filter) == 0) goto all;

	mctx.filter = filter;
	foreach_array_item(pmatch, filter)
		if (strchr(*pmatch, '*') != NULL)
			goto all;

	foreach_array_item(pmatch, filter) {
		name = (struct ps4_name *) ps4_hash_get(&db->available.names, PS4_BLOB_STR(*pmatch));
		r = cb(db, *pmatch, name, ctx);
		if (r) return r;
	}
	return 0;

all:
	return ps4_hash_foreach(&db->available.names, match_names, &mctx);
}

static int cmp_name(const void *a, const void *b)
{
	const struct ps4_name * const* na = a, * const* nb = b;
	return ps4_name_cmp_display(*na, *nb);
}

static int cmp_package(const void *a, const void *b)
{
	const struct ps4_package * const* pa = a, * const* pb = b;
	return ps4_pkg_cmp_display(*pa, *pb);
}

static int add_name(ps4_hash_item item, void *ctx)
{
	struct ps4_name_array **a = ctx;
	ps4_name_array_add(a, (struct ps4_name *) item);
	return 0;
}

static struct ps4_name_array *ps4_db_sorted_names(struct ps4_database *db)
{
	if (!db->sorted_names) {
		ps4_name_array_resize(&db->available.sorted_names, 0, db->available.names.num_items);
		ps4_hash_foreach(&db->available.names, add_name, &db->available.sorted_names);
		ps4_array_qsort(db->available.sorted_names, cmp_name);
		db->sorted_names = 1;
	}
	return db->available.sorted_names;
}

struct ps4_package_array *ps4_db_sorted_installed_packages(struct ps4_database *db)
{
	struct ps4_installed_package *ipkg;

	if (!db->sorted_installed_packages) {
		db->sorted_installed_packages = 1;
		ps4_package_array_resize(&db->installed.sorted_packages, 0, db->installed.stats.packages);
		list_for_each_entry(ipkg, &db->installed.packages, installed_pkgs_list)
			ps4_package_array_add(&db->installed.sorted_packages, ipkg->pkg);
		ps4_array_qsort(db->installed.sorted_packages, cmp_package);
	}
	return db->installed.sorted_packages;
}

int ps4_db_foreach_sorted_name(struct ps4_database *db, struct ps4_string_array *filter,
			       ps4_db_foreach_name_cb cb, void *cb_ctx)
{
	int r, walk_all = 0;
	char **pmatch;
	const char *match;
	struct ps4_name *name;
	struct ps4_name *results[128], **res;
	size_t i, num_res = 0;

	if (filter && ps4_array_len(filter) != 0) {
		foreach_array_item(pmatch, filter) {
			name = (struct ps4_name *) ps4_hash_get(&db->available.names, PS4_BLOB_STR(*pmatch));
			if (strchr(*pmatch, '*')) {
				walk_all = 1;
				continue;
			}
			if (!name) {
				cb(db, *pmatch, NULL, cb_ctx);
				continue;
			}
			if (walk_all) continue;
			if (num_res >= ARRAY_SIZE(results)) {
				walk_all = 1;
				continue;
			}
			results[num_res++] = name;
		}
	} else {
		filter = NULL;
		walk_all = 1;
	}

	if (walk_all) {
		struct ps4_name_array *a = ps4_db_sorted_names(db);
		res = a->item;
		num_res = ps4_array_len(a);
	} else {
		qsort(results, num_res, sizeof results[0], cmp_name);
		res = results;
	}

	for (i = 0; i < num_res; i++) {
		name = res[i];
		if (ps4_name_match(name, filter, &match)) {
			r = cb(db, match, name, cb_ctx);
			if (r) return r;
		}
	}
	return 0;
}

int __ps4_db_foreach_sorted_package(struct ps4_database *db, struct ps4_string_array *filter,
				    ps4_db_foreach_package_cb cb, void *cb_ctx, int provides)
{
	char **pmatch;
	const char *match;
	struct ps4_name *name;
	struct ps4_package *results[128];
	struct ps4_provider *p;
	size_t i, num_res = 0;
	int r;

	if (!filter || ps4_array_len(filter) == 0) {
		filter = NULL;
		goto walk_all;
	}

	foreach_array_item(pmatch, filter) {
		name = (struct ps4_name *) ps4_hash_get(&db->available.names, PS4_BLOB_STR(*pmatch));
		if (strchr(*pmatch, '*')) goto walk_all;
		if (!name) {
			cb(db, *pmatch, NULL, cb_ctx);
			continue;
		}

		foreach_array_item(p, name->providers) {
			if (!provides && p->pkg->name != name) continue;
			if (p->pkg->seen) continue;
			p->pkg->seen = 1;
			if (num_res >= ARRAY_SIZE(results)) goto walk_all;
			results[num_res++] = p->pkg;
		}
	}
	for (i = 0; i < num_res; i++) results[i]->seen = 0;

	qsort(results, num_res, sizeof results[0], cmp_package);
	for (i = 0; i < num_res; i++) {
		if (ps4_pkg_match(results[i], filter, &match, provides)) {
			r = cb(db, match, results[i], cb_ctx);
			if (r) return r;
		}
	}
	return 0;

walk_all:
	for (i = 0; i < num_res; i++) results[i]->seen = 0;

	struct ps4_name_array *name_array = ps4_db_sorted_names(db);
	struct ps4_name **nameptr;
	foreach_array_item(nameptr, name_array) {
		name = *nameptr;
		ps4_name_sorted_providers(name);
		foreach_array_item(p, name->providers) {
			if (p->pkg->name != name) continue;
			if (ps4_pkg_match(p->pkg, filter, &match, provides)) {
				r = cb(db, match, p->pkg, cb_ctx);
				if (r) return r;
			}
		}
	}
	return 0;
}
