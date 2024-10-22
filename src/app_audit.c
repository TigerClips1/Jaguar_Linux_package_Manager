/* app_audit.c - PS4linux package manager (PS4)
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
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_print.h"

enum {
	MODE_BACKUP = 0,
	MODE_SYSTEM,
	MODE_FULL,
};

struct audit_ctx {
	struct ps4_istream blob_istream;
	int verbosity;
	unsigned mode : 2;
	unsigned recursive : 1;
	unsigned check_permissions : 1;
	unsigned packages_only : 1;
	unsigned ignore_busybox_symlinks : 1;
	unsigned details : 1;
};

#define AUDIT_OPTIONS(OPT) \
	OPT(OPT_AUDIT_backup,			"backup") \
	OPT(OPT_AUDIT_check_permissions,	"check-permissions") \
	OPT(OPT_AUDIT_details,			"details") \
	OPT(OPT_AUDIT_full,			"full") \
	OPT(OPT_AUDIT_ignore_busybox_symlinks,	"ignore-busybox-symlinks") \
	OPT(OPT_AUDIT_packages,			"packages") \
	OPT(OPT_AUDIT_protected_paths,		PS4_OPT_ARG "protected-paths") \
	OPT(OPT_AUDIT_recursive,		PS4_OPT_SH("r") "recursive") \
	OPT(OPT_AUDIT_system,			"system")

PS4_OPT_APPLET(option_desc, AUDIT_OPTIONS);

static int protected_paths_istream(struct ps4_ctx *ac, struct ps4_istream *is)
{
	if (ac->protected_paths) ps4_istream_close(ac->protected_paths);
	if (IS_ERR(is)) {
		ac->protected_paths = NULL;
		return PTR_ERR(is);
	}
	ac->protected_paths = is;
	return 0;
}

static int option_parse_applet(void *applet_ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct audit_ctx *actx = (struct audit_ctx *) applet_ctx;
	struct ps4_out *out = &ac->out;
	int r;

	switch (opt) {
	case OPT_AUDIT_backup:
		actx->mode = MODE_BACKUP;
		break;
	case OPT_AUDIT_full:
		actx->mode = MODE_FULL;
		protected_paths_istream(ac,
			ps4_istream_from_blob(&actx->blob_istream,
				PS4_BLOB_STRLIT(
					"+etc\n"
					"@etc/init.d\n"
					"-dev\n"
					"-home\n"
					"-lib/ps4\n"
					"-lib/rc/cache\n"
					"-proc\n"
					"-root\n"
					"-run\n"
					"-sys\n"
					"-tmp\n"
					"-var\n"
				)));
		break;
	case OPT_AUDIT_system:
		actx->mode = MODE_SYSTEM;
		break;
	case OPT_AUDIT_check_permissions:
		actx->check_permissions = 1;
		break;
	case OPT_AUDIT_details:
		actx->details = 1;
		break;
	case OPT_AUDIT_ignore_busybox_symlinks:
		actx->ignore_busybox_symlinks = 1;
		break;
	case OPT_AUDIT_packages:
		actx->packages_only = 1;
		break;
	case OPT_AUDIT_protected_paths:
		r = protected_paths_istream(ac, ps4_istream_from_file(AT_FDCWD, optarg));
		if (r) {
			ps4_err(out, "unable to read protected path file: %s: %s", optarg, ps4_error_str(r));
			return r;
		}
		break;
	case OPT_AUDIT_recursive:
		actx->recursive = 1;
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

struct audit_tree_ctx {
	struct audit_ctx *actx;
	struct ps4_database *db;
	struct ps4_db_dir *dir;
	size_t pathlen;
	char path[PATH_MAX];
};

static int audit_file(struct audit_ctx *actx,
		      struct ps4_database *db,
		      struct ps4_db_file *dbf,
		      int dirfd, const char *name,
		      struct ps4_file_info *fi)
{
	int digest_type = PS4_DIGEST_SHA256;
	int xattr_type = PS4_DIGEST_SHA1;
	int rv = 0;

	if (dbf) {
		digest_type = dbf->digest_alg;
		xattr_type = ps4_digest_alg_by_len(dbf->acl->xattr_hash_len);
	} else {
		if (!actx->details) return 'A';
	}

	if (ps4_fileinfo_get(dirfd, name,
				PS4_FI_NOFOLLOW |
				PS4_FI_XATTR_DIGEST(xattr_type ?: PS4_DIGEST_SHA1) |
				PS4_FI_DIGEST(digest_type),
				fi, &db->atoms) != 0)
		return 'e';

	if (!dbf) return 'A';

	if (dbf->digest_alg != PS4_DIGEST_NONE &&
	    ps4_digest_cmp_blob(&fi->digest, dbf->digest_alg, ps4_dbf_digest_blob(dbf)) != 0)
		rv = 'U';
	else if (!S_ISLNK(fi->mode) && !dbf->diri->pkg->ipkg->broken_xattr &&
		 ps4_digest_cmp_blob(&fi->xattr_digest, xattr_type, ps4_acl_digest_blob(dbf->acl)) != 0)
		rv = 'x';
	else if (S_ISLNK(fi->mode) && dbf->digest_alg == PS4_DIGEST_NONE)
		rv = 'U';
	else if (actx->check_permissions) {
		if ((fi->mode & 07777) != (dbf->acl->mode & 07777))
			rv = 'M';
		else if (fi->uid != dbf->acl->uid || fi->gid != dbf->acl->gid)
			rv = 'M';
	}

	return rv;
}

static int audit_directory(struct audit_ctx *actx,
			   struct ps4_database *db,
			   struct ps4_db_dir *dbd,
			   struct ps4_file_info *fi)
{
	if (dbd != NULL) dbd->modified = 1;

	if (dbd == NULL || dbd->refs == 1)
		return actx->recursive ? 'd' : 'D';

	struct ps4_db_acl *acl = dbd->owner->acl;
	if (actx->check_permissions && dbd->modified) {
		if ((fi->mode & 07777) != (acl->mode & 07777))
			return 'm';
		if (fi->uid != acl->uid || fi->gid != acl->gid)
			return 'm';
	}

	return 0;
}

static const char *format_checksum(const ps4_blob_t csum, ps4_blob_t b)
{
	const char *ret = b.ptr;
	if (csum.len == 0) return "";
	ps4_blob_push_blob(&b, PS4_BLOB_STR(" hash="));
	ps4_blob_push_hexdump(&b, csum);
	ps4_blob_push_blob(&b, PS4_BLOB_PTR_LEN("", 1));
	return ret;
}

static void report_audit(struct audit_ctx *actx,
			 char reason, ps4_blob_t bfull,
			 struct ps4_db_dir *dir,
			 struct ps4_db_file *file,
			 struct ps4_file_info *fi)
{
	struct ps4_package *pkg = file ? file->diri->pkg : NULL;
	char csum_buf[8+2*PS4_DIGEST_LENGTH_MAX];
	int verbosity = actx->verbosity;

	if (!reason) return;

	if (actx->packages_only) {
		if (!pkg || pkg->state_int != 0) return;
		pkg->state_int = 1;
		if (verbosity < 1)
			printf("%s\n", pkg->name->name);
		else
			printf(PKG_VER_FMT "\n", PKG_VER_PRINTF(pkg));
	} else if (verbosity < 1) {
		printf(BLOB_FMT "\n", BLOB_PRINTF(bfull));
	} else {
		if (actx->details) {
			struct ps4_db_acl *acl = NULL;
			if (file) acl = file->acl;
			else if (dir && reason != 'D' && reason != 'd') acl = dir->owner->acl;
			if (acl) printf("- mode=%o uid=%d gid=%d%s\n",
				acl->mode & 07777, acl->uid, acl->gid,
				file ? format_checksum(ps4_dbf_digest_blob(file), PS4_BLOB_BUF(csum_buf)) : "");
			if (fi) printf("+ mode=%o uid=%d gid=%d%s\n",
				fi->mode & 07777, fi->uid, fi->gid,
				format_checksum(PS4_DIGEST_BLOB(fi->digest), PS4_BLOB_BUF(csum_buf)));
		}
		printf("%c " BLOB_FMT "\n", reason, BLOB_PRINTF(bfull));
	}
}

static int determine_file_protect_mode(struct ps4_db_dir *dir, const char *name)
{
	struct ps4_protected_path *ppath;
	int protect_mode = dir->protect_mode;

	/* inherit file's protection mask */
	foreach_array_item(ppath, dir->protected_paths) {
		char *slash = strchr(ppath->relative_pattern, '/');
		if (slash == NULL) {
			if (fnmatch(ppath->relative_pattern, name, FNM_PATHNAME) != 0)
				continue;
			protect_mode = ppath->protect_mode;
		}
	}
	return protect_mode;
}

static int audit_directory_tree_item(void *ctx, int dirfd, const char *name)
{
	struct audit_tree_ctx *atctx = (struct audit_tree_ctx *) ctx;
	ps4_blob_t bdir = PS4_BLOB_PTR_LEN(atctx->path, atctx->pathlen);
	ps4_blob_t bent = PS4_BLOB_STR(name);
	ps4_blob_t bfull;
	struct audit_ctx *actx = atctx->actx;
	struct ps4_database *db = atctx->db;
	struct ps4_db_dir *dir = atctx->dir, *child = NULL;
	struct ps4_db_file *dbf;
	struct ps4_file_info fi;
	int reason = 0;

	if (bdir.len + bent.len + 1 >= sizeof(atctx->path)) return 0;

	memcpy(&atctx->path[atctx->pathlen], bent.ptr, bent.len);
	atctx->pathlen += bent.len;
	bfull = PS4_BLOB_PTR_LEN(atctx->path, atctx->pathlen);

	if (ps4_fileinfo_get(dirfd, name, PS4_FI_NOFOLLOW, &fi, &db->atoms) < 0) {
		dbf = ps4_db_file_query(db, bdir, bent);
		if (dbf) dbf->audited = 1;
		report_audit(actx, 'e', bfull, NULL, dbf, NULL);
		goto done;
	}

	if (S_ISDIR(fi.mode)) {
		int recurse = TRUE;

		switch (actx->mode) {
		case MODE_BACKUP:
			child = ps4_db_dir_get(db, bfull);
			if (!child->has_protected_children)
				recurse = FALSE;
			if (ps4_protect_mode_none(child->protect_mode))
				goto recurse_check;
			break;
		case MODE_SYSTEM:
			child = ps4_db_dir_query(db, bfull);
			if (child == NULL) goto done;
			child = ps4_db_dir_ref(child);
			break;
		case MODE_FULL:
			child = ps4_db_dir_get(db, bfull);
			if (child->protect_mode == PS4_PROTECT_NONE) break;
			goto recurse_check;
		}

		reason = audit_directory(actx, db, child, &fi);

recurse_check:
		atctx->path[atctx->pathlen++] = '/';
		bfull.len++;
		report_audit(actx, reason, bfull, child, NULL, &fi);
		if (reason != 'D' && recurse) {
			atctx->dir = child;
			ps4_dir_foreach_file(
				openat(dirfd, name, O_RDONLY|O_CLOEXEC),
				audit_directory_tree_item, atctx);
			atctx->dir = dir;
		}
		bfull.len--;
		atctx->pathlen--;
	} else {
		int protect_mode = determine_file_protect_mode(dir, name);

		dbf = ps4_db_file_query(db, bdir, bent);
		if (dbf) dbf->audited = 1;

		switch (actx->mode) {
		case MODE_FULL:
			switch (protect_mode) {
			case PS4_PROTECT_NONE:
				break;
			case PS4_PROTECT_SYMLINKS_ONLY:
				if (S_ISLNK(fi.mode)) goto done;
				break;
			case PS4_PROTECT_IGNORE:
			case PS4_PROTECT_ALL:
			case PS4_PROTECT_CHANGED:
				goto done;
			}
			break;
		case MODE_BACKUP:
			switch (protect_mode) {
			case PS4_PROTECT_NONE:
			case PS4_PROTECT_IGNORE:
				goto done;
			case PS4_PROTECT_CHANGED:
				break;
			case PS4_PROTECT_SYMLINKS_ONLY:
				if (!S_ISLNK(fi.mode)) goto done;
				break;
			case PS4_PROTECT_ALL:
				reason = 'A';
				break;
			}
			if ((!dbf || reason == 'A') &&
			    ps4_blob_ends_with(bent, PS4_BLOB_STR(".ps4-new")))
				goto done;
			break;
		case MODE_SYSTEM:
			if (!dbf || !ps4_protect_mode_none(protect_mode)) goto done;
			break;
		}

		if (!dbf && actx->ignore_busybox_symlinks && S_ISLNK(fi.mode)) {
			char target[20];
			ssize_t n;
			n = readlinkat(dirfd, name, target, sizeof target);
			if (n == 12 && memcmp(target, "/bin/busybox", 12) == 0)
				goto done;
			if (n == 11 && memcmp(target, "/bin/bbsuid", 11) == 0)
				goto done;
			if (n == 19 && memcmp(target, "/bin/busybox-extras", 19) == 0)
				goto done;
		}
		if (!reason) reason = audit_file(actx, db, dbf, dirfd, name, &fi);
		report_audit(actx, reason, bfull, NULL, dbf, &fi);
	}

done:
	if (child)
		ps4_db_dir_unref(db, child, FALSE);

	atctx->pathlen -= bent.len;
	return 0;
}

static int audit_directory_tree(struct audit_tree_ctx *atctx, int dirfd)
{
	ps4_blob_t path;
	int r;

	path = PS4_BLOB_PTR_LEN(atctx->path, atctx->pathlen);
	if (path.len && path.ptr[path.len-1] == '/')
		path.len--;

	atctx->dir = ps4_db_dir_get(atctx->db, path);
	atctx->dir->modified = 1;
	r = ps4_dir_foreach_file(dirfd, audit_directory_tree_item, atctx);
	ps4_db_dir_unref(atctx->db, atctx->dir, FALSE);

	return r;
}

static int audit_missing_files(ps4_hash_item item, void *pctx)
{
	struct audit_ctx *actx = pctx;
	struct ps4_db_file *file = item;
	struct ps4_db_dir *dir;
	char path[PATH_MAX];
	int len;

	if (file->audited) return 0;

	dir = file->diri->dir;
	if (!dir->modified) return 0;
	if (determine_file_protect_mode(dir, file->name) == PS4_PROTECT_IGNORE) return 0;

	len = snprintf(path, sizeof(path), DIR_FILE_FMT, DIR_FILE_PRINTF(dir, file));
	report_audit(actx, 'X', PS4_BLOB_PTR_LEN(path, len), NULL, file, NULL);
	return 0;
}

static int audit_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;
	struct audit_tree_ctx atctx;
	struct audit_ctx *actx = (struct audit_ctx *) ctx;
	char **parg, *arg;
	int r = 0;

	if (db->usermode) {
		ps4_err(out, "audit does not support usermode!");
		return -ENOSYS;
	}

	actx->verbosity = ps4_out_verbosity(&db->ctx->out);
	atctx.db = db;
	atctx.actx = actx;
	atctx.pathlen = 0;
	atctx.path[0] = 0;

	if (ps4_array_len(args) == 0) {
		r |= audit_directory_tree(&atctx, dup(db->root_fd));
	} else {
		foreach_array_item(parg, args) {
			arg = *parg;
			if (arg[0] != '/') {
				ps4_warn(out, "%s: relative path skipped.", arg);
				continue;
			}
			arg++;
			atctx.pathlen = strlen(arg);
			memcpy(atctx.path, arg, atctx.pathlen);
			if (atctx.path[atctx.pathlen-1] != '/')
				atctx.path[atctx.pathlen++] = '/';

			r |= audit_directory_tree(&atctx, openat(db->root_fd, arg, O_RDONLY|O_CLOEXEC));
		}
	}
	if (actx->mode == MODE_SYSTEM || actx->mode == MODE_FULL)
		ps4_hash_foreach(&db->installed.files, audit_missing_files, ctx);

	return r;
}

static struct ps4_applet ps4_audit = {
	.name = "audit",
	.open_flags = PS4_OPENF_READ|PS4_OPENF_NO_SCRIPTS|PS4_OPENF_NO_REPOS,
	.context_size = sizeof(struct audit_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = audit_main,
};

PS4_DEFINE_APPLET(ps4_audit);

