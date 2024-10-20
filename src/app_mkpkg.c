/* app_mkpkg.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ps4_defines.h"
#include "ps4_adb.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_pathbuilder.h"
#include "ps4_extract.h"
#include "ps4_print.h"
#include "ps4_xattr.h"

#define BLOCK_SIZE 4096

struct mkpkg_ctx {
	struct ps4_ctx *ac;
	const char *files_dir, *output;
	struct adb db;
	struct adb_obj paths, *files;
	struct ps4_extract_ctx ectx;
	ps4_blob_t package[ADBI_PKG_MAX];
	ps4_blob_t info[ADBI_PI_MAX];
	ps4_blob_t script[ADBI_SCRPT_MAX];
	struct ps4_string_array *triggers;
	uint64_t installed_size;
	struct ps4_pathbuilder pb;
	unsigned has_scripts : 1;
	unsigned rootnode : 1;
};

#define MKPKG_OPTIONS(OPT) \
	OPT(OPT_MKPKG_files,		PS4_OPT_ARG PS4_OPT_SH("F") "files") \
	OPT(OPT_MKPKG_info,		PS4_OPT_ARG PS4_OPT_SH("I") "info") \
	OPT(OPT_MKPKG_output,		PS4_OPT_ARG PS4_OPT_SH("o") "output") \
	OPT(OPT_MKPKG_rootnode,		"rootnode") \
	OPT(OPT_MKPKG_no_rootnode,	"no-rootnode") \
	OPT(OPT_MKPKG_script,		PS4_OPT_ARG PS4_OPT_SH("s") "script") \
	OPT(OPT_MKPKG_trigger,		PS4_OPT_ARG PS4_OPT_SH("t") "trigger") \

PS4_OPT_APPLET(option_desc, MKPKG_OPTIONS);

static int parse_info(struct mkpkg_ctx *ictx, struct ps4_out *out, const char *optarg)
{
	ps4_blob_t l, r;
	int i;

	if (!ps4_blob_split(PS4_BLOB_STR(optarg), PS4_BLOB_STRLIT(":"), &l, &r))
		goto inval;

	i = adb_s_field_by_name_blob(&schema_pkginfo, l);
	switch (i) {
	case 0:
		break;
	case ADBI_PI_FILE_SIZE:
	case ADBI_PI_INSTALLED_SIZE:
		return -EINVAL;
	default:
		ictx->info[i] = r;
		return 0;
	}

	i = adb_s_field_by_name_blob(&schema_package, l);
	switch (i) {
	case ADBI_PKG_REPLACES_PRIORITY:
		ictx->package[i] = r;
		return 0;
	default:
		break;
	}

inval:
	ps4_err(out, "invalid info field: " BLOB_FMT, BLOB_PRINTF(l));
	return -EINVAL;
}

static int option_parse_applet(void *ctx, struct ps4_ctx *ac, int optch, const char *optarg)
{
	struct ps4_out *out = &ac->out;
	struct mkpkg_ctx *ictx = ctx;
	ps4_blob_t l, r;
	int i, ret;

	switch (optch) {
	case PS4_OPTIONS_INIT:
		ps4_string_array_init(&ictx->triggers);
		ictx->rootnode = 1;
		break;
	case OPT_MKPKG_files:
		ictx->files_dir = optarg;
		break;
	case OPT_MKPKG_info:
		return parse_info(ictx, out, optarg);
	case OPT_MKPKG_output:
		ictx->output = optarg;
		break;
	case OPT_MKPKG_rootnode:
		ictx->rootnode = 1;
		break;
	case OPT_MKPKG_no_rootnode:
		ictx->rootnode = 0;
		break;
	case OPT_MKPKG_script:
		ps4_blob_split(PS4_BLOB_STR(optarg), PS4_BLOB_STRLIT(":"), &l, &r);
		i = adb_s_field_by_name_blob(&schema_scripts, l);
		if (!i) {
			ps4_err(out, "invalid script type: " BLOB_FMT, BLOB_PRINTF(l));
			return -EINVAL;
		}
		ret = ps4_blob_from_file(AT_FDCWD, r.ptr, &ictx->script[i]);
		if (ret) {
			ps4_err(out, "failed to load script: " BLOB_FMT ": %s",
				BLOB_PRINTF(r), ps4_error_str(ret));
			return ret;
		}
		ictx->has_scripts = 1;
		break;
	case OPT_MKPKG_trigger:
		ps4_string_array_add(&ictx->triggers, (char*) optarg);
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

static adb_val_t create_xattrs(struct adb *db, int fd)
{
	struct adb_obj xa;
	char names[1024], buf[1024];
	ssize_t len, vlen;
	adb_val_t val;
	int i;

	len = ps4_flistxattr(fd, names, sizeof names);
	if (len <= 0) return ADB_NULL;

	adb_wo_alloca(&xa, &schema_xattr_array, db);
	for (i = 0; i < len; i += strlen(&names[i]) + 1) {
		vlen = ps4_fgetxattr(fd, &names[i], buf, sizeof buf);
		if (vlen < 0) continue;

		ps4_blob_t vec[] = {
			ps4_BLOB_PTR_LEN(&names[i], strlen(&names[i])+1),
			ps4_BLOB_PTR_LEN(buf, vlen),
		};
		adb_wa_append(&xa, adb_w_blob_vec(db, ARRAY_SIZE(vec), vec));
	}
	val = adb_w_arr(&xa);
	adb_wo_free(&xa);

	return val;
}

static adb_val_t create_xattrs_closefd(struct adb *db, int fd)
{
	adb_val_t val = create_xattrs(db, fd);
	close(fd);
	return val;
}

static int mkpkg_process_dirent(void *pctx, int dirfd, const char *entry);

static int mkpkg_process_directory(struct mkpkg_ctx *ctx, int dirfd, struct ps4_file_info *fi)
{
	struct ps4_ctx *ac = ctx->ac;
	struct ps4_id_cache *idc = ps4_ctx_get_id_cache(ac);
	struct ps4_out *out = &ac->out;
	struct adb_obj acl, fio, files, *prev_files;
	ps4_blob_t dirname = ps4_pathbuilder_get(&ctx->pb);
	int r;

	adb_wo_alloca(&fio, &schema_dir, &ctx->db);
	adb_wo_alloca(&acl, &schema_acl, &ctx->db);
	adb_wo_blob(&fio, ADBI_DI_NAME, dirname);
	if (dirname.len != 0 || ctx->rootnode) {
		adb_wo_int(&acl, ADBI_ACL_MODE, fi->mode & ~S_IFMT);
		adb_wo_blob(&acl, ADBI_ACL_USER, ps4_id_cache_resolve_user(idc, fi->uid));
		adb_wo_blob(&acl, ADBI_ACL_GROUP, ps4_id_cache_resolve_group(idc, fi->gid));
		adb_wo_val(&acl, ADBI_ACL_XATTRS, create_xattrs(&ctx->db, dirfd));
		adb_wo_obj(&fio, ADBI_DI_ACL, &acl);
	}

	adb_wo_alloca(&files, &schema_file_array, &ctx->db);
	prev_files = ctx->files;
	ctx->files = &files;
	r = ps4_dir_foreach_file(dirfd, mkpkg_process_dirent, ctx);
	ctx->files = prev_files;
	if (r) {
		ps4_err(out, "failed to process directory '%s': %d",
			ps4_pathbuilder_cstr(&ctx->pb), r);
		goto done;
	}
	// no need to record root folder if its empty
	if (dirname.len == 0 && !ctx->rootnode && adb_ra_num(&files) == 0) goto done;

	adb_wo_obj(&fio, ADBI_DI_FILES, &files);
	adb_wa_append_obj(&ctx->paths, &fio);
done:
	adb_wo_free(&files);
	return r;
}

static int mkpkg_process_dirent(void *pctx, int dirfd, const char *entry)
{
	struct mkpkg_ctx *ctx = pctx;
	struct ps4_ctx *ac = ctx->ac;
	struct ps4_out *out = &ac->out;
	struct ps4_id_cache *idc = ps4_ctx_get_id_cache(ac);
	struct ps4_file_info fi;
	struct adb_obj fio, acl;
	ps4_blob_t target = PS4_BLOB_NULL;
	union {
		uint16_t mode;
		struct {
			uint16_t mode;
			uint64_t dev;
		} __attribute__((packed)) dev;
		struct {
			uint16_t mode;
			char target[1022];
		} symlink;
	} ft;
	int r, n;

	r = ps4_fileinfo_get(dirfd, entry, PS4_FI_NOFOLLOW | PS4_FI_DIGEST(PS4_DIGEST_SHA256), &fi, NULL);
	if (r) return r;

	switch (fi.mode & S_IFMT) {
	case S_IFREG:
		ctx->installed_size += (fi.size + BLOCK_SIZE - 1) & ~(BLOCK_SIZE-1);
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		ft.dev.mode = htole16(fi.mode & S_IFMT);
		ft.dev.dev = htole64(fi.device);
		target = PS4_BLOB_STRUCT(ft.dev);
		break;
	case S_IFLNK:
		ft.symlink.mode = htole16(fi.mode & S_IFMT);
		r = readlinkat(dirfd, entry, ft.symlink.target, sizeof ft.symlink.target);
		if (r < 0) return r;
		target = PS4_BLOB_PTR_LEN((void*)&ft.symlink, sizeof(ft.symlink.mode) + r);
		r = 0;
		break;
	case S_IFDIR:
		n = ps4_pathbuilder_push(&ctx->pb, entry);
		r = mkpkg_process_directory(ctx, openat(dirfd, entry, O_RDONLY), &fi);
		ps4_pathbuilder_pop(&ctx->pb, n);
		return r;
	default:
		n = ps4_pathbuilder_push(&ctx->pb, entry);
		ps4_out(out, "%s: special file ignored", ps4_pathbuilder_cstr(&ctx->pb));
		ps4_pathbuilder_pop(&ctx->pb, n);
		return 0;
	}

	adb_wo_alloca(&fio, &schema_file, &ctx->db);
	adb_wo_alloca(&acl, &schema_acl, &ctx->db);
	adb_wo_blob(&fio, ADBI_FI_NAME, PS4_BLOB_STR(entry));
	if (ps4_BLOB_IS_NULL(target))
		adb_wo_blob(&fio, ADBI_FI_HASHES, PS4_DIGEST_BLOB(fi.digest));
	else
		adb_wo_blob(&fio, ADBI_FI_TARGET, target);
	adb_wo_int(&fio, ADBI_FI_MTIME, fi.mtime);
	adb_wo_int(&fio, ADBI_FI_SIZE, fi.size);

	adb_wo_int(&acl, ADBI_ACL_MODE, fi.mode & 07777);
	adb_wo_blob(&acl, ADBI_ACL_USER, ps4_id_cache_resolve_user(idc, fi.uid));
	adb_wo_blob(&acl, ADBI_ACL_GROUP, ps4_id_cache_resolve_group(idc, fi.gid));
	adb_wo_val(&acl, ADBI_ACL_XATTRS, create_xattrs_closefd(&ctx->db, openat(dirfd, entry, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)));
	adb_wo_obj(&fio, ADBI_FI_ACL, &acl);

	adb_wa_append_obj(ctx->files, &fio);

	return r;
}

static char *pkgi_filename(struct adb_obj *pkgi, char *buf, size_t n)
{
	ps4_blob_t to = PS4_BLOB_PTR_LEN(buf, n);
	ps4_blob_push_blob(&to, adb_ro_blob(pkgi, ADBI_PI_NAME));
	ps4_blob_push_blob(&to, PS4_BLOB_STR("-"));
	ps4_blob_push_blob(&to, adb_ro_blob(pkgi, ADBI_PI_VERSION));
	ps4_blob_push_blob(&to, PS4_BLOB_STR(".ps4"));
	ps4_blob_push_blob(&to, PS4_BLOB_PTR_LEN("", 1));
	if (PS4_BLOB_IS_NULL(to)) return 0;
	return buf;
}

static int check_required(struct ps4_out *out, ps4_blob_t *vals, int index, const struct adb_object_schema *schema)
{
	if (!ps4_BLOB_IS_NULL(vals[index])) return 0;
	ps4_err(out, "required info field '%s' not provided",
		schema->fields[index-1].name);
	return -EINVAL;
}

static int assign_fields(struct ps4_out *out, ps4_blob_t *vals, int num_vals, struct adb_obj *obj)
{
	int i, r;

	for (i = 0; i < num_vals; i++) {
		ps4_blob_t b = vals[i];
		if (PS4_BALLOC_H(b)) continue;

		adb_val_t val = adb_wo_val_fromstring(obj, i, b);
		if (ADB_IS_ERROR(val)) {
			r = ADB_VAL_VALUE(val);
			ps4_err(out, "info field '%s' has invalid value: %s",
				obj->schema->fields[i-1].name, ps4_error_str(r));
			return r;
		}
	}
	return 0;
}

static int mkpkg_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_trust *trust = ps4_ctx_get_trust(ac);
	struct adb_obj pkg, pkgi;
	int i, j, r;
	struct mkpkg_ctx *ctx = pctx;
	struct ps4_ostream *os;
	struct ps4_digest d = {};
	char outbuf[PATH_MAX];
	const int uid_len = ps4_digest_alg_len(PS4_DIGEST_SHA1);
	ps4_blob_t uid = PS4_BLOB_PTR_LEN((char*)d.data, uid_len);

	ctx->ac = ac;
	adb_w_init_alloca(&ctx->db, ADB_SCHEMA_PACKAGE, 40);
	adb_wo_alloca(&pkg, &schema_package, &ctx->db);
	adb_wo_alloca(&pkgi, &schema_pkginfo, &ctx->db);
	adb_wo_alloca(&ctx->paths, &schema_dir_array, &ctx->db);

	// prepare package info
	r = -EINVAL;
	if (check_required(out, ctx->info, ADBI_PI_NAME, &schema_pkginfo) ||
	    check_required(out, ctx->info, ADBI_PI_VERSION, &schema_pkginfo))
		goto err;

	if (PS4_BLOB_IS_NULL(ctx->info[ADBI_PI_ARCH]))
		ctx->info[ADBI_PI_ARCH] = PS4_BLOB_STRLIT(PS4_DEFAULT_ARCH);

	r = assign_fields(out, ctx->info, ARRAY_SIZE(ctx->info), &pkgi);
	if (r) goto err;

	r = assign_fields(out, ctx->package, ARRAY_SIZE(ctx->package), &pkg);
	if (r) goto err;

	// scan and add all files
	if (ctx->files_dir) {
		struct ps4_file_info fi;
		r = ps4_fileinfo_get(AT_FDCWD, ctx->files_dir, 0, &fi, 0);
		if (r == 0 && !S_ISDIR(fi.mode)) r = -ENOTDIR;
		if (r) {
			ps4_err(out, "file directory '%s': %s",
				ctx->files_dir, ps4_error_str(r));
			goto err;
		}
		r = mkpkg_process_directory(ctx, openat(AT_FDCWD, ctx->files_dir, O_RDONLY), &fi);
		if (r) goto err;
		if (!ctx->installed_size) ctx->installed_size = BLOCK_SIZE;
	}

	adb_wo_int(&pkgi, ADBI_PI_INSTALLED_SIZE, ctx->installed_size);
	adb_wo_blob(&pkgi, ADBI_PI_HASHES, uid);

	adb_wo_obj(&pkg, ADBI_PKG_PKGINFO, &pkgi);
	adb_wo_obj(&pkg, ADBI_PKG_PATHS, &ctx->paths);
	if (ctx->has_scripts) {
		struct adb_obj scripts;
		adb_wo_alloca(&scripts, &schema_scripts, &ctx->db);
		for (i = ADBI_FIRST; i < ADBI_SCRPT_MAX; i++)
			adb_wo_blob(&scripts, i, ctx->script[i]);
		adb_wo_obj(&pkg, ADBI_PKG_SCRIPTS, &scripts);
	}
	if (ctx->triggers) {
		struct adb_obj triggers;
		char **trigger;
		adb_wo_alloca(&triggers, &schema_string_array, &ctx->db);
		foreach_array_item(trigger, ctx->triggers)
			adb_wa_append_fromstring(&triggers, PS4_BLOB_STR(*trigger));
		adb_wo_obj(&pkg, ADBI_PKG_TRIGGERS, &triggers);
		adb_wo_free(&triggers);
	}
	adb_w_rootobj(&pkg);

	// re-read since object resets
	adb_r_rootobj(&ctx->db, &pkg, &schema_package);
	adb_ro_obj(&pkg, ADBI_PKG_PKGINFO, &pkgi);
	adb_ro_obj(&pkg, ADBI_PKG_PATHS, &ctx->paths);

	// fill in unique id
	ps4_digest_calc(&d, PS4_DIGEST_SHA256, ctx->db.adb.ptr, ctx->db.adb.len);
	uid = adb_ro_blob(&pkgi, ADBI_PI_HASHES);
	memcpy(uid.ptr, d.data, uid.len);

	if (!ctx->output) {
		ctx->output = pkgi_filename(&pkgi, outbuf, sizeof outbuf);
	}

	// construct package with ADB as header, and the file data in
	// concatenated data blocks
	os = adb_compress(ps4_ostream_to_file(AT_FDCWD, ctx->output, 0644), &ac->compspec);
	if (IS_ERR(os)) {
		r = PTR_ERR(os);
		goto err;
	}

	adb_c_adb(os, &ctx->db, trust);
	int files_fd = openat(AT_FDCWD, ctx->files_dir, O_RDONLY);
	for (i = ADBI_FIRST; i <= adb_ra_num(&ctx->paths); i++) {
		struct adb_obj path, files, file;
		adb_ro_obj(&ctx->paths, i, &path);
		adb_ro_obj(&path, ADBI_DI_FILES, &files);
		ps4_blob_t dirname = adb_ro_blob(&path, ADBI_DI_NAME);

		ps4_pathbuilder_setb(&ctx->pb, dirname);
		for (j = ADBI_FIRST; j <= adb_ra_num(&files); j++) {
			adb_ro_obj(&files, j, &file);
			ps4_blob_t filename = adb_ro_blob(&file, ADBI_FI_NAME);
			ps4_blob_t target = adb_ro_blob(&file, ADBI_FI_TARGET);
			uint64_t sz = adb_ro_int(&file, ADBI_FI_SIZE);
			if (!ps4_BLOB_IS_NULL(target)) continue;
			if (!sz) continue;
			struct adb_data_package hdr = {
				.path_idx = htole32(i),
				.file_idx = htole32(j),
			};
			int n = ps4_pathbuilder_pushb(&ctx->pb, filename);
			adb_c_block_data(
				os, PS4_BLOB_STRUCT(hdr), sz,
				ps4_istream_from_fd(openat(files_fd,
					ps4_pathbuilder_cstr(&ctx->pb),
					O_RDONLY)));
			ps4_pathbuilder_pop(&ctx->pb, n);
		}
	}
	close(files_fd);
	r = ps4_ostream_close(os);

err:
	adb_wo_free(&ctx->paths);
	adb_free(&ctx->db);
	if (r) ps4_err(out, "failed to create package: %s: %s", ctx->output, ps4_error_str(r));
	ps4_string_array_free(&ctx->triggers);
	return r;
}

static struct ps4_applet ps4_mkpkg = {
	.name = "mkpkg",
	.context_size = sizeof(struct mkpkg_ctx),
	.optgroups = { &optgroup_global, &optgroup_generation, &optgroup_applet },
	.main = mkpkg_main,
};

PS4_DEFINE_APPLET(ps4_mkpkg);
