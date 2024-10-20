/* app_manifest.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2017 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2017 Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2017 William Pitcock <nenolod@dereferenced.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <sys/stat.h>

#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_extract.h"
#include "ps4_version.h"
#include "ps4_print.h"
#include "ps4_adb.h"
#include "ps4_pathbuilder.h"

/* TODO: support package files as well as generating manifest from the installed DB. */

static void process_package(struct ps4_database *db, struct ps4_package *pkg)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_installed_package *ipkg = pkg->ipkg;
	struct ps4_db_dir_instance *diri;
	struct ps4_db_file *file;
	struct hlist_node *dc, *dn, *fc, *fn;
	const char *prefix1 = "", *prefix2 = "";
	char csum_buf[PS4_BLOB_DIGEST_BUF];

	if (ipkg == NULL)
		return;

	if (ps4_out_verbosity(out) > 1) {
		prefix1 = pkg->name->name;
		prefix2 = ": ";
	}

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs,
				  pkg_dirs_list) {
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files,
					  diri_files_list) {
			ps4_blob_t csum_blob = PS4_BLOB_BUF(csum_buf);
			memset(csum_buf, '\0', sizeof(csum_buf));
			ps4_blob_push_hexdump(&csum_blob, ps4_dbf_digest_blob(file));

			ps4_out(out, "%s%s%s:%s  " DIR_FILE_FMT,
				prefix1, prefix2,
				ps4_digest_alg_str(file->digest_alg),
				csum_buf, DIR_FILE_PRINTF(diri->dir, file));
		}
	}
}

struct manifest_file_ctx {
	struct ps4_out *out;
	struct ps4_extract_ctx ectx;
	const char *prefix1, *prefix2;
};

static int process_pkg_file(struct ps4_extract_ctx *ectx, const struct ps4_file_info *fi, struct ps4_istream *is)
{
	struct manifest_file_ctx *mctx = container_of(ectx, struct manifest_file_ctx, ectx);
	struct ps4_out *out = mctx->out;
	char csum_buf[PS4_BLOB_DIGEST_BUF];
	ps4_blob_t csum_blob = PS4_BLOB_BUF(csum_buf);

	if ((fi->mode & S_IFMT) != S_IFREG) return 0;

	memset(csum_buf, '\0', sizeof(csum_buf));
	ps4_blob_push_hexdump(&csum_blob, PS4_DIGEST_BLOB(fi->digest));

	ps4_out(out, "%s%s%s:%s  %s",
		mctx->prefix1, mctx->prefix2,
		ps4_digest_alg_str(fi->digest.alg), csum_buf,
		fi->name);

	return 0;
}

static int process_v3_meta(struct ps4_extract_ctx *ectx, struct adb_obj *pkg)
{
	struct manifest_file_ctx *mctx = container_of(ectx, struct manifest_file_ctx, ectx);
	struct ps4_out *out = mctx->out;
	struct adb_obj paths, path, files, file;
	struct ps4_digest digest;
	struct ps4_pathbuilder pb;
	char buf[PS4_DIGEST_LENGTH_MAX*2+1];
	ps4_blob_t hex;
	int i, j, n;

	adb_ro_obj(pkg, ADBI_PKG_PATHS, &paths);

	for (i = ADBI_FIRST; i <= adb_ra_num(&paths); i++) {
		adb_ro_obj(&paths, i, &path);
		adb_ro_obj(&path, ADBI_DI_FILES, &files);
		ps4_pathbuilder_setb(&pb, adb_ro_blob(&path, ADBI_DI_NAME));

		for (j = ADBI_FIRST; j <= adb_ra_num(&files); j++) {
			adb_ro_obj(&files, j, &file);
			n = ps4_pathbuilder_pushb(&pb, adb_ro_blob(&file, ADBI_FI_NAME));
			ps4_digest_from_blob(&digest, adb_ro_blob(&file, ADBI_FI_HASHES));

			hex = PS4_BLOB_BUF(buf);
			ps4_blob_push_hexdump(&hex, PS4_DIGEST_BLOB(digest));
			ps4_blob_push_blob(&hex, PS4_BLOB_STRLIT("\0"));

			ps4_out(out, "%s%s%s:%s  %s",
				mctx->prefix1, mctx->prefix2,
				ps4_digest_alg_str(digest.alg), buf,
				ps4_pathbuilder_cstr(&pb));
			ps4_pathbuilder_pop(&pb, n);
		}
	}

	return -ECANCELED;
}

static const struct ps4_extract_ops extract_manifest_ops = {
	.v2meta = ps4_extract_v2_meta,
	.v3meta = process_v3_meta,
	.file = process_pkg_file,
};

static void process_file(struct ps4_database *db, const char *match)
{
	struct ps4_out *out = &db->ctx->out;
	struct manifest_file_ctx ctx = {
		.out = out,
		.prefix1 = "",
		.prefix2 = "",
	};
	int r;

	ps4_extract_init(&ctx.ectx, db->ctx, &extract_manifest_ops);
	if (ps4_out_verbosity(out) > 1) {
		ctx.prefix1 = match;
		ctx.prefix2 = ": ";
	}

	r = ps4_extract(&ctx.ectx, ps4_istream_from_file(AT_FDCWD, match));
	if (r < 0 && r != -ECANCELED) ps4_err(out, "%s: %s", match, ps4_error_str(r));
}

static int process_match(struct ps4_database *db, const char *match, struct ps4_name *name, void *ctx)
{
	struct ps4_provider *p;

	if (!name) {
		process_file(db, match);
		return 0;
	}

	ps4_name_sorted_providers(name);
	foreach_array_item(p, name->providers) {
		if (p->pkg->name != name) continue;
		process_package(db, p->pkg);
	}
	return 0;
}

static int manifest_main(void *applet_ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	if (ps4_array_len(args) == 0) return 0;
	ps4_db_foreach_sorted_name(ac->db, args, process_match, NULL);
	return 0;
}

static struct ps4_applet ps4_manifest = {
	.name = "manifest",
	.open_flags = PS4_OPENF_READ,
	.main = manifest_main,
};

PS4_DEFINE_APPLET(ps4_manifest);
