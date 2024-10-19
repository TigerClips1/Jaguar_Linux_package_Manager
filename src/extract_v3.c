/* extract_v3.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/stat.h>

#include "ps4_context.h"
#include "ps4_extract.h"
#include "ps4_adb.h"
#include "ps4_pathbuilder.h"

struct ps4_extract_v3_ctx {
	struct ps4_extract_ctx *ectx;
	struct adb db;
	struct adb_obj pkg, paths, path, files, file;
	unsigned int cur_path, cur_file;
	struct ps4_pathbuilder pb;
};

static void ps4_extract_v3_acl(struct ps4_file_info *fi, struct adb_obj *o, struct ps4_id_cache *idc)
{
	struct adb_obj xa;
	ps4_blob_t x, key, value;
	int i;

	fi->mode = adb_ro_int(o, ADBI_ACL_MODE);
	fi->uid = ps4_id_cache_resolve_uid(idc, adb_ro_blob(o, ADBI_ACL_USER), 65534);
	fi->gid = ps4_id_cache_resolve_gid(idc, adb_ro_blob(o, ADBI_ACL_GROUP), 65534);

	adb_ro_obj(o, ADBI_ACL_XATTRS, &xa);

	ps4_xattr_array_resize(&fi->xattrs, 0, adb_ra_num(&xa));
	for (i = ADBI_FIRST; i <= adb_ra_num(&xa); i++) {
		x = adb_ro_blob(&xa, i);
		ps4_blob_split(x, PS4_BLOB_BUF(""), &key, &value);
		ps4_xattr_array_add(&fi->xattrs, (struct ps4_xattr) {
			.name = key.ptr,
			.value = value,
		});
	}
	ps4_fileinfo_hash_xattr(fi, PS4_DIGEST_SHA1);
}

static int ps4_extract_v3_file(struct ps4_extract_ctx *ectx, off_t sz, struct ps4_istream *is)
{
	struct ps4_extract_v3_ctx *ctx = ectx->pctx;
	const char *path_name = ps4_pathbuilder_cstr(&ctx->pb);
	struct ps4_file_info fi = {
		.name = path_name,
		.size = adb_ro_int(&ctx->file, ADBI_FI_SIZE),
		.mtime = adb_ro_int(&ctx->file, ADBI_FI_MTIME),
	};
	struct adb_obj acl;
	struct ps4_digest_istream dis;
	ps4_blob_t target;
	int r;

	ps4_xattr_array_init(&fi.xattrs);
	ps4_extract_v3_acl(&fi, adb_ro_obj(&ctx->file, ADBI_FI_ACL, &acl), ps4_ctx_get_id_cache(ectx->ac));

	target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
	if (!ps4_BLOB_IS_NULL(target)) {
		char *target_path;
		uint16_t mode;

		if (target.len < 2) goto err_schema;
		mode = le16toh(*(uint16_t*)target.ptr);
		target.ptr += 2;
		target.len -= 2;
		switch (mode) {
		case S_IFBLK:
		case S_IFCHR:
		case S_IFIFO:
			if (target.len != sizeof(uint64_t)) goto err_schema;
			struct unaligned64 {
				uint64_t value;
			} __attribute__((packed));
			fi.device = le64toh(((struct unaligned64 *)target.ptr)->value);
			break;
		case S_IFLNK:
			target_path = alloca(target.len + 1);
			memcpy(target_path, target.ptr, target.len);
			target_path[target.len] = 0;
			fi.link_target = target_path;
			break;
		default:
		err_schema:
			r = -PS4E_ADB_SCHEMA;
			goto done;
		}
		fi.mode |= mode;
		r = ectx->ops->file(ectx, &fi, is);
		goto done;
	}

	ps4_digest_from_blob(&fi.digest, adb_ro_blob(&ctx->file, ADBI_FI_HASHES));
	if (fi.digest.alg == PS4_DIGEST_NONE) goto err_schema;
	fi.mode |= S_IFREG;
	if (!is) {
		r = ectx->ops->file(ectx, &fi, 0);
		goto done;
	}

	r = ectx->ops->file(ectx, &fi, ps4_istream_verify(&dis, is, fi.size, &fi.digest));
	r = ps4_istream_close_error(&dis.is, r);
done:
	ps4_xattr_array_free(&fi.xattrs);
	return r;
}

static int ps4_extract_v3_directory(struct ps4_extract_ctx *ectx)
{
	struct ps4_extract_v3_ctx *ctx = ectx->pctx;
	struct ps4_file_info fi = {
		.name = ps4_pathbuilder_cstr(&ctx->pb),
	};
	struct adb_obj acl;
	int r;

	ps4_xattr_array_init(&fi.xattrs);
	ps4_extract_v3_acl(&fi, adb_ro_obj(&ctx->path, ADBI_DI_ACL, &acl), ps4_ctx_get_id_cache(ectx->ac));
	fi.mode |= S_IFDIR;
	r = ectx->ops->file(ectx, &fi, 0);
	ps4_xattr_array_free(&fi.xattrs);

	return r;
}

static int ps4_extract_v3_next_file(struct ps4_extract_ctx *ectx)
{
	struct ps4_extract_v3_ctx *ctx = ectx->pctx;
	ps4_blob_t target;
	int r, n;

	if (!ctx->cur_path) {
		// one time init
		ctx->cur_path = ADBI_FIRST;
		ctx->cur_file = ADBI_FIRST;
		adb_r_rootobj(&ctx->db, &ctx->pkg, &schema_package);

		r = ectx->ops->v3meta(ectx, &ctx->pkg);
		if (r < 0) return r;

		adb_ro_obj(&ctx->pkg, ADBI_PKG_PATHS, &ctx->paths);
		if (!ectx->ops->file) return -ECANCELED;
	} else {
		ctx->cur_file++;
		if (ctx->cur_file > adb_ra_num(&ctx->files)) {
			ctx->cur_path++;
			ctx->cur_file = ADBI_FIRST;
		}
	}

	for (; ctx->cur_path <= adb_ra_num(&ctx->paths); ctx->cur_path++, ctx->cur_file = ADBI_FIRST) {
		if (ctx->cur_file == ADBI_FIRST) {
			adb_ro_obj(&ctx->paths, ctx->cur_path, &ctx->path);
			adb_ro_obj(&ctx->path, ADBI_DI_FILES, &ctx->files);
		}
		ps4_pathbuilder_setb(&ctx->pb, adb_ro_blob(&ctx->path, ADBI_DI_NAME));
		if (ctx->pb.namelen != 0 && ctx->cur_file == ADBI_FIRST) {
			r = ps4_extract_v3_directory(ectx);
			if (r != 0) return r;
		}

		for (; ctx->cur_file <= adb_ra_num(&ctx->files); ctx->cur_file++) {
			adb_ro_obj(&ctx->files, ctx->cur_file, &ctx->file);

			n = ps4_pathbuilder_pushb(&ctx->pb, adb_ro_blob(&ctx->file, ADBI_FI_NAME));

			target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
			if (adb_ro_int(&ctx->file, ADBI_FI_SIZE) != 0 && PS4_BLOB_IS_NULL(target))
				return 0;

			r = ps4_extract_v3_file(ectx, 0, 0);
			if (r != 0) return r;

			ps4_pathbuilder_pop(&ctx->pb, n);
		}
	}
	return 1;
}

static int ps4_extract_v3_data_block(struct adb *db, struct adb_block *b, struct ps4_istream *is)
{
	struct ps4_extract_v3_ctx *ctx = container_of(db, struct ps4_extract_v3_ctx, db);
	struct ps4_extract_ctx *ectx = ctx->ectx;
	struct adb_data_package *hdr;
	uint64_t sz = adb_block_length(b);
	int r;

	if (adb_block_type(b) != ADB_BLOCK_DATA) return 0;
	if (db->schema != ADB_SCHEMA_PACKAGE) return -PS4E_ADB_SCHEMA;
	if (!ectx->ops->v3meta) return -PS4E_FORMAT_NOT_SUPPORTED;

	r = ps4_extract_v3_next_file(ectx);
	if (r != 0) {
		if (r > 0) r = -PS4E_ADB_BLOCK;
		return r;
	}

	hdr = ps4_istream_get(is, sizeof *hdr);
	sz -= sizeof *hdr;
	if (IS_ERR(hdr)) return PTR_ERR(hdr);

	if (le32toh(hdr->path_idx) != ctx->cur_path ||
	    le32toh(hdr->file_idx) != ctx->cur_file ||
	    sz != adb_ro_int(&ctx->file, ADBI_FI_SIZE)) {
		// got data for some unexpected file
		return -PS4E_ADB_BLOCK;
	}

	return ps4_extract_v3_file(ectx, sz, is);
}

static int ps4_extract_v3_verify_index(struct ps4_extract_ctx *ectx, struct adb_obj *obj)
{
	return 0;
}

static int ps4_extract_v3_verify_meta(struct ps4_extract_ctx *ectx, struct adb_obj *obj)
{
	return 0;
}

static int ps4_extract_v3_verify_file(struct ps4_extract_ctx *ectx, const struct ps4_file_info *fi, struct ps4_istream *is)
{
	if (is) {
		ps4_istream_read(is, 0, fi->size);
		return ps4_istream_close(is);
	}
	return 0;
}

static const struct ps4_extract_ops extract_v3verify_ops = {
	.v3index = ps4_extract_v3_verify_index,
	.v3meta = ps4_extract_v3_verify_meta,
	.file = ps4_extract_v3_verify_file,
};

int ps4_extract_v3(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	struct ps4_ctx *ac = ectx->ac;
	struct ps4_trust *trust = ps4_ctx_get_trust(ac);
	struct ps4_extract_v3_ctx ctx = {
		.ectx = ectx,
	};
	struct adb_obj obj;
	int r;

	if (IS_ERR(is)) return PTR_ERR(is);
	if (!ectx->ops) ectx->ops = &extract_v3verify_ops;
	if (!ectx->ops->v3meta && !ectx->ops->v3index)
		return ps4_istream_close_error(is, -PS4E_FORMAT_NOT_SUPPORTED);

	ectx->pctx = &ctx;
	r = adb_m_process(&ctx.db, adb_decompress(is, 0),
		ADB_SCHEMA_ANY, trust, ectx, ps4_extract_v3_data_block);
	if (r == 0) {
		switch (ctx.db.schema) {
		case ADB_SCHEMA_PACKAGE:
			r = ps4_extract_v3_next_file(ectx);
			if (r == 0) r = -PS4E_ADB_BLOCK;
			if (r == 1) r = 0;
			break;
		case ADB_SCHEMA_INDEX:
			if (!ectx->ops->v3index) {
				r = -PS4E_FORMAT_NOT_SUPPORTED;
				break;
			}
			adb_r_rootobj(&ctx.db, &obj, &schema_index);
			r = ectx->ops->v3index(ectx, &obj);
			break;
		default:
			r = -PS4E_ADB_SCHEMA;
			break;
		}
	}
	if (r == -ECANCELED) r = 0;
	if (r == 0 && !ctx.db.adb.len) r = -PS4E_ADB_BLOCK;
	adb_free(&ctx.db);
	ps4_extract_reset(ectx);

	return r;
}

int ps4_extract(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	void *sig;

	if (IS_ERR(is)) return PTR_ERR(is);

	sig = ps4_istream_peek(is, 4);
	if (IS_ERR(sig)) return ps4_istream_close_error(is, PTR_ERR(sig));

	if (memcmp(sig, "ADB", 3) == 0) return ps4_extract_v3(ectx, is);
	return ps4_extract_v2(ectx, is);
}
