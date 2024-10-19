/* extract_v2.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ps4_context.h"
#include "ps4_extract.h"
#include "ps4_package.h"
#include "ps4_crypto.h"
#include "ps4_tar.h"

#define PS4_SIGN_VERIFY			1
#define PS4_SIGN_VERIFY_IDENTITY	2
#define PS4_SIGN_VERIFY_AND_GENERATE	3

struct ps4_sign_ctx {
	struct ps4_extract_ctx *ectx;
	struct ps4_trust *trust;
	int action;
	int num_signatures;
	int verify_error;
	unsigned char control_started : 1;
	unsigned char data_started : 1;
	unsigned char has_data_checksum : 1;
	unsigned char control_verified : 1;
	unsigned char data_verified : 1;
	unsigned char allow_untrusted : 1;
	unsigned char end_seen : 1;
	uint8_t alg;
	struct ps4_digest data_hash;
	struct ps4_digest_ctx digest_ctx;
	struct ps4_digest_ctx identity_ctx;

	struct {
		ps4_blob_t data;
		struct ps4_pkey *pkey;
		char *identity;
	} signature;
};

static void ps4_sign_ctx_init(struct ps4_sign_ctx *ctx, int action, struct ps4_extract_ctx *ectx, struct ps4_trust *trust)
{
	memset(ctx, 0, sizeof(struct ps4_sign_ctx));
	ctx->trust = trust;
	ctx->action = action;
	ctx->allow_untrusted = trust->allow_untrusted;
	ctx->verify_error = -PS4E_SIGNATURE_UNTRUSTED;
	ctx->alg = PS4_DIGEST_SHA1;
	ctx->ectx = ectx;
	switch (action) {
	case PS4_SIGN_VERIFY_AND_GENERATE:
		ps4_digest_ctx_init(&ctx->identity_ctx, PS4_DIGEST_SHA1);
		break;
	case PS4_SIGN_VERIFY:
	case PS4_SIGN_VERIFY_IDENTITY:
		break;
	default:
		assert(!"unreachable");
		break;
	}
	ps4_digest_ctx_init(&ctx->digest_ctx, ctx->alg);
}

static void ps4_sign_ctx_free(struct ps4_sign_ctx *ctx)
{
	free(ctx->signature.data.ptr);
	ps4_digest_ctx_free(&ctx->identity_ctx);
	ps4_digest_ctx_free(&ctx->digest_ctx);
}

static int check_signing_key_trust(struct ps4_sign_ctx *sctx)
{
	switch (sctx->action) {
	case PS4_SIGN_VERIFY:
	case PS4_SIGN_VERIFY_AND_GENERATE:
		if (sctx->signature.pkey == NULL) {
			if (sctx->allow_untrusted)
				break;
			return -PS4E_SIGNATURE_UNTRUSTED;
		}
	}
	return 0;
}

static int ps4_sign_ctx_process_file(struct ps4_sign_ctx *ctx, const struct ps4_file_info *fi,
		struct ps4_istream *is)
{
	static struct {
		char type[7];
		uint8_t alg;
	} signature_type[] = {
		{ "RSA512", PS4_DIGEST_SHA512 },
		{ "RSA256", PS4_DIGEST_SHA256 },
		{ "RSA", PS4_DIGEST_SHA1 },
		{ "DSA", PS4_DIGEST_SHA1 },
	};
	uint8_t alg = PS4_DIGEST_NONE;
	const char *name = NULL;
	struct ps4_pkey *pkey;
	int r, i;

	if (ctx->data_started)
		return 1;

	if (fi->name[0] != '.' || strchr(fi->name, '/') != NULL) {
		/* ps4v1.0 compatibility - first non-hidden file is
		 * considered to start the data section of the file.
		 * This does not make any sense if the file has v2.0
		 * style .PKGINFO */
		if (ctx->has_data_checksum)
			return -PS4E_V2PKG_FORMAT;
		/* Error out early if identity part is missing */
		if (ctx->action == PS4_SIGN_VERIFY_IDENTITY)
			return -PS4E_V2PKG_FORMAT;
		ctx->data_started = 1;
		ctx->control_started = 1;
		r = check_signing_key_trust(ctx);
		if (r != 0) return r;
		return 1;
	}

	if (ctx->control_started)
		return 1;

	if (strncmp(fi->name, ".SIGN.", 6) != 0) {
		ctx->control_started = 1;
		return 1;
	}

	/* By this point, we must be handling a signature file */
	ctx->num_signatures++;

	/* Already found a signature by a trusted key; no need to keep searching */
	if (ctx->signature.pkey != NULL) return 0;
	if (ctx->action == PS4_SIGN_VERIFY_IDENTITY) return 0;

	for (i = 0; i < ARRAY_SIZE(signature_type); i++) {
		size_t slen = strlen(signature_type[i].type);
		if (strncmp(&fi->name[6], signature_type[i].type, slen) == 0 &&
		    fi->name[6+slen] == '.') {
			alg = signature_type[i].alg;
			name = &fi->name[6+slen+1];
			break;
		}
	}
	if (alg == PS4_DIGEST_NONE) return 0;

	pkey = ps4_trust_key_by_name(ctx->trust, name);
	if (pkey) {
		ctx->alg = alg;
		ctx->signature.pkey = pkey;
		ps4_blob_from_istream(is, fi->size, &ctx->signature.data);
	}
	return 0;
}


/*	ps4_sign_ctx_mpart_cb() handles hashing archives and checking signatures, but
	it can't do it alone. ps4_sign_ctx_process_file() must be in the loop to
	actually select which signature is to be verified and load the corresponding
	public key into the context object, and	ps4_sign_ctx_parse_pkginfo_line()
	needs to be called when handling the .PKGINFO file to find any applicable
	datahash and load it into the context for this function to check against. */
static int ps4_sign_ctx_mpart_cb(void *ctx, int part, ps4_blob_t data)
{
	struct ps4_sign_ctx *sctx = (struct ps4_sign_ctx *) ctx;
	struct ps4_digest calculated;
	int r, end_of_control;

	if (sctx->end_seen || sctx->data_verified) return -PS4E_FORMAT_INVALID;
	if (part == PS4_MPART_BOUNDARY && sctx->data_started) return -PS4E_FORMAT_INVALID;
	if (part == PS4_MPART_END) sctx->end_seen = 1;
	if (part == PS4_MPART_DATA) {
		/* Update digest with the data now. Only _DATA callbacks can have data. */
		r = ps4_digest_ctx_update(&sctx->digest_ctx, data.ptr, data.len);
		if (r != 0) return r;

		/* Update identity generated also if needed. */
		if (sctx->control_started && !sctx->data_started &&
		    sctx->identity_ctx.alg != PS4_DIGEST_NONE) {
			r = ps4_digest_ctx_update(&sctx->identity_ctx, data.ptr, data.len);
			if (r != 0) return r;
		}
		return 0;
	}
	if (data.len) return -PS4E_FORMAT_INVALID;

	/* Still in signature blocks? */
	if (!sctx->control_started) {
		if (part == PS4_MPART_END) return -PS4E_FORMAT_INVALID;

		r = ps4_digest_ctx_reset(&sctx->identity_ctx);
		if (r != 0) return r;

		/* Control block starting, prepare for signature verification */
		if (sctx->signature.pkey == NULL || sctx->action == PS4_SIGN_VERIFY_IDENTITY)
			return ps4_digest_ctx_reset_alg(&sctx->digest_ctx, sctx->alg);

		return ps4_verify_start(&sctx->digest_ctx, sctx->alg, sctx->signature.pkey);
	}

	/* Grab state and mark all remaining block as data */
	end_of_control = (sctx->data_started == 0);
	sctx->data_started = 1;

	/* End of control-block and control does not have data checksum? */
	if (sctx->has_data_checksum == 0 && end_of_control && part != PS4_MPART_END)
		return 0;

	if (sctx->has_data_checksum && !end_of_control) {
		/* End of data-block with a checksum read from the control block */
		r = ps4_digest_ctx_final(&sctx->digest_ctx, &calculated);
		if (r != 0) return r;
		if (ps4_digest_cmp(&calculated, &sctx->data_hash) != 0)
			return -PS4E_V2PKG_INTEGRITY;
		sctx->data_verified = 1;
		if (!sctx->allow_untrusted && !sctx->control_verified)
			return -PS4E_SIGNATURE_UNTRUSTED;
		return 0;
	}

	/* Either end of control block with a data checksum or end
	 * of the data block following a control block without a data
	 * checksum. In either case, we're checking a signature. */
	r = check_signing_key_trust(sctx);
	if (r != 0) return r;

	switch (sctx->action) {
	case PS4_SIGN_VERIFY_AND_GENERATE:
		/* Package identity is the checksum */
		ps4_digest_ctx_final(&sctx->identity_ctx, sctx->ectx->generate_identity);
		if (!sctx->has_data_checksum) return -PS4E_V2PKG_FORMAT;
		/* Fallthrough to check signature */
	case PS4_SIGN_VERIFY:
		if (sctx->signature.pkey != NULL) {
			sctx->verify_error = ps4_verify(&sctx->digest_ctx,
				(unsigned char *) sctx->signature.data.ptr,
				sctx->signature.data.len);
		}
		if (sctx->verify_error) {
			if (sctx->verify_error != -PS4E_SIGNATURE_UNTRUSTED ||
			    !sctx->allow_untrusted)
				return sctx->verify_error;
		}
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == PS4_MPART_END)
			sctx->data_verified = 1;
		break;
	case PS4_SIGN_VERIFY_IDENTITY:
		/* Reset digest for hashing data */
		ps4_digest_ctx_final(&sctx->digest_ctx, &calculated);
		if (ps4_digest_cmp_blob(&calculated, sctx->ectx->verify_alg, sctx->ectx->verify_digest) != 0)
			return -PS4E_V2PKG_INTEGRITY;
		sctx->verify_error = 0;
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == PS4_MPART_END)
			sctx->data_verified = 1;
		break;
	}

	r = ps4_digest_ctx_reset(&sctx->identity_ctx);
	if (r != 0) return r;

	return ps4_digest_ctx_reset_alg(&sctx->digest_ctx, sctx->alg);
}

static int ps4_extract_verify_v2index(struct ps4_extract_ctx *ectx, ps4_blob_t *desc, struct ps4_istream *is)
{
	return 0;
}

static int ps4_extract_verify_v2file(struct ps4_extract_ctx *ectx, const struct ps4_file_info *fi, struct ps4_istream *is)
{
	return 0;
}

static const struct ps4_extract_ops extract_v2verify_ops = {
	.v2index = ps4_extract_verify_v2index,
	.v2meta = ps4_extract_v2_meta,
	.file = ps4_extract_verify_v2file,
};

static int ps4_extract_v2_entry(void *pctx, const struct ps4_file_info *fi, struct ps4_istream *is)
{
	struct ps4_extract_ctx *ectx = pctx;
	struct ps4_sign_ctx *sctx = ectx->pctx;
	int r, type;

	r = ps4_sign_ctx_process_file(sctx, fi, is);
	if (r <= 0) return r;

	if (!sctx->control_started) return 0;
	if (!sctx->data_started || !sctx->has_data_checksum) {
		if (fi->name[0] == '.') {
			ectx->is_package = 1;
			if (ectx->is_index) return -PS4E_V2NDX_FORMAT;
			if (!ectx->ops->v2meta) return -PS4E_FORMAT_NOT_SUPPORTED;
			if (strcmp(fi->name, ".PKGINFO") == 0) {
				return ectx->ops->v2meta(ectx, is);
			} else if (strcmp(fi->name, ".INSTALL") == 0) {
				return -PS4E_V2PKG_FORMAT;
			} else if ((type = ps4_script_type(&fi->name[1])) != PS4_SCRIPT_INVALID) {
				if (ectx->ops->script) return ectx->ops->script(ectx, type, fi->size, is);
			}
		} else {
			ectx->is_index = 1;
			if (ectx->is_package) return -PS4E_V2PKG_FORMAT;
			if (!ectx->ops->v2index) return -PS4E_FORMAT_NOT_SUPPORTED;
			if (strcmp(fi->name, "DESCRIPTION") == 0) {
				free(ectx->desc.ptr);
				ps4_blob_from_istream(is, fi->size, &ectx->desc);
			} else if (strcmp(fi->name, "ps4INDEX") == 0) {
				return ectx->ops->v2index(ectx, &ectx->desc, is);
			}
		}
		return 0;
	}

	if (!sctx->data_started) return 0;
	if (!ectx->ops->file) return -ECANCELED;
	return ectx->ops->file(ectx, fi, is);
}

int ps4_extract_v2(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	struct ps4_ctx *ac = ectx->ac;
	struct ps4_trust *trust = ps4_ctx_get_trust(ac);
	struct ps4_sign_ctx sctx;
	int r, action;

	if (ectx->generate_identity)
		action = PS4_SIGN_VERIFY_AND_GENERATE;
	else if (ectx->verify_alg != PS4_DIGEST_NONE)
		action = PS4_SIGN_VERIFY_IDENTITY;
	else
		action = PS4_SIGN_VERIFY;

	if (!ectx->ops) ectx->ops = &extract_v2verify_ops;
	ectx->pctx = &sctx;
	ps4_sign_ctx_init(&sctx, action, ectx, trust);
	r = ps4_tar_parse(
		ps4_istream_gunzip_mpart(is, ps4_sign_ctx_mpart_cb, &sctx),
		ps4_extract_v2_entry, ectx, ps4_ctx_get_id_cache(ac));
	if ((r == 0 || r == -ECANCELED || r == -PS4E_EOF) && !ectx->is_package && !ectx->is_index)
		r = -PS4E_FORMAT_INVALID;
	if (r == 0 && (!sctx.data_verified || !sctx.end_seen)) r = -PS4E_V2PKG_INTEGRITY;
	if ((r == 0 || r == -ECANCELED) && sctx.verify_error) r = sctx.verify_error;
	if (r == -PS4E_SIGNATURE_UNTRUSTED && sctx.allow_untrusted) r = 0;
	ps4_sign_ctx_free(&sctx);
	free(ectx->desc.ptr);
	ps4_extract_reset(ectx);

	return r;
}

void ps4_extract_v2_control(struct ps4_extract_ctx *ectx, ps4_blob_t l, ps4_blob_t r)
{
	struct ps4_sign_ctx *sctx = ectx->pctx;

	if (!sctx || !sctx->control_started || sctx->data_started) return;

	if (ps4_blob_compare(PS4_BLOB_STR("datahash"), l) == 0) {
		sctx->has_data_checksum = 1;
		sctx->alg = PS4_DIGEST_SHA256;
		ps4_digest_set(&sctx->data_hash, sctx->alg);
		ps4_blob_pull_hexdump(&r, PS4_DIGEST_BLOB(sctx->data_hash));
	}
}

int ps4_extract_v2_meta(struct ps4_extract_ctx *ectx, struct ps4_istream *is)
{
	ps4_blob_t k, v, token = PS4_BLOB_STRLIT("\n");
	while (ps4_istream_get_delim(is, token, &k) == 0) {
		if (k.len < 1 || k.ptr[0] == '#') continue;
		if (ps4_blob_split(k, PS4_BLOB_STRLIT(" = "), &k, &v)) {
			ps4_extract_v2_control(ectx, k, v);
		}
	}
	return 0;
}

