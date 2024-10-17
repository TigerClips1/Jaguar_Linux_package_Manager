/* ps4_extract.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_EXTRACT
#define PS4_EXTRACT

#include "ps4_crypto.h"
#include "ps4_print.h"
#include "ps4_io.h"

struct adb_obj;
struct ps4_ctx;
struct ps4_extract_ctx;

struct ps4_extract_ops {
	int (*v2index)(struct ps4_extract_ctx *, ps4_blob_t *desc, struct ps4_istream *is);
	int (*v2meta)(struct ps4_extract_ctx *, struct ps4_istream *is);
	int (*v3index)(struct ps4_extract_ctx *, struct adb_obj *);
	int (*v3meta)(struct ps4_extract_ctx *, struct adb_obj *);
	int (*script)(struct ps4_extract_ctx *, unsigned int script, size_t size, struct ps4_istream *is);
	int (*file)(struct ps4_extract_ctx *, const struct ps4_file_info *fi, struct ps4_istream *is);
};

struct ps4_extract_ctx {
	struct ps4_ctx *ac;
	const struct ps4_extract_ops *ops;
	struct ps4_digest *generate_identity;
	uint8_t generate_alg, verify_alg;
	ps4_blob_t verify_digest;
	ps4_blob_t desc;
	void *pctx;
	unsigned is_package : 1;
	unsigned is_index : 1;
};

static inline void ps4_extract_init(struct ps4_extract_ctx *ectx, struct ps4_ctx *ac, const struct ps4_extract_ops *ops) {
	*ectx = (struct ps4_extract_ctx){.ac = ac, .ops = ops};
}
static inline void ps4_extract_reset(struct ps4_extract_ctx *ectx) {
	ps4_extract_init(ectx, ectx->ac, ectx->ops);
}
static inline void ps4_extract_generate_identity(struct ps4_extract_ctx *ctx, uint8_t alg, struct ps4_digest *id) {
	ctx->generate_alg = alg;
	ctx->generate_identity = id;
}
static inline void ps4_extract_verify_identity(struct ps4_extract_ctx *ctx, uint8_t alg, ps4_blob_t digest) {
	ctx->verify_alg = alg;
	ctx->verify_digest = digest;
}
int ps4_extract(struct ps4_extract_ctx *, struct ps4_istream *is);

int ps4_extract_v2(struct ps4_extract_ctx *, struct ps4_istream *is);
void ps4_extract_v2_control(struct ps4_extract_ctx *, ps4_blob_t, ps4_blob_t);
int ps4_extract_v2_meta(struct ps4_extract_ctx *ectx, struct ps4_istream *is);

int ps4_extract_v3(struct ps4_extract_ctx *, struct ps4_istream *is);

#endif
