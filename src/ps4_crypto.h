/* ps4_crypt.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_CRYPTO_H
#define PS4_CRYPTO_H

#include <string.h>
#include "ps4_defines.h"
#include "ps4_blob.h"

#if defined(CRYPTO_USE_OPENSSL)
#include "ps4_crypto_openssl.h"
#elif defined(CRYPTO_USE_MBEDTLS)
#include "ps4_crypto_mbedtls.h"
#else
#error Crypto backend not selected
#endif

// Digest

#define PS4_DIGEST_NONE		0x00
#define PS4_DIGEST_MD5		0x01
#define PS4_DIGEST_SHA1		0x02
#define PS4_DIGEST_SHA256	0x03
#define PS4_DIGEST_SHA512	0x04
#define PS4_DIGEST_SHA256_160	0x05

#define PS4_DIGEST_LENGTH_MD5		16
#define PS4_DIGEST_LENGTH_SHA1		20
#define PS4_DIGEST_LENGTH_SHA256_160	20
#define PS4_DIGEST_LENGTH_SHA256	32
#define PS4_DIGEST_LENGTH_SHA512	64
#define PS4_DIGEST_LENGTH_MAX		PS4_DIGEST_LENGTH_SHA512

/* Enough space for a hexdump of the longest checksum possible plus
 * a two-character type prefix */
#define PS4_BLOB_DIGEST_BUF	(2 + (2 * PS4_DIGEST_LENGTH_MAX))

const char *ps4_digest_alg_str(uint8_t);
uint8_t ps4_digest_alg_by_str(const char *algstr);

struct ps4_digest {
	uint8_t alg, len;
	uint8_t data[PS4_DIGEST_LENGTH_MAX];
};

#define PS4_DIGEST_BLOB(d) PS4_BLOB_PTR_LEN((void*)((d).data), (d).len)

int ps4_digest_alg_len(uint8_t alg);
uint8_t ps4_digest_alg_by_len(int len);
uint8_t ps4_digest_from_blob(struct ps4_digest *d, ps4_blob_t b);

int ps4_digest_calc(struct ps4_digest *d, uint8_t alg, const void *ptr, size_t sz);

static inline int ps4_digest_cmp(struct ps4_digest *a, struct ps4_digest *b) {
	if (a->alg != b->alg) return b->alg - a->alg;
	return memcmp(a->data, b->data, a->len);
}

static inline void ps4_digest_reset(struct ps4_digest *d) {
	d->alg = PS4_DIGEST_NONE;
	d->len = 0;
}

static inline void ps4_digest_set(struct ps4_digest *d, uint8_t alg) {
	d->alg = alg;
	d->len = ps4_digest_alg_len(alg);
}

static inline int ps4_digest_cmp_blob(const struct ps4_digest *d, uint8_t alg, const ps4_blob_t b) {
	if (d->alg != alg) return (int)alg - (int)d->alg;
	return ps4_blob_compare(PS4_DIGEST_BLOB(*d), b);
}

static inline void ps4_digest_push(ps4_blob_t *to, struct ps4_digest *digest) {
	return ps4_blob_push_hash(to, PS4_DIGEST_BLOB(*digest));
}

static inline void ps4_digest_push_hex(ps4_blob_t *to, struct ps4_digest *digest) {
	return ps4_blob_push_hash_hex(to, PS4_DIGEST_BLOB(*digest));
}

int ps4_digest_ctx_init(struct ps4_digest_ctx *dctx, uint8_t alg);
int ps4_digest_ctx_reset(struct ps4_digest_ctx *dctx);
int ps4_digest_ctx_reset_alg(struct ps4_digest_ctx *dctx, uint8_t alg);
void ps4_digest_ctx_free(struct ps4_digest_ctx *dctx);
int ps4_digest_ctx_update(struct ps4_digest_ctx *dctx, const void *ptr, size_t sz);
int ps4_digest_ctx_final(struct ps4_digest_ctx *dctx, struct ps4_digest *d);

// Asymmetric keys

void ps4_pkey_free(struct ps4_pkey *pkey);
int ps4_pkey_load(struct ps4_pkey *pkey, int dirfd, const char *fn, int priv);

// Signing

int ps4_sign_start(struct ps4_digest_ctx *, uint8_t, struct ps4_pkey *);
int ps4_sign(struct ps4_digest_ctx *, void *, size_t *);
int ps4_verify_start(struct ps4_digest_ctx *, uint8_t, struct ps4_pkey *);
int ps4_verify(struct ps4_digest_ctx *, void *, size_t);

// Initializiation

void ps4_crypto_init(void);

#endif
