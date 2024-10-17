/* ps4_crypto_openssl.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_CRYPTO_OPENSSL_H
#define PS4_CRYPTO_OPENSSL_H

#include <openssl/evp.h>

struct ps4_digest_ctx {
	EVP_MD_CTX *mdctx;
	uint8_t alg;
};

struct ps4_pkey {
	uint8_t id[16];
	EVP_PKEY *key;
};

#endif
