/* ps4_trust.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_TRUST
#define PS4_TRUST

#include "ps4_blob.h"
#include "ps4_crypto.h"

struct ps4_trust_key {
	struct list_head key_node;
	struct ps4_pkey key;
	char *filename;

};

struct ps4_trust {
	struct ps4_digest_ctx dctx;
	struct list_head trusted_key_list;
	struct list_head private_key_list;
	unsigned int allow_untrusted : 1;
	unsigned int keys_loaded : 1;
};

void ps4_trust_init(struct ps4_trust *trust);
void ps4_trust_free(struct ps4_trust *trust);
int ps4_trust_load_keys(struct ps4_trust *trust, int keysfd);
struct ps4_trust_key *ps4_trust_load_key(int dirfd, const char *filename, int priv);
struct ps4_pkey *ps4_trust_key_by_name(struct ps4_trust *trust, const char *filename);

#endif
