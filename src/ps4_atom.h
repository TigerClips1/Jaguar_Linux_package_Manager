/* ps4_atom.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_ATOM_H
#define PS4_ATOM_H

#include "ps4_hash.h"
#include "ps4_blob.h"
#include "ps4_balloc.h"

extern ps4_blob_t ps4_atom_null;

struct ps4_atom_pool {
	struct ps4_balloc ba;
	struct ps4_hash hash;
};

void ps4_atom_init(struct ps4_atom_pool *);
void ps4_atom_free(struct ps4_atom_pool *);
ps4_blob_t *ps4_atom_get(struct ps4_atom_pool *atoms, ps4_blob_t blob, int duplicate);

static inline ps4_blob_t *ps4_atomize(struct ps4_atom_pool *atoms, ps4_blob_t blob) {
	return ps4_atom_get(atoms, blob, 0);
}
static inline ps4_blob_t *ps4_atomize_dup(struct ps4_atom_pool *atoms, ps4_blob_t blob) {
	return ps4_atom_get(atoms, blob, 1);
}
static inline ps4_blob_t *ps4_atomize_dup0(struct ps4_atom_pool *atoms, ps4_blob_t blob) {
	return ps4_atom_get(atoms, blob, 2);
}

#endif
