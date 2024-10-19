/* atom.c - Alpine Package Keeper (ps4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ps4_atom.h"

ps4_blob_t ps4_atom_null = {0,""};

struct ps4_atom_hashnode {
	struct hlist_node hash_node;
	ps4_blob_t blob;
};

static ps4_blob_t atom_hash_get_key(ps4_hash_item item)
{
	return ((struct ps4_atom_hashnode *) item)->blob;
}

static struct ps4_hash_ops atom_ops = {
	.node_offset = offsetof(struct ps4_atom_hashnode, hash_node),
	.get_key = atom_hash_get_key,
	.hash_key = ps4_blob_hash,
	.compare = ps4_blob_compare,
};

void ps4_atom_init(struct ps4_atom_pool *atoms)
{
	ps4_balloc_init(&atoms->ba, 64*1024);
	ps4_hash_init(&atoms->hash, &atom_ops, 10000);
}

void ps4_atom_free(struct ps4_atom_pool *atoms)
{
	ps4_hash_free(&atoms->hash);
	ps4_balloc_destroy(&atoms->ba);
}

ps4_blob_t *ps4_atom_get(struct ps4_atom_pool *atoms, ps4_blob_t blob, int duplicate)
{
	struct ps4_atom_hashnode *atom;
	unsigned long hash = ps4_hash_from_key(&atoms->hash, blob);

	if (blob.len < 0 || !blob.ptr) return &ps4_atom_null;

	atom = (struct ps4_atom_hashnode *) ps4_hash_get_hashed(&atoms->hash, blob, hash);
	if (atom) return &atom->blob;

	if (duplicate) {
		char *ptr;
		atom = ps4_balloc_new_extra(&atoms->ba, struct ps4_atom_hashnode, blob.len + duplicate - 1);
		ptr = (char*) (atom + 1);
		memcpy(ptr, blob.ptr, blob.len);
		if (duplicate > 1) ptr[blob.len] = 0;
		atom->blob = PS4_BLOB_PTR_LEN(ptr, blob.len);
	} else {
		atom = ps4_balloc_new(&atoms->ba, struct ps4_atom_hashnode);
		atom->blob = blob;
	}
	ps4_hash_insert_hashed(&atoms->hash, atom, hash);
	return &atom->blob;
}
