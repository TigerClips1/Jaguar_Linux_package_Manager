/* ps4_hash.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_HASH_H
#define PS4_HASH_H

#include <stdlib.h>
#include <stddef.h>
#include "ps4_defines.h"
#include "ps4_blob.h"

typedef void *ps4_hash_item;

typedef unsigned long (*ps4_hash_f)(ps4_blob_t);
typedef int (*ps4_hash_compare_f)(ps4_blob_t, ps4_blob_t);
typedef int (*ps4_hash_compare_item_f)(ps4_hash_item, ps4_blob_t);
typedef void (*ps4_hash_delete_f)(ps4_hash_item);
typedef int (*ps4_hash_enumerator_f)(ps4_hash_item, void *ctx);

struct ps4_hash_ops {
	ptrdiff_t	node_offset;
	ps4_blob_t	(*get_key)(ps4_hash_item item);
	unsigned long	(*hash_key)(ps4_blob_t key);
	unsigned long	(*hash_item)(ps4_hash_item item);
	int		(*compare)(ps4_blob_t itemkey, ps4_blob_t key);
	int		(*compare_item)(ps4_hash_item item, ps4_blob_t key);
	void		(*delete_item)(ps4_hash_item item);
};

typedef struct hlist_node ps4_hash_node;
PS4_ARRAY(ps4_hash_array, struct hlist_head);

struct ps4_hash {
	const struct ps4_hash_ops *ops;
	struct ps4_hash_array *buckets;
	int num_items;
};

void ps4_hash_init(struct ps4_hash *h, const struct ps4_hash_ops *ops,
		   int num_buckets);
void ps4_hash_free(struct ps4_hash *h);

int ps4_hash_foreach(struct ps4_hash *h, ps4_hash_enumerator_f e, void *ctx);
ps4_hash_item ps4_hash_get_hashed(struct ps4_hash *h, ps4_blob_t key, unsigned long hash);
void ps4_hash_insert_hashed(struct ps4_hash *h, ps4_hash_item item, unsigned long hash);
void ps4_hash_delete_hashed(struct ps4_hash *h, ps4_blob_t key, unsigned long hash);

static inline unsigned long ps4_hash_from_key(struct ps4_hash *h, ps4_blob_t key)
{
	return h->ops->hash_key(key);
}

static inline unsigned long ps4_hash_from_item(struct ps4_hash *h, ps4_hash_item item)
{
	if (h->ops->hash_item != NULL)
		return h->ops->hash_item(item);
	return ps4_hash_from_key(h, h->ops->get_key(item));
}

static inline ps4_hash_item ps4_hash_get(struct ps4_hash *h, ps4_blob_t key)
{
	return ps4_hash_get_hashed(h, key, ps4_hash_from_key(h, key));
}

static inline void ps4_hash_insert(struct ps4_hash *h, ps4_hash_item item)
{
	return ps4_hash_insert_hashed(h, item, ps4_hash_from_item(h, item));
}

#endif
