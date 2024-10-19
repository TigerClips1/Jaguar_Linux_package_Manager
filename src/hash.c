/* hash.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ps4_defines.h"
#include "ps4_hash.h"

void ps4_hash_init(struct ps4_hash *h, const struct ps4_hash_ops *ops,
		   int num_buckets)
{
	h->ops = ops;
	ps4_hash_array_init(&h->buckets);
	ps4_hash_array_resize(&h->buckets, num_buckets, num_buckets);
	h->num_items = 0;
}

void ps4_hash_free(struct ps4_hash *h)
{
	if (h->ops->delete_item) ps4_hash_foreach(h, (ps4_hash_enumerator_f) h->ops->delete_item, NULL);
	ps4_hash_array_free(&h->buckets);
}

int ps4_hash_foreach(struct ps4_hash *h, ps4_hash_enumerator_f e, void *ctx)
{
	struct hlist_head *bucket;
	ps4_hash_node *pos, *n;
	ptrdiff_t offset = h->ops->node_offset;
	int r;

	foreach_array_item(bucket, h->buckets) {
		hlist_for_each_safe(pos, n, bucket) {
			r = e(((void *) pos) - offset, ctx);
			if (r != 0 && ctx != NULL)
				return r;
		}
	}

	return 0;
}

ps4_hash_item ps4_hash_get_hashed(struct ps4_hash *h, ps4_blob_t key, unsigned long hash)
{
	ptrdiff_t offset = h->ops->node_offset;
	ps4_hash_node *pos;
	ps4_hash_item item;
	ps4_blob_t itemkey;

	hash %= ps4_array_len(h->buckets);
	if (h->ops->compare_item != NULL) {
		hlist_for_each(pos, &h->buckets->item[hash]) {
			item = ((void *) pos) - offset;
			if (h->ops->compare_item(item, key) == 0)
				return item;
		}
	} else {
		hlist_for_each(pos, &h->buckets->item[hash]) {
			item = ((void *) pos) - offset;
			itemkey = h->ops->get_key(item);
			if (h->ops->compare(key, itemkey) == 0)
				return item;
		}
	}

	return NULL;
}

void ps4_hash_insert_hashed(struct ps4_hash *h, ps4_hash_item item, unsigned long hash)
{
	ps4_hash_node *node;

	hash %= ps4_array_len(h->buckets);
	node = (ps4_hash_node *) (item + h->ops->node_offset);
	hlist_add_head(node, &h->buckets->item[hash]);
	h->num_items++;
}

void ps4_hash_delete_hashed(struct ps4_hash *h, ps4_blob_t key, unsigned long hash)
{
	ptrdiff_t offset = h->ops->node_offset;
	ps4_hash_node *pos;
	ps4_hash_item item;

	assert(h->ops->compare_item != NULL);

	hash %= ps4_array_len(h->buckets);
	hlist_for_each(pos, &h->buckets->item[hash]) {
		item = ((void *) pos) - offset;
		if (h->ops->compare_item(item, key) == 0) {
			hlist_del(pos, &h->buckets->item[hash]);
			if (h->ops->delete_item) h->ops->delete_item(item);
			h->num_items--;
			break;
		}
	}
}
