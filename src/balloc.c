/* balloc.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include "ps4_defines.h"
#include "ps4_balloc.h"

struct ps4_balloc_page {
	struct hlist_node pages_list;
};

void ps4_balloc_init(struct ps4_balloc *ba, size_t page_size)
{
	*ba = (struct ps4_balloc) { .page_size = page_size };
}

void ps4_balloc_destroy(struct ps4_balloc *ba)
{
	struct ps4_balloc_page *p;
	struct hlist_node *pn, *pc;

	hlist_for_each_entry_safe(p, pc, pn, &ba->pages_head, pages_list)
		free(p);
	memset(ba, 0, sizeof *ba);
}

void *ps4_balloc_aligned(struct ps4_balloc *ba, size_t size, size_t align)
{
	uintptr_t ptr = ROUND_UP(ba->cur, align);
	if (ptr + size > ba->end) {
		size_t page_size = max(ba->page_size, size);
		struct ps4_balloc_page *bp = malloc(page_size + sizeof(struct ps4_balloc_page));
		hlist_add_head(&bp->pages_list, &ba->pages_head);
		ba->cur = (intptr_t)bp + sizeof *bp;
		ba->end = (intptr_t)bp + page_size;
		ptr = ROUND_UP(ba->cur, align);
	}
	ba->cur = ptr + size;
	return (void *) ptr;
}

void *ps4_balloc_aligned0(struct ps4_balloc *ba, size_t size, size_t align)
{
	void *ptr = ps4_balloc_aligned(ba, size, align);
	memset(ptr, 0, size);
	return ptr;
}
