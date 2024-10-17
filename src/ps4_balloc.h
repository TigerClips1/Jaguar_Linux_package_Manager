/* ps4_balloc.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_BALLOC_H
#define PS4_BALLOC_H

#include "ps4_defines.h"

struct ps4_balloc {
	struct hlist_head pages_head;
	size_t page_size;
	uintptr_t cur, end;
};

void ps4_balloc_init(struct ps4_balloc *ba, size_t page_size);
void ps4_balloc_destroy(struct ps4_balloc *ba);
void *ps4_balloc_aligned(struct ps4_balloc *ba, size_t size, size_t align);
void *ps4_balloc_aligned0(struct ps4_balloc *ba, size_t size, size_t align);

#define ps4_balloc_new_extra(ba, type, extra) (type *) ps4_balloc_aligned(ba, sizeof(type)+extra, alignof(type))
#define ps4_balloc_new(ba, type) (type *) ps4_balloc_new_extra(ba, type, 0)
#define ps4_balloc_new0_extra(ba, type, extra) (type *) ps4_balloc_aligned0(ba, sizeof(type)+extra, alignof(type))
#define ps4_balloc_new0(ba, type) (type *) ps4_balloc_new0_extra(ba, type, 0)

#endif
