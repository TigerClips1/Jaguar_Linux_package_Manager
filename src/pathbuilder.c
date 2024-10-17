/* pathbuilder.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include "ps4_pathbuilder.h"

int ps4_pathbuilder_pushb(struct ps4_pathbuilder *pb, ps4_blob_t b)
{
	size_t oldlen = pb->namelen, i = pb->namelen;
	if (i + b.len + 2 >= ARRAY_SIZE(pb->name)) return -ENAMETOOLONG;
	if (i) pb->name[i++] = '/';
	memcpy(&pb->name[i], b.ptr, b.len);
	pb->namelen = i + b.len;
	pb->name[pb->namelen] = 0;
	return oldlen;
}

void ps4_pathbuilder_pop(struct ps4_pathbuilder *pb, int pos)
{
	if (pos < 0) return;
	pb->namelen = pos;
	pb->name[pb->namelen] = 0;
}
