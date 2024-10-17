/* ps4_pathbuilder.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_PATHBUILDER_H
#define PS4_PATHBUILDER_H

#include <limits.h>
#include "ps4_blob.h"

struct ps4_pathbuilder {
	uint16_t namelen;
	char name[PATH_MAX];
};

int ps4_pathbuilder_pushb(struct ps4_pathbuilder *pb, ps4_blob_t b);
void ps4_pathbuilder_pop(struct ps4_pathbuilder *pb, int);


static inline int ps4_pathbuilder_setb(struct ps4_pathbuilder *pb, ps4_blob_t b)
{
	pb->namelen = 0;
	return ps4_pathbuilder_pushb(pb, b);
}

static inline int ps4_pathbuilder_push(struct ps4_pathbuilder *pb, const char *name)
{
	return ps4_pathbuilder_pushb(pb, PS4_BLOB_STR(name));
}

static inline const char *ps4_pathbuilder_cstr(const struct ps4_pathbuilder *pb)
{
	return pb->name;
}

static inline ps4_blob_t ps4_pathbuilder_get(const struct ps4_pathbuilder *pb)
{
	return PS4_BLOB_PTR_LEN((void*)pb->name, pb->namelen);
}

#endif
