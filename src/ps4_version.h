/* ps4_version.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_VERSION_H
#define PS4_VERSION_H

#include "ps4_blob.h"

#define PS4_VERSION_UNKNOWN		0
#define PS4_VERSION_EQUAL		1
#define PS4_VERSION_LESS		2
#define PS4_VERSION_GREATER		4
#define PS4_VERSION_FUZZY		8
#define PS4_VERSION_CONFLICT	16

#define PS4_DEPMASK_ANY		(PS4_VERSION_EQUAL|PS4_VERSION_LESS|\
				 PS4_VERSION_GREATER)
#define PS4_DEPMASK_CHECKSUM	(PS4_VERSION_LESS|PS4_VERSION_GREATER)

const char *ps4_version_op_string(int op);
int ps4_version_result_mask(const char *op);
int ps4_version_result_mask_blob(ps4_blob_t op);
int ps4_version_validate(ps4_blob_t ver);
int ps4_version_compare(ps4_blob_t a, ps4_blob_t b);
int ps4_version_match(ps4_blob_t a, int op, ps4_blob_t b);

#endif
