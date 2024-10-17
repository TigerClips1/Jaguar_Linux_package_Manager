/* ps4_provider_data.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2012 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_PROVIDER_DATA_H
#define PS4_PROVIDER_DATA_H

#include "ps4_defines.h"
#include "ps4_blob.h"

struct ps4_provider {
	struct ps4_package *pkg;
	ps4_blob_t *version;
};
PS4_ARRAY(ps4_provider_array, struct ps4_provider);

#define PROVIDER_FMT		"%s%s"BLOB_FMT
#define PROVIDER_PRINTF(n,p)	(n)->name, (p)->version->len ? "-" : "", BLOB_PRINTF(*(p)->version)

#endif
