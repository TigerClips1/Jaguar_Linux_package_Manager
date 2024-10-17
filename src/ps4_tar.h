/* ps4_tar.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_TAR
#define PS4_TAR

#include "ps4_io.h"

int ps4_tar_parse(struct ps4_istream *,
		  ps4_archive_entry_parser parser, void *ctx,
		  struct ps4_id_cache *);
int ps4_tar_write_entry(struct ps4_ostream *, const struct ps4_file_info *ae,
			const char *data);
int ps4_tar_write_padding(struct ps4_ostream *, int size);

#endif
