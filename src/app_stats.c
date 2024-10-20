/* app_stats.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2013 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"

static int list_count(struct list_head *h)
{
	struct list_head *n;
	int c = 0;

	list_for_each(n, h)
		c++;

	return c;
}

static int stats_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;

	ps4_out(out,
		"installed:\n"
		"  packages: %d\n"
		"  dirs: %d\n"
		"  files: %d\n"
		"  bytes: %zu\n"
		"  triggers: %d\n"
		"available:\n"
		"  names: %d\n"
		"  packages: %d\n"
		"atoms:\n"
		"  num: %d\n"
		,
		db->installed.stats.packages,
		db->installed.stats.dirs,
		db->installed.stats.files,
		db->installed.stats.bytes,
		list_count(&db->installed.triggers),
		db->available.names.num_items,
		db->available.packages.num_items,
		db->atoms.hash.num_items
		);
	return 0;
}

static struct ps4_applet stats_applet = {
	.name = "stats",
	.open_flags = PS4_OPENF_READ,
	.main = stats_main,
};

PS4_DEFINE_APPLET(stats_applet);


