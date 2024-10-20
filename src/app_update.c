/* app_update.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_version.h"
#include "ps4_print.h"

static int update_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_database *db = ac->db;
	struct ps4_repository *repo;
	struct ps4_url_print urlp;
	int i;
	char buf[32] = "OK:";

	if (ps4_out_verbosity(out) < 1)
		return db->repositories.unavailable + db->repositories.stale;

	for (i = 0; i < db->num_repos; i++) {
		repo = &db->repos[i];

		if (PS4_BLOB_IS_NULL(repo->description))
			continue;

		ps4_url_parse(&urlp, db->repos[i].url);
		ps4_msg(out, BLOB_FMT " [" URL_FMT "]",
			BLOB_PRINTF(repo->description),
			URL_PRINTF(urlp));
	}

	if (db->repositories.unavailable || db->repositories.stale)
		snprintf(buf, sizeof(buf), "%d unavailable, %d stale;",
			 db->repositories.unavailable,
			 db->repositories.stale);

	ps4_msg(out, "%s %d distinct packages available", buf,
		db->available.packages.num_items);

	return db->repositories.unavailable + db->repositories.stale;
}

static struct ps4_applet ps4_update = {
	.name = "update",
	.open_flags = PS4_OPENF_WRITE | PS4_OPENF_ALLOW_ARCH,
	.forced_force = PS4_FORCE_REFRESH,
	.main = update_main,
};

PS4_DEFINE_APPLET(ps4_update);

