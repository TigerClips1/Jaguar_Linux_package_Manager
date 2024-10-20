/* app_policy.c -  PS4linux package manager (PS4)
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
#include "ps4_version.h"
#include "ps4_print.h"

static int print_policy(struct ps4_database *db, const char *match, struct ps4_name *name, void *ctx)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_provider *p;
	struct ps4_repository *repo;
	int i, j, num = 0;

	if (!name) return 0;

/*
zlib1g policy:
  2.0:
    @testing http://nl.alpinelinux.org/alpine/edge/testing
  1.7:
    @edge http://nl.alpinelinux.org/alpine/edge/main
  1.2.3.5 (upgradeable):
    http://nl.alpinelinux.org/alpine/v2.6/main
  1.2.3.4 (installed):
    /media/cdrom/...
    http://nl.alpinelinux.org/alpine/v2.5/main
  1.1:
    http://nl.alpinelinux.org/alpine/v2.4/main
*/
	ps4_name_sorted_providers(name);
	foreach_array_item(p, name->providers) {
		if (p->pkg->name != name) continue;
		if (num++ == 0) ps4_out(out, "%s policy:", name->name);
		ps4_out(out, "  " BLOB_FMT ":", BLOB_PRINTF(*p->version));
		if (p->pkg->ipkg)
			ps4_out(out, "    %s/installed", ps4_db_layer_name(p->pkg->layer));
		for (i = 0; i < db->num_repos; i++) {
			repo = &db->repos[i];
			if (!(BIT(i) & p->pkg->repos))
				continue;
			for (j = 0; j < db->num_repo_tags; j++) {
				if (db->repo_tags[j].allowed_repos & p->pkg->repos)
					ps4_out(out, "    "BLOB_FMT"%s%s",
						BLOB_PRINTF(db->repo_tags[j].tag),
						j == 0 ? "" : " ",
						repo->url);
			}
		}
	}
	return 0;
}

static int policy_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	if (ps4_array_len(args) == 0) return 0;
	ps4_db_foreach_sorted_name(ac->db, args, print_policy, NULL);
	return 0;
}

static struct ps4_applet ps4_policy = {
	.name = "policy",
	.open_flags = PS4_OPENF_READ | PS4_OPENF_ALLOW_ARCH,
	.optgroups = { &optgroup_global, &optgroup_source },
	.main = policy_main,
};

PS4_DEFINE_APPLET(ps4_policy);


