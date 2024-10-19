/* app_verify.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "ps4_applet.h"
#include "ps4_print.h"
#include "ps4_extract.h"

static int verify_main(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	struct ps4_extract_ctx ectx;
	char **parg;
	int r, rc = 0;

	foreach_array_item(parg, args) {
		ps4_extract_init(&ectx, ac, 0);
		r = ps4_extract(&ectx, ps4_istream_from_file(AT_FDCWD, *parg));
		if (ps4_out_verbosity(out) >= 1)
			ps4_msg(out, "%s: %s", *parg,
				r < 0 ? ps4_error_str(r) : "OK");
		else if (r < 0)
			ps4_out(out, "%s", *parg);
		if (r < 0) rc++;
	}

	return rc;
}

static struct ps4_applet ps4_verify_applet = {
	.name = "verify",
	.main = verify_main,
};

PS4_DEFINE_APPLET(ps4_verify_applet);

