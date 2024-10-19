/* app_vertest.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <unistd.h>
#include "ps4_defines.h"
#include "ps4_applet.h"
#include "ps4_database.h"
#include "ps4_version.h"
#include "ps4_print.h"

static int vertest_one(struct ps4_ctx *ac, ps4_blob_t arg)
{
	struct ps4_out *out = &ac->out;
	ps4_blob_t ver1, ver2, op, space = PS4_BLOB_STRLIT(" "), binvert = PS4_BLOB_STRLIT("!");
	int ok = 0, invert = 0;

	// trim comments and trailing whitespace
	ps4_blob_split(arg, PS4_BLOB_STRLIT("#"), &arg, &op);
	arg = ps4_blob_trim(arg);
	if (arg.len == 0) return 0;

	// arguments are either:
	//   "version"		-> check validity
	//   "!version"		-> check invalid
	//   "ver1 op ver2"	-> check if that the comparison is true
	//   "ver1 !op ver2"	-> check if that the comparison is false
	if (ps4_blob_split(arg, space, &ver1, &op) &&
	    ps4_blob_split(op,  space, &op,   &ver2)) {
		invert = ps4_blob_pull_blob_match(&op, binvert);
		ok = ps4_version_match(ver1, ps4_version_result_mask_blob(op), ver2);
	} else {
		ver1 = arg;
		invert = ps4_blob_pull_blob_match(&ver1, binvert);
		ok = ps4_version_validate(ver1);
	}
	if (invert) ok = !ok;
	if (!ok) {
		ps4_msg(out, "FAIL: " BLOB_FMT, BLOB_PRINTF(arg));
		return 1;
	}

	ps4_dbg(out, "OK: " BLOB_FMT, BLOB_PRINTF(arg));
	return 0;
}

static int vertest_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_istream *is;
	char **parg;
	ps4_blob_t l;
	int errors = 0, count = 0;

	if (ps4_array_len(args) != 0) {
		foreach_array_item(parg, args)
			errors += vertest_one(ac, PS4_BLOB_STR(*parg));
		count = ps4_array_len(args);
	} else {
		is = ps4_istream_from_fd(STDIN_FILENO);
		if (IS_ERR(is)) return 1;

		while (ps4_istream_get_delim(is, PS4_BLOB_STR("\n"), &l) == 0) {
			errors += vertest_one(ac, l);
			count++;
		}

		if (ps4_istream_close(is) != 0)
			errors++;
	}
	if (errors) ps4_dbg(&ac->out, "Result: %d/%d", count-errors, count);

	return errors ? 1 : 0;
}

static struct ps4_applet ps4_vertest = {
	.name = "vertest",
	.main = vertest_main,
};

PS4_DEFINE_APPLET(ps4_vertest);
