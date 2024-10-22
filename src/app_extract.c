/* extract.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ps4_applet.h"
#include "ps4_print.h"
#include "ps4_extract.h"
#include "ps4_fs.h"

struct extract_ctx {
	const char *destination;
	unsigned int extract_flags;

	struct ps4_extract_ctx ectx;
	struct ps4_ctx *ac;
};


#define EXTRACT_OPTIONS(OPT) \
	OPT(OPT_EXTRACT_destination,	PS4_OPT_ARG "destination") \
	OPT(OPT_EXTRACT_no_chown,	"no-chown")

PS4_OPT_APPLET(option_desc, EXTRACT_OPTIONS);

static int option_parse_applet(void *pctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct extract_ctx *ctx = (struct extract_ctx *) pctx;

	switch (opt) {
	case OPT_EXTRACT_destination:
		ctx->destination = optarg;
		break;
	case OPT_EXTRACT_no_chown:
		ctx->extract_flags |= PS4_FSEXTRACTF_NO_CHOWN;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct ps4_option_group optgroup_applet = {
	.desc = option_desc,
	.parse = option_parse_applet,
};

static int extract_v3_meta(struct ps4_extract_ctx *ectx, struct adb_obj *pkg)
{
	return 0;
}

static int extract_file(struct ps4_extract_ctx *ectx, const struct ps4_file_info *fi, struct ps4_istream *is)
{
	struct extract_ctx *ctx = container_of(ectx, struct extract_ctx, ectx);
	struct ps4_out *out = &ctx->ac->out;
	int r;

	ps4_dbg2(out, "%s", fi->name);
	r = ps4_fs_extract(ctx->ac, fi, is, 0, 0, ctx->extract_flags, PS4_BLOB_NULL);
	if (r == -EEXIST && S_ISDIR(fi->mode)) r = 0;
	return r;
}

static const struct ps4_extract_ops extract_ops = {
	.v2meta = ps4_extract_v2_meta,
	.v3meta = extract_v3_meta,
	.file = extract_file,
};

static int extract_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct extract_ctx *ctx = pctx;
	struct ps4_out *out = &ac->out;
	char **parg;
	int r = 0;

	ctx->ac = ac;
	if (getuid() != 0) ctx->extract_flags |= PS4_FSEXTRACTF_NO_CHOWN|PS4_FSEXTRACTF_NO_SYS_XATTRS;
	if (!(ac->force & PS4_FORCE_OVERWRITE)) ctx->extract_flags |= PS4_FSEXTRACTF_NO_OVERWRITE;
	if (!ctx->destination) ctx->destination = ".";

	ac->dest_fd = openat(AT_FDCWD, ctx->destination, O_RDONLY);
	if (ac->dest_fd < 0) {
		r = -errno;
		ps4_err(out, "Error opening destination '%s': %s",
			ctx->destination, ps4_error_str(r));
		return r;
	}

	ps4_extract_init(&ctx->ectx, ac, &extract_ops);
	foreach_array_item(parg, args) {
		ps4_out(out, "Extracting %s...", *parg);
		r = ps4_extract(&ctx->ectx, ps4_istream_from_fd_url(AT_FDCWD, *parg, ps4_ctx_since(ac, 0)));
		if (r != 0) {
			ps4_err(out, "%s: %s", *parg, ps4_error_str(r));
			break;
		}
	}
	close(ac->dest_fd);
	return r;
}

static struct ps4_applet app_extract = {
	.name = "extract",
	.context_size = sizeof(struct extract_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = extract_main,
};

PS4_DEFINE_APPLET(app_extract);

