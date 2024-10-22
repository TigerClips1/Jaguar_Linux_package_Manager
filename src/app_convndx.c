#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ps4_adb.h"
#include "ps4_applet.h"
#include "ps4_extract.h"

struct conv_ctx {
	struct ps4_ctx *ac;
	struct adb_obj pkgs;
	struct adb dbi;
	struct ps4_extract_ctx ectx;
};

static int convert_v2index(struct ps4_extract_ctx *ectx, ps4_blob_t *desc, struct ps4_istream *is)
{
	struct conv_ctx *ctx = container_of(ectx, struct conv_ctx, ectx);
	struct adb_obj pkginfo;
	ps4_blob_t token = PS4_BLOB_STR("\n"), l;
	int i;

	adb_wo_alloca(&pkginfo, &schema_pkginfo, &ctx->dbi);

	while (ps4_istream_get_delim(is, token, &l) == 0) {
		if (l.len < 2) {
			adb_wa_append_obj(&ctx->pkgs, &pkginfo);
			continue;
		}
		i = adb_pkg_field_index(l.ptr[0]);
		if (i > 0) adb_wo_pkginfo(&pkginfo, i, PS4_BLOB_PTR_LEN(l.ptr+2, l.len-2));
	}
	return ps4_istream_close(is);
}

static const struct ps4_extract_ops extract_convndx = {
	.v2index = convert_v2index,
};

static int load_index(struct conv_ctx *ctx, struct ps4_istream *is)
{
	if (IS_ERR(is)) return PTR_ERR(is);
	ps4_extract_init(&ctx->ectx, ctx->ac, &extract_convndx);
	return ps4_extract(&ctx->ectx, is);
}

static int conv_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	char **arg;
	struct conv_ctx *ctx = pctx;
	struct ps4_trust *trust = ps4_ctx_get_trust(ac);
	struct ps4_out *out = &ac->out;
	struct adb_obj ndx;
	int r;

	ctx->ac = ac;
	adb_w_init_alloca(&ctx->dbi, ADB_SCHEMA_INDEX, 1000);
	adb_wo_alloca(&ndx, &schema_index, &ctx->dbi);
	adb_wo_alloca(&ctx->pkgs, &schema_pkginfo_array, &ctx->dbi);

	foreach_array_item(arg, args) {
		r = load_index(ctx, ps4_istream_from_url(*arg, ps4_ctx_since(ac, 0)));
		if (r) {
			ps4_err(out, "%s: %s", *arg, ps4_error_str(r));
			goto err;
		}
		ps4_notice(out, "%s: %u packages", *arg, adb_ra_num(&ctx->pkgs));
	}

	adb_wo_obj(&ndx, ADBI_NDX_PACKAGES, &ctx->pkgs);
	adb_w_rootobj(&ndx);

	r = adb_c_create(
		adb_compress(ps4_ostream_to_fd(STDOUT_FILENO), &ac->compspec),
		&ctx->dbi, trust);
err:
	adb_free(&ctx->dbi);

	return r;
}

static struct ps4_applet ps4_convndx = {
	.name = "convndx",
	.context_size = sizeof(struct conv_ctx),
	.optgroups = { &optgroup_global, &optgroup_generation },
	.main = conv_main,
};
PS4_DEFINE_APPLET(ps4_convndx);
