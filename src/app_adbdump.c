#include <stdio.h>
#include <unistd.h>
#include "ps4_adb.h"
#include "ps4_applet.h"
#include "ps4_print.h"

static const struct adb_db_schema dbschemas[] = {
	{ .magic = ADB_SCHEMA_INDEX,		.root = &schema_index, },
	{ .magic = ADB_SCHEMA_INSTALLED_DB,	.root = &schema_idb, },
	{ .magic = ADB_SCHEMA_PACKAGE,		.root = &schema_package },
	{},
};

static int adbdump_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	char **arg;
	int r;

	foreach_array_item(arg, args) {
		struct adb_walk_gentext td = {
			.d.ops = &adb_walk_gentext_ops,
			.d.schemas = dbschemas,
			.out = out->out,
		};

		r = adb_walk_adb(&td.d,
			adb_decompress(ps4_istream_from_file_mmap(AT_FDCWD, *arg), 0),
			ps4_ctx_get_trust(ac));
		if (r) {
			ps4_err(out, "%s: %s", *arg, ps4_error_str(r));
			return r;
		}
	}

	return 0;
}

static struct ps4_applet ps4_adbdump = {
	.name = "adbdump",
	.main = adbdump_main,
};
ps4_DEFINE_APPLET(ps4_adbdump);


static int adbgen_main(void *pctx, struct ps4_ctx *ac, struct ps4_string_array *args)
{
	struct ps4_out *out = &ac->out;
	char **arg;
	int r;
	struct adb_walk_genadb genadb = {
		.d.ops = &adb_walk_genadb_ops,
		.d.schemas = dbschemas,
	};

	adb_w_init_alloca(&genadb.db, 0, 1000);
	adb_w_init_alloca(&genadb.idb[0], 0, 100);
	foreach_array_item(arg, args) {
		adb_reset(&genadb.db);
		adb_reset(&genadb.idb[0]);
		r = adb_walk_text(&genadb.d, ps4_istream_from_file(AT_FDCWD, *arg));
		if (!r) {
			adb_w_root(&genadb.db, genadb.stored_object);
			r = adb_c_create(ps4_ostream_to_fd(STDOUT_FILENO), &genadb.db,
				ps4_ctx_get_trust(ac));
		}
		adb_free(&genadb.db);
		adb_free(&genadb.idb[0]);
		if (r) {
			ps4_err(out, "%s: %s", *arg, ps4_error_str(r));
			return r;
		}
	}

	return 0;
}

static struct ps4_applet ps4_adbgen = {
	.name = "adbgen",
	.main = adbgen_main,
};
PS4_DEFINE_APPLET(ps4_adbgen);

