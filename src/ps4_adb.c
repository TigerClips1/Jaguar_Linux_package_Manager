#include <errno.h>
#include <inttypes.h>
#include "adb.h"
#include "ps4_adb.h"
#include "ps4_print.h"
#include "ps4_version.h"
#include "ps4_package.h"
#include "ps4_ctype.h"

/* Few helpers to map old database to new one */

int ps4_dep_split(ps4_blob_t *b, ps4_blob_t *bdep)
{
	if (b->len == 0) return 0;
	// skip all separator characters
	ps4_blob_spn(*b, PS4_CTYPE_DEPENDENCY_SEPARATOR, NULL, b);
	// split the dependency string
	ps4_blob_cspn(*b, PS4_CTYPE_DEPENDENCY_SEPARATOR, bdep, b);
	return bdep->len != 0;
}

adb_val_t adb_wo_pkginfo(struct adb_obj *obj, unsigned int f, ps4_blob_t val)
{
	struct ps4_digest digest;
	char buf[20];
	adb_val_t v = ADB_ERROR(PS4E_ADB_PACKAGE_FORMAT);

	/* FIXME: get rid of this function, and handle the conversion via schema? */
	switch (f) {
	case ADBI_PI_HASHES:
		if (!val.ptr || val.len < 4) break;
		ps4_blob_pull_digest(&val, &digest);
		v = adb_w_blob(obj->db, PS4_DIGEST_BLOB(digest));
		break;
	case ADBI_PI_REPO_COMMIT:
		if (val.len < 40) break;
		ps4_blob_pull_hexdump(&val, PS4_BLOB_BUF(buf));
		if (val.ptr) v = adb_w_blob(obj->db, PS4_BLOB_BUF(buf));
		break;
	default:
		return adb_wo_val_fromstring(obj, f, val);
	}
	if (v != ADB_NULL && !ADB_IS_ERROR(v))
		v = adb_wo_val(obj, f, v);
	return v;
}

unsigned int adb_pkg_field_index(char f)
{
#define MAP(ch, ndx) [ch - 'A'] = ndx
	static unsigned char map[] = {
		MAP('C', ADBI_PI_HASHES),
		MAP('P', ADBI_PI_NAME),
		MAP('V', ADBI_PI_VERSION),
		MAP('T', ADBI_PI_DESCRIPTION),
		MAP('U', ADBI_PI_URL),
		MAP('I', ADBI_PI_INSTALLED_SIZE),
		MAP('S', ADBI_PI_FILE_SIZE),
		MAP('L', ADBI_PI_LICENSE),
		MAP('A', ADBI_PI_ARCH),
		MAP('D', ADBI_PI_DEPENDS),
		MAP('i', ADBI_PI_INSTALL_IF),
		MAP('p', ADBI_PI_PROVIDES),
		MAP('k', ADBI_PI_PROVIDER_PRIORITY),
		MAP('o', ADBI_PI_ORIGIN),
		MAP('m', ADBI_PI_MAINTAINER),
		MAP('t', ADBI_PI_BUILD_TIME),
		MAP('c', ADBI_PI_REPO_COMMIT),
		MAP('r', ADBI_PI_REPLACES),
	};
	if (f < 'A' || f-'A' >= ARRAY_SIZE(map)) return 0;
	return map[(unsigned char)f - 'A'];
}

/* Schema */

static ps4_blob_t string_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return adb_r_blob(db, val);
}

static adb_val_t string_fromstring(struct adb *db, ps4_blob_t val)
{
	return adb_w_blob(db, val);
}

static int string_compare(struct adb *db1, adb_val_t v1, struct adb *db2, adb_val_t v2)
{
	return ps4_blob_sort(adb_r_blob(db1, v1), adb_r_blob(db2, v2));
}

static struct adb_scalar_schema scalar_string = {
	.kind = ADB_KIND_BLOB,
	.tostring = string_tostring,
	.fromstring = string_fromstring,
	.compare = string_compare,
};

static struct adb_scalar_schema scalar_mstring = {
	.kind = ADB_KIND_BLOB,
	.multiline = 1,
	.tostring = string_tostring,
	.fromstring = string_fromstring,
	.compare = string_compare,
};

const struct adb_object_schema schema_string_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = 32,
	.fields = ADB_ARRAY_ITEM(scalar_string),
};

static ps4_blob_t xattr_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	ps4_blob_t b = adb_r_blob(db, val), to = PS4_BLOB_PTR_LEN(buf, bufsz), k, v;

	if (PS4_BLOB_IS_NULL(b)) return b;
	if (!ps4_blob_split(b, PS4_BLOB_BUF(""), &k, &v)) return PS4_BLOB_NULL;

	ps4_blob_push_blob(&to, k);
	ps4_blob_push_blob(&to, PS4_BLOB_PTR_LEN("=", 1));
	ps4_blob_push_hexdump(&to, v);
	if (!ps4_BLOB_IS_NULL(to))
		return PS4_BLOB_PTR_PTR(buf, to.ptr-1);
	return PS4_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, BLOB_FMT "=(%d bytes)",
		BLOB_PRINTF(k), (int)v.len));
}

static adb_val_t xattr_fromstring(struct adb *db, ps4_blob_t val)
{
	char buf[256];
	ps4_blob_t b[2], hex;

	if (!ps4_blob_rsplit(val, '=', &b[0], &hex)) return ADB_ERROR(PS4E_ADB_SCHEMA);
	b[0].len++;

	if (hex.len & 1) return ADB_ERROR(EINVAL);
	if (hex.len/2 > sizeof buf) return ADB_ERROR(E2BIG);
	b[1] = PS4_BLOB_PTR_LEN(buf, hex.len / 2);
	ps4_blob_pull_hexdump(&hex, b[1]);
	if (PS4_BLOB_IS_NULL(hex)) return ADB_ERROR(EINVAL);

	return adb_w_blob_vec(db, ARRAY_SIZE(b), b);
}

static const struct adb_scalar_schema schema_xattr = {
	.kind = ADB_KIND_BLOB,
	.tostring = xattr_tostring,
	.fromstring = xattr_fromstring,
	.compare = string_compare,
};

const struct adb_object_schema schema_xattr_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = 8,
	.pre_commit = adb_wa_sort,
	.fields = ADB_ARRAY_ITEM(schema_xattr),
};

static adb_val_t name_fromstring(struct adb *db, ps4_blob_t val)
{
	// Check invalid first character
	if (val.len == 0 || !isascii(val.ptr[0]) || !isalnum(val.ptr[0])) goto fail;
	// Shall consist of characters
	if (ps4_blob_spn(val, PS4_CTYPE_PACKAGE_NAME, NULL, NULL)) goto fail;
	return adb_w_blob(db, val);
fail:
	return ADB_ERROR(PS4E_PKGNAME_FORMAT);
}

static struct adb_scalar_schema scalar_name = {
	.kind = ADB_KIND_BLOB,
	.tostring = string_tostring,
	.fromstring = name_fromstring,
	.compare = string_compare,
};

static adb_val_t version_fromstring(struct adb *db, ps4_blob_t val)
{
	if (!ps4_version_validate(val)) return ADB_ERROR(PS4E_PKGVERSION_FORMAT);
	return adb_w_blob(db, val);
}

static int version_compare(struct adb *db1, adb_val_t v1, struct adb *db2, adb_val_t v2)
{
	switch (ps4_version_compare(adb_r_blob(db1, v1), adb_r_blob(db2, v2))) {
	case PS4_VERSION_LESS: return -1;
	case PS4_VERSION_GREATER: return 1;
	default: return 0;
	}
}

static struct adb_scalar_schema scalar_version = {
	.kind = ADB_KIND_BLOB,
	.tostring = string_tostring,
	.fromstring = version_fromstring,
	.compare = version_compare,
};

static ps4_blob_t hexblob_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	ps4_blob_t b = adb_r_blob(db, val), to = PS4_BLOB_PTR_LEN(buf, bufsz);

	if (PS4_BLOB_IS_NULL(b)) return b;

	ps4_blob_push_hexdump(&to, b);
	if (!PS4_BLOB_IS_NULL(to))
		return PS4_BLOB_PTR_PTR(buf, to.ptr-1);

	return PS4_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "(%ld bytes)", b.len));
}

static adb_val_t hexblob_fromstring(struct adb *db, ps4_blob_t val)
{
	char buf[256];

	if (val.len & 1) return ADB_ERROR(EINVAL);
	if (val.len/2 > sizeof buf) return ADB_ERROR(E2BIG);

	ps4_blob_t b = PS4_BLOB_PTR_LEN(buf, val.len / 2);
	ps4_blob_pull_hexdump(&val, b);
	if (PS4_BLOB_IS_NULL(val))
		return ADB_ERROR(EINVAL);

	return adb_w_blob(db, b);
}

static struct adb_scalar_schema scalar_hexblob = {
	.kind = ADB_KIND_BLOB,
	.tostring = hexblob_tostring,
	.fromstring = hexblob_fromstring,
	.compare = string_compare,
};

static ps4_blob_t int_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return PS4_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%" PRIu64, adb_r_int(db, val)));
}

static adb_val_t int_fromstring(struct adb *db, ps4_blob_t val)
{
	uint32_t n = ps4_blob_pull_uint(&val, 10);
	if (val.len) return ADB_ERROR(EINVAL);
	return adb_w_int(db, n) ?: ADB_VAL_NULL;
}

static int int_compare(struct adb *db1, adb_val_t v1, struct adb *db2, adb_val_t v2)
{
	uint64_t r1 = adb_r_int(db1, v1);
	uint64_t r2 = adb_r_int(db1, v2);
	if (r1 < r2) return -1;
	if (r1 > r2) return 1;
	return 0;
}

static struct adb_scalar_schema scalar_int = {
	.kind = ADB_KIND_INT,
	.tostring = int_tostring,
	.fromstring = int_fromstring,
	.compare = int_compare,
};

static ps4_blob_t oct_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return PS4_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%" PRIo64, adb_r_int(db, val)));
}

static adb_val_t oct_fromstring(struct adb *db, ps4_blob_t val)
{
	uint32_t n = ps4_blob_pull_uint(&val, 8);
	if (val.len) return ADB_ERROR(EINVAL);
	return adb_w_int(db, n) ?: ADB_VAL_NULL;
}

static struct adb_scalar_schema scalar_oct = {
	.kind = ADB_KIND_INT,
	.tostring = oct_tostring,
	.fromstring = oct_fromstring,
	.compare = int_compare,
};

static ps4_blob_t hsize_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	off_t v = adb_r_int(db, val);
	const char *unit = ps4_get_human_size(v, &v);

	return PS4_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%jd %s", (intmax_t)v, unit));
}

static adb_val_t hsize_fromstring(struct adb *db, ps4_blob_t val)
{
	ps4_blob_t l, r;

	if (!ps4_blob_split(val, PS4_BLOB_STR(" "), &l, &r))
		return int_fromstring(db, val);

	uint64_t n = ps4_blob_pull_uint(&l, 10);
	int sz = ps4_get_human_size_unit(r);
	n *= sz;
	return adb_w_int(db, n);
}

static struct adb_scalar_schema scalar_hsize = {
	.kind = ADB_KIND_INT,
	.tostring = hsize_tostring,
	.fromstring = hsize_fromstring,
	.compare = int_compare,
};

static ps4_blob_t dependency_tostring(struct adb_obj *obj, char *buf, size_t bufsz)
{
	ps4_blob_t name, ver;
	unsigned int op;

	name = adb_ro_blob(obj, ADBI_DEP_NAME);
	ver  = adb_ro_blob(obj, ADBI_DEP_VERSION);
	op   = adb_ro_int(obj, ADBI_DEP_MATCH) ?: PS4_VERSION_EQUAL;

	if (PS4_BLOB_IS_NULL(name)) return PS4_BLOB_NULL;
	if (ps4_BLOB_IS_NULL(ver)) {
		if (op & PS4_VERSION_CONFLICT)
			return PS4_BLOB_PTR_LEN(buf,
				snprintf(buf, bufsz, "!"BLOB_FMT,
					BLOB_PRINTF(name)));
		return name;
	}

	return PS4_BLOB_PTR_LEN(buf,
		snprintf(buf, bufsz, "%s"BLOB_FMT"%s"BLOB_FMT,
			(op & PS4_VERSION_CONFLICT) ? "!" : "",
			BLOB_PRINTF(name),
			ps4_version_op_string(op),
			BLOB_PRINTF(ver)));
}

static int dependency_fromstring(struct adb_obj *obj, ps4_blob_t bdep)
{
	ps4_blob_t bname, bver;
	int op;

	if (ps4_dep_parse(bdep, &bname, &op, &bver) != 0) goto fail;
	if ((op & PS4_DEPMASK_CHECKSUM) != PS4_DEPMASK_CHECKSUM &&
	    !ps4_version_validate(bver)) goto fail;

	if (ps4_blob_spn(bname, PS4_CTYPE_DEPENDENCY_NAME, NULL, NULL)) goto fail;

	adb_wo_blob(obj, ADBI_DEP_NAME, bname);
	if (op != PS4_DEPMASK_ANY) {
		adb_wo_blob(obj, ADBI_DEP_VERSION, bver);
		if (op != PS4_VERSION_EQUAL)
			adb_wo_int(obj, ADBI_DEP_MATCH, op);
	}
	return 0;

fail:
	return -PS4E_DEPENDENCY_FORMAT;
}

const struct adb_object_schema schema_dependency = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_DEP_MAX,
	.num_compare = ADBI_DEP_NAME,
	.tostring = dependency_tostring,
	.fromstring = dependency_fromstring,
	.fields = ADB_OBJECT_FIELDS(ADBI_DEP_MAX) {
		ADB_FIELD(ADBI_DEP_NAME,	"name",		scalar_string),
		ADB_FIELD(ADBI_DEP_VERSION,	"version",	scalar_version),
		ADB_FIELD(ADBI_DEP_MATCH,	"match",	scalar_int),
	},
};

static int dependencies_fromstring(struct adb_obj *obj, ps4_blob_t b)
{
	struct adb_obj dep;
	ps4_blob_t bdep;

	adb_wo_alloca(&dep, &schema_dependency, obj->db);

	while (ps4_dep_split(&b, &bdep)) {
		int r = adb_wo_fromstring(&dep, bdep);
		if (r) return r;
		adb_wa_append_obj(obj, &dep);
	}

	return 0;
}

const struct adb_object_schema schema_dependency_array = {
	.kind = ADB_KIND_ARRAY,
	.fromstring = dependencies_fromstring,
	.num_fields = 32,
	.pre_commit = adb_wa_sort_unique,
	.fields = ADB_ARRAY_ITEM(schema_dependency),
};

const struct adb_object_schema schema_pkginfo = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_PI_MAX,
	.num_compare = ADBI_PI_HASHES,
	.fields = ADB_OBJECT_FIELDS(ADBI_PI_MAX) {
		ADB_FIELD(ADBI_PI_NAME,		"name",		scalar_name),
		ADB_FIELD(ADBI_PI_VERSION,	"version",	scalar_version),
		ADB_FIELD(ADBI_PI_HASHES,	"hashes",	scalar_hexblob),
		ADB_FIELD(ADBI_PI_DESCRIPTION,	"description",	scalar_string),
		ADB_FIELD(ADBI_PI_ARCH,		"arch",		scalar_string),
		ADB_FIELD(ADBI_PI_LICENSE,	"license",	scalar_string),
		ADB_FIELD(ADBI_PI_ORIGIN,	"origin",	scalar_string),
		ADB_FIELD(ADBI_PI_MAINTAINER,	"maintainer",	scalar_string),
		ADB_FIELD(ADBI_PI_URL,		"url",		scalar_string),
		ADB_FIELD(ADBI_PI_REPO_COMMIT,	"repo-commit",	scalar_hexblob),
		ADB_FIELD(ADBI_PI_BUILD_TIME,	"build-time",	scalar_int),
		ADB_FIELD(ADBI_PI_INSTALLED_SIZE,"installed-size",scalar_hsize),
		ADB_FIELD(ADBI_PI_FILE_SIZE,	"file-size",	scalar_hsize),
		ADB_FIELD(ADBI_PI_PROVIDER_PRIORITY,	"provider-priority",	scalar_int),
		ADB_FIELD(ADBI_PI_DEPENDS,	"depends",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_PROVIDES,	"provides",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_REPLACES,	"replaces",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_INSTALL_IF,	"install-if",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_RECOMMENDS,	"recommends",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_LAYER,	"layer",	scalar_int),
	},
};

const struct adb_object_schema schema_pkginfo_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = 128,
	.pre_commit = adb_wa_sort,
	.fields = ADB_ARRAY_ITEM(schema_pkginfo),
};

const struct adb_object_schema schema_index = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_NDX_MAX,
	.fields = ADB_OBJECT_FIELDS(ADBI_NDX_MAX) {
		ADB_FIELD(ADBI_NDX_DESCRIPTION,	"description",	scalar_string),
		ADB_FIELD(ADBI_NDX_PACKAGES,	"packages",	schema_pkginfo_array),
	},
};

const struct adb_object_schema schema_acl = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_ACL_MAX,
	.fields = ADB_OBJECT_FIELDS(ADBI_ACL_MAX) {
		ADB_FIELD(ADBI_ACL_MODE,	"mode",		scalar_oct),
		ADB_FIELD(ADBI_ACL_USER,	"user",		scalar_string),
		ADB_FIELD(ADBI_ACL_GROUP,	"group",	scalar_string),
		ADB_FIELD(ADBI_ACL_XATTRS,	"xattrs",	schema_xattr_array),
	},
};

const struct adb_object_schema schema_file = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_FI_MAX,
	.num_compare = ADBI_FI_NAME,
	.fields = ADB_OBJECT_FIELDS(ADBI_FI_MAX) {
		ADB_FIELD(ADBI_FI_NAME,		"name",		scalar_string),
		ADB_FIELD(ADBI_FI_ACL,		"acl",		schema_acl),
		ADB_FIELD(ADBI_FI_SIZE,		"size",		scalar_int),
		ADB_FIELD(ADBI_FI_MTIME,	"mtime",	scalar_int),
		ADB_FIELD(ADBI_FI_HASHES,	"hash",		scalar_hexblob),
		ADB_FIELD(ADBI_FI_TARGET,	"target",	scalar_hexblob),
	},
};

const struct adb_object_schema schema_file_array = {
	.kind = ADB_KIND_ARRAY,
	.pre_commit = adb_wa_sort,
	.num_fields = 128,
	.fields = ADB_ARRAY_ITEM(schema_file),
};

const struct adb_object_schema schema_dir = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_DI_MAX,
	.num_compare = ADBI_DI_NAME,
	.fields = ADB_OBJECT_FIELDS(ADBI_DI_MAX) {
		ADB_FIELD(ADBI_DI_NAME,		"name",		scalar_string),
		ADB_FIELD(ADBI_DI_ACL,		"acl",		schema_acl),
		ADB_FIELD(ADBI_DI_FILES,	"files",	schema_file_array),
	},
};

const struct adb_object_schema schema_dir_array = {
	.kind = ADB_KIND_ARRAY,
	.pre_commit = adb_wa_sort,
	.num_fields = 128,
	.fields = ADB_ARRAY_ITEM(schema_dir),
};

const struct adb_object_schema schema_scripts = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_SCRPT_MAX,
	.fields = ADB_OBJECT_FIELDS(ADBI_SCRPT_MAX) {
		ADB_FIELD(ADBI_SCRPT_TRIGGER,	"trigger",	scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_PREINST,	"pre-install",	scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_POSTINST,	"post-install",	scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_PREDEINST,	"pre-deinstall",scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_POSTDEINST,"post-deinstall",scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_PREUPGRADE,"pre-upgrade",	scalar_mstring),
		ADB_FIELD(ADBI_SCRPT_POSTUPGRADE,"post-upgrade",scalar_mstring),
	},
};

const struct adb_object_schema schema_package = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_PKG_MAX,
	.num_compare = ADBI_PKG_PKGINFO,
	.fields = ADB_OBJECT_FIELDS(ADBI_PKG_MAX) {
		ADB_FIELD(ADBI_PKG_PKGINFO,	"info",		schema_pkginfo),
		ADB_FIELD(ADBI_PKG_PATHS,	"paths",	schema_dir_array),
		ADB_FIELD(ADBI_PKG_SCRIPTS,	"scripts",	schema_scripts),
		ADB_FIELD(ADBI_PKG_TRIGGERS,	"triggers",	schema_string_array),
		ADB_FIELD(ADBI_PKG_REPLACES_PRIORITY,	"replaces-priority",	scalar_int),
	},
};

const struct adb_adb_schema schema_package_adb = {
	.kind = ADB_KIND_ADB,
	.schema_id = ADB_SCHEMA_PACKAGE,
	.schema = &schema_package,
};

const struct adb_object_schema schema_package_adb_array = {
	.kind = ADB_KIND_ARRAY,
	.pre_commit = adb_wa_sort,
	.num_fields = 128,
	.fields = ADB_ARRAY_ITEM(schema_package_adb),
};

const struct adb_object_schema schema_idb = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_IDB_MAX,
	.fields = ADB_OBJECT_FIELDS(ADBI_IDB_MAX) {
		ADB_FIELD(ADBI_IDB_PACKAGES,	"packages",	schema_package_adb_array),
	},
};

/* Command group for adb generation */

#include "ps4_applet.h"

#define GENERATION_OPTIONS(OPT) \
	OPT(OPT_GENERATION_compression,	PS4_OPT_ARG PS4_OPT_SH("c") "compression") \
	OPT(OPT_GENERATION_sign_key,	PS4_OPT_ARG "sign-key")

PS4_OPT_GROUP(options_generation, "Generation", GENERATION_OPTIONS);

static int option_parse_generation(void *ctx, struct ps4_ctx *ac, int optch, const char *optarg)
{
	struct ps4_trust *trust = &ac->trust;
	struct ps4_out *out = &ac->out;
	struct ps4_trust_key *key;

	switch (optch) {
	case OPT_GENERATION_compression:
		if (adb_parse_compression(optarg, &ac->compspec) != 0) {
			ps4_err(out, "invalid compression type: %s", optarg);
			return -EINVAL;
		}
		break;
	case OPT_GENERATION_sign_key:
		key = ps4_trust_load_key(AT_FDCWD, optarg, 1);
		if (IS_ERR(key)) {
			ps4_err(out, "Failed to load signing key: %s: %s",
				optarg, ps4_error_str(PTR_ERR(key)));
			return PTR_ERR(key);
		}
		list_add_tail(&key->key_node, &trust->private_key_list);
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct ps4_option_group optgroup_generation = {
	.desc = options_generation,
	.parse = option_parse_generation,
};
