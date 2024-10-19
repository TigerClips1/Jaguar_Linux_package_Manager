#include "ps4_crypto.h"

static const char *ps4_digest_str[] = {
	[PS4_DIGEST_NONE]	= "none",
	[PS4_DIGEST_MD5]	= "md5",
	[PS4_DIGEST_SHA1]	= "sha1",
	[PS4_DIGEST_SHA256_160] = "sha256-160",
	[PS4_DIGEST_SHA256]	= "sha256",
	[PS4_DIGEST_SHA512]	= "sha512",
};

const char *ps4_digest_alg_str(uint8_t alg)
{
	const char *alg_str = "unknown";
	if (alg < ARRAY_SIZE(ps4_digest_str))
		alg_str = ps4_digest_str[alg];
	return alg_str;
}

uint8_t ps4_digest_alg_by_str(const char *algstr)
{
	for (uint8_t alg = 0; alg < ARRAY_SIZE(ps4_digest_str); alg++)
		if (strcmp(ps4_digest_str[alg], algstr) == 0) return alg;
	return PS4_DIGEST_NONE;
}

int ps4_digest_alg_len(uint8_t alg)
{
	switch (alg) {
	case PS4_DIGEST_MD5:		return PS4_DIGEST_LENGTH_MD5;
	case PS4_DIGEST_SHA1:		return PS4_DIGEST_LENGTH_SHA1;
	case PS4_DIGEST_SHA256_160:	return PS4_DIGEST_LENGTH_SHA256_160;
	case PS4_DIGEST_SHA256:		return PS4_DIGEST_LENGTH_SHA256;
	case PS4_DIGEST_SHA512:		return PS4_DIGEST_LENGTH_SHA512;
	default:			return 0;
	}
}

uint8_t ps4_digest_alg_by_len(int len)
{
	switch (len) {
	case 0:				return PS4_DIGEST_NONE;
	case PS4_DIGEST_LENGTH_MD5:	return PS4_DIGEST_MD5;
	case PS4_DIGEST_LENGTH_SHA1:	return PS4_DIGEST_SHA1;
	case PS4_DIGEST_LENGTH_SHA256:	return PS4_DIGEST_SHA256;
	case PS4_DIGEST_LENGTH_SHA512:	return PS4_DIGEST_SHA512;
	default:			return PS4_DIGEST_NONE;
	}
}

uint8_t ps4_digest_from_blob(struct ps4_digest *d, ps4_blob_t b)
{
	d->alg = ps4_digest_alg_by_len(b.len);
	d->len = 0;
	if (d->alg != PS4_DIGEST_NONE) {
		d->len = b.len;
		memcpy(d->data, b.ptr, d->len);
	}
	return d->alg;
}
