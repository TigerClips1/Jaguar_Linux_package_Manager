/* tar.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <limits.h>

#include "ps4_defines.h"
#include "ps4_tar.h"

struct tar_header {
	/* ustar header, Posix 1003.1 */
	char name[100];     /*   0-99 */
	char mode[8];       /* 100-107 */
	char uid[8];        /* 108-115 */
	char gid[8];        /* 116-123 */
	char size[12];      /* 124-135 */
	char mtime[12];     /* 136-147 */
	char chksum[8];     /* 148-155 */
	char typeflag;      /* 156-156 */
	char linkname[100]; /* 157-256 */
	char magic[8];      /* 257-264 */
	char uname[32];     /* 265-296 */
	char gname[32];     /* 297-328 */
	char devmajor[8];   /* 329-336 */
	char devminor[8];   /* 337-344 */
	char prefix[155];   /* 345-499 */
	char padding[12];   /* 500-511 */
};

#define TAR_BLOB(s)		PS4_BLOB_PTR_LEN(s, strnlen(s, sizeof(s)))
#define GET_OCTAL(s,r)		get_octal(s, sizeof(s), r)
#define PUT_OCTAL(s,v,hz)	put_octal(s, sizeof(s), v, hz)

static unsigned int get_octal(char *s, size_t l, int *r)
{
	ps4_blob_t b = PS4_BLOB_PTR_LEN(s, l);
	unsigned int val = ps4_blob_pull_uint(&b, 8);
	while (b.len >= 1 && (b.ptr[0] == 0 || b.ptr[0] == 0x20)) b.ptr++, b.len--;
	if (b.len != 0) *r = -PS4E_V2PKG_FORMAT;
	return val;
}

static void put_octal(char *s, size_t l, size_t value, int has_zero)
{
	char *ptr = &s[l - 1];

	if (has_zero) *(ptr--) = '\0';
	while (value != 0 && ptr >= s) {
		*(ptr--) = '0' + (value % 8);
		value /= 8;
	}
	while (ptr >= s)
		*(ptr--) = '0';
}

static int blob_realloc(ps4_blob_t *b, size_t newsize)
{
	char *tmp;
	if (b->len >= newsize) return 0;
	tmp = realloc(b->ptr, newsize);
	if (!tmp) return -ENOMEM;
	b->ptr = tmp;
	b->len = newsize;
	return 0;
}

static void handle_extended_header(struct ps4_file_info *fi, ps4_blob_t hdr)
{
	ps4_blob_t name, value;

	while (1) {
		char *start = hdr.ptr;
		unsigned int len = ps4_blob_pull_uint(&hdr, 10);
		ps4_blob_pull_char(&hdr, ' ');
		if (!ps4_blob_split(hdr, PS4_BLOB_STR("="), &name, &hdr)) break;
		if (len < hdr.ptr - start + 1) break;
		len -= hdr.ptr - start + 1;
		if (hdr.len < len) break;
		value = PS4_BLOB_PTR_LEN(hdr.ptr, len);
		hdr = PS4_BLOB_PTR_LEN(hdr.ptr+len, hdr.len-len);
		ps4_blob_pull_char(&hdr, '\n');
		if (PS4_BLOB_IS_NULL(hdr)) break;
		value.ptr[value.len] = 0;

		if (ps4_blob_compare(name, PS4_BLOB_STR("path")) == 0) {
			fi->name = value.ptr;
		} else if (ps4_blob_compare(name, PS4_BLOB_STR("linkpath")) == 0) {
			fi->link_target = value.ptr;
		} else if (ps4_blob_pull_blob_match(&name, PS4_BLOB_STR("SCHILY.xattr."))) {
			name.ptr[name.len] = 0;
			ps4_xattr_array_add(&fi->xattrs, (struct ps4_xattr) {
				.name = name.ptr,
				.value = value,
			});
		} else if (ps4_blob_pull_blob_match(&name, PS4_BLOB_STR("PS4-TOOLS.checksum."))) {
			int alg = PS4_DIGEST_NONE;
			if (ps4_blob_compare(name, PS4_BLOB_STR("SHA1")) == 0)
				alg = PS4_DIGEST_SHA1;
			else if (ps4_blob_compare(name, PS4_BLOB_STR("MD5")) == 0)
				alg = PS4_DIGEST_MD5;
			if (alg > fi->digest.alg) {
				ps4_digest_set(&fi->digest, alg);
				ps4_blob_pull_hexdump(&value, PS4_DIGEST_BLOB(fi->digest));
				if (PS4_BLOB_IS_NULL(value)) ps4_digest_reset(&fi->digest);
			}
		}
	}
}

int ps4_tar_parse(struct ps4_istream *is, ps4_archive_entry_parser parser,
		  void *ctx, struct ps4_id_cache *idc)
{
	struct ps4_file_info entry;
	struct ps4_segment_istream segment;
	struct tar_header buf;
	int end = 0, r;
	size_t toskip, paxlen = 0;
	ps4_blob_t pax = PS4_BLOB_NULL, longname = PS4_BLOB_NULL;
	char filename[sizeof buf.name + sizeof buf.prefix + 2];

	if (IS_ERR(is)) return PTR_ERR(is);

	memset(&entry, 0, sizeof(entry));
	ps4_xattr_array_init(&entry.xattrs);
	entry.name = buf.name;
	while ((r = ps4_istream_read_max(is, &buf, 512)) == 512) {
		if (buf.name[0] == '\0') {
			if (end) break;
			end++;
			continue;
		}
		if (memcmp(buf.magic, "ustar", 5) != 0) {
			r = -PS4E_V2PKG_FORMAT;
			goto err;
		}

		r = 0;
		entry = (struct ps4_file_info){
			.size  = GET_OCTAL(buf.size, &r),
			.uid   = ps4_id_cache_resolve_uid(idc, TAR_BLOB(buf.uname), GET_OCTAL(buf.uid, &r)),
			.gid   = ps4_id_cache_resolve_gid(idc, TAR_BLOB(buf.gname), GET_OCTAL(buf.gid, &r)),
			.mode  = GET_OCTAL(buf.mode, &r) & 07777,
			.mtime = GET_OCTAL(buf.mtime, &r),
			.name  = entry.name,
			.uname = buf.uname,
			.gname = buf.gname,
			.device = makedev(GET_OCTAL(buf.devmajor, &r),
					  GET_OCTAL(buf.devminor, &r)),
			.xattrs = entry.xattrs,
		};
		if (r != 0) goto err;

		if (buf.prefix[0] && buf.typeflag != 'x' && buf.typeflag != 'g') {
			snprintf(filename, sizeof filename, "%.*s/%.*s",
				 (int) sizeof buf.prefix, buf.prefix,
				 (int) sizeof buf.name, buf.name);
			entry.name = filename;
		}
		buf.mode[0] = 0; /* to nul terminate 100-byte buf.name */
		buf.magic[0] = 0; /* to nul terminate 100-byte buf.linkname */
		ps4_array_truncate(entry.xattrs, 0);

		if (entry.size >= SSIZE_MAX-512) goto err;

		if (paxlen) {
			handle_extended_header(&entry, PS4_BLOB_PTR_LEN(pax.ptr, paxlen));
			ps4_fileinfo_hash_xattr(&entry, PS4_DIGEST_SHA1);
		}

		toskip = (entry.size + 511) & -512;
		switch (buf.typeflag) {
		case 'L': /* GNU long name extension */
			if ((r = blob_realloc(&longname, entry.size+1)) != 0 ||
			    (r = ps4_istream_read(is, longname.ptr, entry.size)) < 0)
				goto err;
			longname.ptr[entry.size] = 0;
			entry.name = longname.ptr;
			toskip -= entry.size;
			break;
		case 'K': /* GNU long link target extension - ignored */
			break;
		case '0':
		case '7': /* regular file */
			entry.mode |= S_IFREG;
			break;
		case '1': /* hard link */
			entry.mode |= S_IFREG;
			if (!entry.link_target) entry.link_target = buf.linkname;
			break;
		case '2': /* symbolic link */
			entry.mode |= S_IFLNK;
			if (!entry.link_target) entry.link_target = buf.linkname;
			break;
		case '3': /* char device */
			entry.mode |= S_IFCHR;
			break;
		case '4': /* block device */
			entry.mode |= S_IFBLK;
			break;
		case '5': /* directory */
			entry.mode |= S_IFDIR;
			break;
		case '6': /* fifo */
			entry.mode |= S_IFIFO;
			break;
		case 'g': /* global pax header */
			break;
		case 'x': /* file specific pax header */
			paxlen = entry.size;
			if ((r = blob_realloc(&pax, (paxlen + 511) & -512)) != 0 ||
			    (r = ps4_istream_read(is, pax.ptr, paxlen)) < 0)
				goto err;
			toskip -= entry.size;
			break;
		default:
			break;
		}

		if (strnlen(entry.name, PATH_MAX) >= PATH_MAX-10 ||
		    (entry.link_target && strnlen(entry.link_target, PATH_MAX) >= PATH_MAX-10)) {
			r = -ENAMETOOLONG;
			goto err;
		}

		if (entry.mode & S_IFMT) {
			ps4_istream_segment(&segment, is, entry.size, entry.mtime);
			r = parser(ctx, &entry, &segment.is);
			if (r != 0) goto err;
			ps4_istream_close(&segment.is);

			entry.name = buf.name;
			toskip -= entry.size;
			paxlen = 0;
		}

		if (toskip && (r = ps4_istream_read(is, NULL, toskip)) < 0)
			goto err;
	}

	/* Read remaining end-of-archive records, to ensure we read all of
	 * the file. The underlying istream is likely doing checksumming. */
	if (r == 512) {
		while ((r = ps4_istream_read_max(is, &buf, 512)) == 512) {
			if (buf.name[0] != 0) break;
		}
	}
	if (r == 0) goto ok;
err:
	/* Check that there was no partial (or non-zero) record */
	if (r >= 0) r = -PS4E_EOF;
ok:
	free(pax.ptr);
	free(longname.ptr);
	ps4_xattr_array_free(&entry.xattrs);
	return ps4_istream_close_error(is, r);
}

static void ps4_tar_fill_header(struct tar_header *hdr, char typeflag,
				const char *name, int size,
				const struct ps4_file_info *ae)
{
	const unsigned char *src;
	int chksum, i;

	hdr->typeflag = typeflag;
	if (name != NULL)
		strlcpy(hdr->name, name, sizeof hdr->name);

	strlcpy(hdr->uname, ae->uname ?: "root", sizeof hdr->uname);
	strlcpy(hdr->gname, ae->gname ?: "root", sizeof hdr->gname);

	PUT_OCTAL(hdr->size, size, 0);
	PUT_OCTAL(hdr->uid, ae->uid, 1);
	PUT_OCTAL(hdr->gid, ae->gid, 1);
	PUT_OCTAL(hdr->mode, ae->mode & 07777, 1);
	PUT_OCTAL(hdr->mtime, ae->mtime, 0);

	/* Checksum */
	strcpy(hdr->magic, "ustar  ");
	memset(hdr->chksum, ' ', sizeof(hdr->chksum));
	src = (const unsigned char *) hdr;
	for (i = chksum = 0; i < sizeof(*hdr); i++)
		chksum += src[i];
	put_octal(hdr->chksum, sizeof(hdr->chksum)-1, chksum, 1);
}

static int ps4_tar_write_longname_entry(struct ps4_ostream *os,
					const struct ps4_file_info *ae)
{
	struct tar_header buf;

	memset(&buf, 0, sizeof(buf));

	/* GNU long name extension header */
	ps4_tar_fill_header(&buf, 'L', "././@LongLink", strlen(ae->name), ae);

	/* Write Header */
	if (ps4_ostream_write(os, &buf, sizeof(buf)) < 0)
		return -1;

	/* Write filename */
	if (ps4_ostream_write(os, ae->name, strlen(ae->name) + 1) < 0)
		return -1;

	if (ps4_tar_write_padding(os, strlen(ae->name) + 1) < 0)
		return -1;

	return 0;
}

int ps4_tar_write_entry(struct ps4_ostream *os, const struct ps4_file_info *ae,
			const char *data)
{
	struct tar_header buf;

	memset(&buf, 0, sizeof(buf));
	if (ae != NULL) {
		if (!S_ISREG(ae->mode))
			return -1;

		if (ae->name && strlen(ae->name) > sizeof buf.name - 1 &&
		    ps4_tar_write_longname_entry(os, ae) < 0)
		    	return -1;

		ps4_tar_fill_header(&buf, '0', ae->name, ae->size, ae);
	}

	if (ps4_ostream_write(os, &buf, sizeof(buf)) < 0)
		return -1;

	if (ae == NULL) {
		/* End-of-archive is two empty headers */
		if (ps4_ostream_write(os, &buf, sizeof(buf)) < 0)
			return -1;
	} else if (data != NULL) {
		if (ps4_ostream_write(os, data, ae->size) < 0)
			return -1;
		if (ps4_tar_write_padding(os, ae->size) != 0)
			return -1;
	}

	return 0;
}

int ps4_tar_write_padding(struct ps4_ostream *os, int size)
{
	static char padding[512];
	int pad;

	pad = 512 - (size & 511);
	if (pad != 512 &&
	    ps4_ostream_write(os, padding, pad) < 0)
		return -1;

	return 0;
}
