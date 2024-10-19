/* ps4_blob.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_BLOB_H
#define PS4_BLOB_H

#include <ctype.h>
#include <string.h>

#include "ps4_defines.h"

struct ps4_blob {
	long len;
	char *ptr;
};
typedef struct ps4_blob ps4_blob_t;
typedef int (*ps4_blob_cb)(void *ctx, ps4_blob_t blob);

#define BLOB_FMT		"%.*s"
#define BLOB_PRINTF(b)		(int)(b).len, (b).ptr

#define PS4_BLOB_IS_NULL(blob)		((blob).ptr == NULL)
#define PS4_BLOB_NULL			((ps4_blob_t){0, NULL})
#define PS4_BLOB_BUF(buf)		((ps4_blob_t){sizeof(buf), (char *)(buf)})
#define PS4_BLOB_STRUCT(s)		((ps4_blob_t){sizeof(s), (char*)&(s)})
#define PS4_BLOB_STRLIT(s)		((ps4_blob_t){sizeof(s)-1, (char *)(s)})
#define PS4_BLOB_PTR_LEN(beg,len)	((ps4_blob_t){(len), (beg)})
#define PS4_BLOB_PTR_PTR(beg,end)	PS4_BLOB_PTR_LEN((beg),(end)-(beg)+1)

static inline ps4_blob_t PS4_BLOB_STR(const char *str)
{
	if (str == NULL)
		return PS4_BLOB_NULL;
	return ((ps4_blob_t){strlen(str), (void *)(str)});
}

static inline ps4_blob_t ps4_blob_trim(ps4_blob_t blob)
{
	ps4_blob_t b = blob;
	while (b.len > 0 && isspace(b.ptr[b.len-1]))
		b.len--;
	return b;
}

char *ps4_blob_cstr(ps4_blob_t str);
ps4_blob_t ps4_blob_dup(ps4_blob_t blob);
int ps4_blob_split(ps4_blob_t blob, ps4_blob_t split, ps4_blob_t *l, ps4_blob_t *r);
int ps4_blob_rsplit(ps4_blob_t blob, char split, ps4_blob_t *l, ps4_blob_t *r);
ps4_blob_t ps4_blob_pushed(ps4_blob_t buffer, ps4_blob_t left);
unsigned long ps4_blob_hash_seed(ps4_blob_t, unsigned long seed);
unsigned long ps4_blob_hash(ps4_blob_t str);
int ps4_blob_compare(ps4_blob_t a, ps4_blob_t b);
int ps4_blob_sort(ps4_blob_t a, ps4_blob_t b);
int ps4_blob_starts_with(ps4_blob_t a, ps4_blob_t b);
int ps4_blob_ends_with(ps4_blob_t str, ps4_blob_t suffix);
int ps4_blob_for_each_segment(ps4_blob_t blob, const char *split,
			      ps4_blob_cb cb, void *ctx);

static inline char *ps4_blob_chr(ps4_blob_t b, unsigned char ch)
{
	return memchr(b.ptr, ch, b.len);
}

void ps4_blob_push_blob(ps4_blob_t *to, ps4_blob_t literal);
void ps4_blob_push_uint(ps4_blob_t *to, unsigned int value, int radix);
void ps4_blob_push_hash(ps4_blob_t *to, ps4_blob_t digest);
void ps4_blob_push_hash_hex(ps4_blob_t *to, ps4_blob_t digest);
void ps4_blob_push_base64(ps4_blob_t *to, ps4_blob_t binary);
void ps4_blob_push_hexdump(ps4_blob_t *to, ps4_blob_t binary);
void ps4_blob_push_fmt(ps4_blob_t *to, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void ps4_blob_pull_char(ps4_blob_t *b, int expected);
uint64_t ps4_blob_pull_uint(ps4_blob_t *b, int radix);
void ps4_blob_pull_base64(ps4_blob_t *b, ps4_blob_t to);
void ps4_blob_pull_hexdump(ps4_blob_t *b, ps4_blob_t to);
int ps4_blob_pull_blob_match(ps4_blob_t *b, ps4_blob_t match);

struct ps4_digest;
void ps4_blob_pull_digest(ps4_blob_t *b, struct ps4_digest *digest);

#endif
