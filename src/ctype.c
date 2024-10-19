/* ctype.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ps4_defines.h"
#include "ps4_blob.h"
#include "ps4_ctype.h"

#define HEXDGT	BIT(PS4_CTYPE_HEXDIGIT)
#define PKGNAME	BIT(PS4_CTYPE_PACKAGE_NAME)|BIT(PS4_CTYPE_DEPENDENCY_NAME)
#define VERSUF	BIT(PS4_CTYPE_VERSION_SUFFIX)
#define DEPNAME	BIT(PS4_CTYPE_DEPENDENCY_NAME)
#define DEPCOMP	BIT(PS4_CTYPE_DEPENDENCY_COMPARER)
#define DEPSEP	BIT(PS4_CTYPE_DEPENDENCY_SEPARATOR)
#define REPOSEP	BIT(PS4_CTYPE_REPOSITORY_SEPARATOR)

static uint8_t ps4_ctype[128] = {
	['\t'] = REPOSEP,
	['\n'] = DEPSEP,
	[' '] = REPOSEP|DEPSEP,
	['+'] = PKGNAME,
	[','] = DEPNAME,
	['-'] = PKGNAME,
	['.'] = PKGNAME,
	[':'] = REPOSEP|DEPNAME,
	['<'] = DEPCOMP,
	['='] = DEPCOMP,
	['>'] = DEPCOMP,
	['/'] = DEPNAME,
	['0'] = HEXDGT|PKGNAME,
	['1'] = HEXDGT|PKGNAME,
	['2'] = HEXDGT|PKGNAME,
	['3'] = HEXDGT|PKGNAME,
	['4'] = HEXDGT|PKGNAME,
	['5'] = HEXDGT|PKGNAME,
	['6'] = HEXDGT|PKGNAME,
	['7'] = HEXDGT|PKGNAME,
	['8'] = HEXDGT|PKGNAME,
	['9'] = HEXDGT|PKGNAME,
	['A'] = PKGNAME,
	['B'] = PKGNAME,
	['C'] = PKGNAME,
	['D'] = PKGNAME,
	['E'] = PKGNAME,
	['F'] = PKGNAME,
	['G'] = PKGNAME,
	['H'] = PKGNAME,
	['I'] = PKGNAME,
	['J'] = PKGNAME,
	['K'] = PKGNAME,
	['L'] = PKGNAME,
	['M'] = PKGNAME,
	['N'] = PKGNAME,
	['O'] = PKGNAME,
	['P'] = PKGNAME,
	['Q'] = PKGNAME,
	['R'] = PKGNAME,
	['S'] = PKGNAME,
	['T'] = PKGNAME,
	['U'] = PKGNAME,
	['V'] = PKGNAME,
	['W'] = PKGNAME,
	['X'] = PKGNAME,
	['Y'] = PKGNAME,
	['Z'] = PKGNAME,
	['['] = DEPNAME,
	[']'] = DEPNAME,
	['_'] = PKGNAME,
	['a'] = HEXDGT|VERSUF|PKGNAME,
	['b'] = HEXDGT|VERSUF|PKGNAME,
	['c'] = HEXDGT|VERSUF|PKGNAME,
	['d'] = HEXDGT|VERSUF|PKGNAME,
	['e'] = HEXDGT|VERSUF|PKGNAME,
	['f'] = HEXDGT|VERSUF|PKGNAME,
	['g'] = VERSUF|PKGNAME,
	['h'] = VERSUF|PKGNAME,
	['i'] = VERSUF|PKGNAME,
	['j'] = VERSUF|PKGNAME,
	['k'] = VERSUF|PKGNAME,
	['l'] = VERSUF|PKGNAME,
	['m'] = VERSUF|PKGNAME,
	['n'] = VERSUF|PKGNAME,
	['o'] = VERSUF|PKGNAME,
	['p'] = VERSUF|PKGNAME,
	['q'] = VERSUF|PKGNAME,
	['r'] = VERSUF|PKGNAME,
	['s'] = VERSUF|PKGNAME,
	['t'] = VERSUF|PKGNAME,
	['u'] = VERSUF|PKGNAME,
	['v'] = VERSUF|PKGNAME,
	['w'] = VERSUF|PKGNAME,
	['x'] = VERSUF|PKGNAME,
	['y'] = VERSUF|PKGNAME,
	['z'] = VERSUF|PKGNAME,
	['~'] = DEPCOMP,
};

int ps4_blob_spn(ps4_blob_t blob, unsigned char ctype, ps4_blob_t *l, ps4_blob_t *r)
{
	uint8_t mask = BIT(ctype);
	int i, ret = 0;

	for (i = 0; i < blob.len; i++) {
		uint8_t ch = blob.ptr[i];
		if (ch < ARRAY_SIZE(ps4_ctype) && !(ps4_ctype[ch]&mask)) {
			ret = 1;
			break;
		}
	}
	if (l != NULL) *l = PS4_BLOB_PTR_LEN(blob.ptr, i);
	if (r != NULL) *r = PS4_BLOB_PTR_LEN(blob.ptr+i, blob.len-i);
	return ret;
}

int ps4_blob_cspn(ps4_blob_t blob, unsigned char ctype, ps4_blob_t *l, ps4_blob_t *r)
{
	uint8_t mask = BIT(ctype);
	int i, ret = 0;

	for (i = 0; i < blob.len; i++) {
		uint8_t ch = blob.ptr[i];
		if (ch >= ARRAY_SIZE(ps4_ctype) || (ps4_ctype[ch]&mask)) {
			ret = 1;
			break;
		}
	}
	if (l != NULL) *l = PS4_BLOB_PTR_LEN(blob.ptr, i);
	if (r != NULL) *r = PS4_BLOB_PTR_LEN(blob.ptr+i, blob.len-i);
	return ret;
}
