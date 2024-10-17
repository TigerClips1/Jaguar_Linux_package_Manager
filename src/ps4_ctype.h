/* ps4_ctype.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_CTYPE_H
#define PS4_CTYPE_H

enum {
	PS4_CTYPE_HEXDIGIT = 0,
	PS4_CTYPE_PACKAGE_NAME,
	PS4_CTYPE_VERSION_SUFFIX,
	PS4_CTYPE_DEPENDENCY_NAME,
	PS4_CTYPE_DEPENDENCY_COMPARER,
	PS4_CTYPE_DEPENDENCY_SEPARATOR,
	PS4_CTYPE_REPOSITORY_SEPARATOR,
};

int ps4_blob_spn(ps4_blob_t blob, unsigned char ctype, ps4_blob_t *l, ps4_blob_t *r);
int ps4_blob_cspn(ps4_blob_t blob, unsigned char ctype, ps4_blob_t *l, ps4_blob_t *r);

#endif
