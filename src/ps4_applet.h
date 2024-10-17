/* ps4_applet.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_APPLET_H
#define PS4_APPLET_H

#include <errno.h>
#include <getopt.h>
#include "ps4_defines.h"
#include "ps4_database.h"

#define __PS4_OPTAPPLET		"\x00"
#define __PS4_OPTGROUP(_name)	_name "\x00"
#define __PS4_OPT_ENUM(_enum,__desc) _enum,
#define __PS4_OPT_DESC(_enum,__desc) __desc "\x00"

#define PS4_OPT_ARG		"\xaf"
#define PS4_OPT_SH(x)		"\xf1" x
#define PS4_OPT_S2(x)		"\xf2" x

#define PS4_OPT_APPLET(var_name, init_macro) \
	enum { init_macro(__PS4_OPT_ENUM) }; \
	static const char var_name[] = __PS4_OPTAPPLET init_macro(__PS4_OPT_DESC);

#define PS4_OPT_GROUP(var_name, group_name, init_macro) \
	enum { init_macro(__PS4_OPT_ENUM) }; \
	static const char var_name[] = __PS4_OPTGROUP(group_name) init_macro(__PS4_OPT_DESC);

#define PS4_OPT_GROUP2(var_name, group_name, init_macro, init_macro2) \
	enum { init_macro(__PS4_OPT_ENUM) init_macro2(__PS4_OPT_ENUM) }; \
	static const char var_name[] = __PS4_OPTGROUP(group_name) init_macro(__PS4_OPT_DESC) init_macro2(__PS4_OPT_DESC);

#define PS4_OPTIONS_INIT 0xffff00

struct ps4_option_group {
	const char *desc;
	int (*parse)(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg);
};

struct ps4_applet {
	struct list_head node;

	const char *name;
	const struct ps4_option_group *optgroups[4];

	unsigned int remove_empty_arguments : 1;
	unsigned int open_flags, forced_force;
	int context_size;

	int (*main)(void *ctx, struct ps4_ctx *ac, struct ps4_string_array *args);
};

extern const struct ps4_option_group optgroup_global, optgroup_commit, optgroup_generation, optgroup_source;

void ps4_applet_register(struct ps4_applet *);
struct ps4_applet *ps4_applet_find(const char *name);
void ps4_applet_help(struct ps4_applet *applet, struct ps4_out *out);

#define PS4_DEFINE_APPLET(x) \
__attribute__((constructor)) static void __register_##x(void) { ps4_applet_register(&x); }

#endif
