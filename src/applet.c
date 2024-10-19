/* help.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <zlib.h>
#include "ps4_applet.h"
#include "ps4_print.h"
#include "help.h"

static LIST_HEAD(ps4_applet_list);

#define ps4_applet_foreach(iter) list_for_each_entry(iter, &ps4_applet_list, node)

void ps4_applet_register(struct ps4_applet *applet)
{
	list_init(&applet->node);
	list_add_tail(&applet->node, &ps4_applet_list);
}

struct ps4_applet *ps4_applet_find(const char *name)
{
	struct ps4_applet *a;

	ps4_applet_foreach(a) {
		if (strcmp(name, a->name) == 0)
			return a;
	}
	return NULL;
}

#ifndef NO_HELP
static inline int is_group(struct ps4_applet *applet, const char *topic)
{
	if (!applet) return strcasecmp(topic, "ps4") == 0;
	if (strcasecmp(topic, applet->name) == 0) return 1;
	for (int i = 0; applet->optgroups[i] && i < ARRAY_SIZE(applet->optgroups); i++)
		if (strcasecmp(applet->optgroups[i]->desc, topic) == 0) return 1;
	return 0;
}
#endif

void ps4_applet_help(struct ps4_applet *applet, struct ps4_out *out)
{
#ifndef NO_HELP
#ifdef COMPRESSED_HELP
	unsigned char buf[payload_help_size];
#endif
	const char *ptr = (const char *) payload_help, *base = ptr, *msg;
	unsigned long len = payload_help_size;
	int num = 0;

#ifdef COMPRESSED_HELP
	uncompress(buf, &len, payload_help, sizeof payload_help);
	ptr = base = (const char *) buf;
	len = sizeof buf;
#endif
	for (; *ptr && ptr < &base[len]; ptr = msg + strlen(msg) + 1) {
		msg = ptr + strlen(ptr) + 1;
		if (is_group(applet, ptr)) {
			fputc('\n', stdout);
			fwrite(msg, strlen(msg), 1, stdout);
			num++;
		}
	}
	if (num == 0) ps4_err(out, "Help not found");
#else
	fputc('\n', stdout);
	ps4_err(out, "This ps4-tools has been built without help");
#endif
}
