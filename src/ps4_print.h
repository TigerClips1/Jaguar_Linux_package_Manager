/* ps4_print.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_PRINT_H
#define PS4_PRINT_H

#include <stdio.h>
#include "ps4_blob.h"

#define PS4_EXIT_STATUS_MAX_SIZE	128

const char *ps4_error_str(int error);
int ps4_exit_status_str(int status, char *buf, size_t sz);
int ps4_get_human_size_unit(ps4_blob_t b);
const char *ps4_get_human_size(off_t size, off_t *dest);
const char *ps4_last_path_segment(const char *);

struct ps4_url_print {
	const char *url;
	const char *pwmask;
	const char *url_or_host;
	size_t len_before_pw;
};

void ps4_url_parse(struct ps4_url_print *, const char *);

#define URL_FMT			"%.*s%s%s"
#define URL_PRINTF(u)		(int)u.len_before_pw, u.url, u.pwmask, u.url_or_host

struct ps4_out {
	int verbosity;
	unsigned int width, last_change;
	FILE *out, *err, *log;
};

static inline int ps4_out_verbosity(struct ps4_out *out) { return out->verbosity; }

// Pass this as the prefix to skip logging to the console (but still write to
// the log file).
#define PS4_OUT_LOG_ONLY ((const char*)-1)

#define ps4_err(out, args...)	do { ps4_out_fmt(out, "ERROR: ", args); } while (0)
#define ps4_out(out, args...)	do { ps4_out_fmt(out, NULL, args); } while (0)
#define ps4_warn(out, args...)	do { if (ps4_out_verbosity(out) >= 0) { ps4_out_fmt(out, "WARNING: ", args); } } while (0)
#define ps4_notice(out, args...) do { if (ps4_out_verbosity(out) >= 0) { ps4_out_fmt(out, "", args); } } while (0)
#define ps4_msg(out, args...)	do { if (ps4_out_verbosity(out) >= 1) { ps4_out_fmt(out, NULL, args); } } while (0)
#define ps4_dbg(out, args...)	do { if (ps4_out_verbosity(out) >= 2) { ps4_out_fmt(out, NULL, args); } } while (0)
#define ps4_dbg2(out, args...)	do { if (ps4_out_verbosity(out) >= 3) { ps4_out_fmt(out, NULL, args); } } while (0)

void ps4_out_reset(struct ps4_out *);
void ps4_out_fmt(struct ps4_out *, const char *prefix, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));
void ps4_out_log_argv(struct ps4_out *, char **argv);

struct ps4_progress {
	struct ps4_out *out;
	int fd, last_bar, last_percent;
	unsigned int last_out_change;
	size_t last_done;
	const char *progress_char;
};

void ps4_print_progress(struct ps4_progress *p, size_t done, size_t total);

struct ps4_indent {
	FILE *f;
	unsigned int x, indent, width;
};

void ps4_print_indented_init(struct ps4_indent *i, struct ps4_out *out, int err);
void ps4_print_indented_line(struct ps4_indent *i, const char *fmt, ...);
void ps4_print_indented_group(struct ps4_indent *i, int indent, const char *fmt, ...);
void ps4_print_indented_end(struct ps4_indent *i);
int  ps4_print_indented(struct ps4_indent *i, ps4_blob_t blob);
void ps4_print_indented_words(struct ps4_indent *i, const char *text);
void ps4_print_indented_fmt(struct ps4_indent *i, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
