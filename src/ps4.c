/* ps4.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ps4_defines.h"
#include "ps4_database.h"
#include "ps4_applet.h"
#include "ps4_blob.h"
#include "ps4_print.h"
#include "ps4_io.h"
#include "ps4_fs.h"

#ifdef TEST_MODE
static const char *test_installed_db = NULL;
static const char *test_world = NULL;
static struct ps4_string_array *test_repos;
#endif

char **ps4_argv;

#ifdef TEST_MODE
time_t time(time_t *tloc)
{
	const time_t val = 1559567666;
	if (tloc) *tloc = val;
	return val;
}
#endif

static void version(struct ps4_out *out, const char *prefix)
{
	ps4_out_fmt(out, prefix, "ps4-tools " PS4_VERSION ", compiled for " PS4_DEFAULT_ARCH ".");
#ifdef TEST_MODE
	ps4_out_fmt(out, prefix, "TEST MODE BUILD. NOT FOR PRODUCTION USE.");
#endif
}

#define GLOBAL_OPTIONS(OPT) \
	OPT(OPT_GLOBAL_allow_untrusted,		"allow-untrusted") \
	OPT(OPT_GLOBAL_arch,			PS4_OPT_ARG "arch") \
	OPT(OPT_GLOBAL_cache_dir,		PS4_OPT_ARG "cache-dir") \
	OPT(OPT_GLOBAL_cache_max_age,		PS4_OPT_ARG "cache-max-age") \
	OPT(OPT_GLOBAL_force,			PS4_OPT_SH("f") "force") \
	OPT(OPT_GLOBAL_force_binary_stdout,	"force-binary-stdout") \
	OPT(OPT_GLOBAL_force_broken_world,	"force-broken-world") \
	OPT(OPT_GLOBAL_force_missing_repositories, "force-missing-repositories") \
	OPT(OPT_GLOBAL_force_no_chroot,		"force-no-chroot") \
	OPT(OPT_GLOBAL_force_non_repository,	"force-non-repository") \
	OPT(OPT_GLOBAL_force_old_ps4,		"force-old-ps4") \
	OPT(OPT_GLOBAL_force_overwrite,		"force-overwrite") \
	OPT(OPT_GLOBAL_force_refresh,		"force-refresh") \
	OPT(OPT_GLOBAL_help,			PS4_OPT_SH("h") "help") \
	OPT(OPT_GLOBAL_interactive,		PS4_OPT_SH("i") "interactive") \
	OPT(OPT_GLOBAL_keys_dir,		PS4_OPT_ARG "keys-dir") \
	OPT(OPT_GLOBAL_no_cache,		"no-cache") \
	OPT(OPT_GLOBAL_no_check_certificate,	"no-check-certificate") \
	OPT(OPT_GLOBAL_no_interactive,		"no-interactive") \
	OPT(OPT_GLOBAL_no_logfile,		"no-logfile") \
	OPT(OPT_GLOBAL_no_network,		"no-network") \
	OPT(OPT_GLOBAL_no_progress,		"no-progress") \
	OPT(OPT_GLOBAL_preserve_env,		"preserve-env") \
	OPT(OPT_GLOBAL_print_arch,		"print-arch") \
	OPT(OPT_GLOBAL_progress,		"progress") \
	OPT(OPT_GLOBAL_progress_fd,		PS4_OPT_ARG "progress-fd") \
	OPT(OPT_GLOBAL_purge,			"purge") \
	OPT(OPT_GLOBAL_quiet,			PS4_OPT_SH("q") "quiet") \
	OPT(OPT_GLOBAL_repositories_file,	PS4_OPT_ARG "repositories-file") \
	OPT(OPT_GLOBAL_repository,		PS4_OPT_ARG ps4_OPT_SH("X") "repository") \
	OPT(OPT_GLOBAL_root,			PS4_OPT_ARG ps4_OPT_SH("p") "root") \
	OPT(OPT_GLOBAL_timeout,			PS4_OPT_ARG "timeout") \
	OPT(OPT_GLOBAL_update_cache,		PS4_OPT_SH("U") "update-cache") \
	OPT(OPT_GLOBAL_verbose,			PS4_OPT_SH("v") "verbose") \
	OPT(OPT_GLOBAL_version,			PS4_OPT_SH("V") "version") \
	OPT(OPT_GLOBAL_wait,			PS4_OPT_ARG "wait") \

#define TEST_OPTIONS(OPT) \
	OPT(OPT_GLOBAL_test_instdb,		PS4_OPT_ARG "test-instdb") \
	OPT(OPT_GLOBAL_test_repo,		PS4_OPT_ARG "test-repo") \
	OPT(OPT_GLOBAL_test_world,		PS4_OPT_ARG "test-world")


#ifdef TEST_MODE
PS4_OPT_GROUP2(optiondesc_global, "Global", GLOBAL_OPTIONS, TEST_OPTIONS);
#else
PS4_OPT_GROUP(optiondesc_global, "Global", GLOBAL_OPTIONS);
#endif

static int option_parse_global(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	struct ps4_out *out = &ac->out;
	switch (opt) {
	case OPT_GLOBAL_help:
		return -EINVAL;
	case OPT_GLOBAL_root:
		ac->root = optarg;
		break;
	case OPT_GLOBAL_keys_dir:
		ac->keys_dir = optarg;
		break;
	case OPT_GLOBAL_repositories_file:
		ac->repositories_file = optarg;
		break;
	case OPT_GLOBAL_repository:
		ps4_string_array_add(&ac->repository_list, (char*) optarg);
		break;
	case OPT_GLOBAL_quiet:
		if (ac->out.verbosity) ac->out.verbosity--;
		break;
	case OPT_GLOBAL_verbose:
		ac->out.verbosity++;
		break;
	case OPT_GLOBAL_version:
		version(out, NULL);
		return -ESHUTDOWN;
	case OPT_GLOBAL_force:
		ac->force |= PS4_FORCE_OVERWRITE | PS4_FORCE_OLD_PS4
			| PS4_FORCE_BROKEN_WORLD | PS4_FORCE_NON_REPOSITORY
			| PS4_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_overwrite:
		ac->force |= PS4_FORCE_OVERWRITE;
		break;
	case OPT_GLOBAL_force_old_ps4:
		ac->force |= PS4_FORCE_OLD_PS4;
		break;
	case OPT_GLOBAL_force_broken_world:
		ac->force |= PS4_FORCE_BROKEN_WORLD;
		break;
	case OPT_GLOBAL_force_refresh:
		ac->force |= PS4_FORCE_REFRESH;
		break;
	case OPT_GLOBAL_force_no_chroot:
		ac->flags |= PS4_NO_CHROOT;
		break;
	case OPT_GLOBAL_force_non_repository:
		ac->force |= PS4_FORCE_NON_REPOSITORY;
		break;
	case OPT_GLOBAL_force_binary_stdout:
		ac->force |= PS4_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_missing_repositories:
		ac->force |= PS4_FORCE_MISSING_REPOSITORIES;
		break;
	case OPT_GLOBAL_interactive:
		ac->flags |= PS4_INTERACTIVE;
		break;
	case OPT_GLOBAL_no_interactive:
		ac->flags &= ~PS4_INTERACTIVE;
		break;
	case OPT_GLOBAL_preserve_env:
		ac->flags |= PS4_PRESERVE_ENV;
		break;
	case OPT_GLOBAL_progress:
		ac->progress.out = &ac->out;
		break;
	case OPT_GLOBAL_no_progress:
		ac->progress.out = NULL;
		break;
	case OPT_GLOBAL_progress_fd:
		ac->progress.fd = atoi(optarg);
		break;
	case OPT_GLOBAL_allow_untrusted:
		ac->flags |= PS4_ALLOW_UNTRUSTED;
		break;
	case OPT_GLOBAL_purge:
		ac->flags |= PS4_PURGE;
		break;
	case OPT_GLOBAL_wait:
		ac->lock_wait = atoi(optarg);
		break;
	case OPT_GLOBAL_no_logfile:
		ac->flags |= PS4_NO_LOGFILE;
		break;
	case OPT_GLOBAL_no_network:
		ac->flags |= PS4_NO_NETWORK;
		break;
	case OPT_GLOBAL_no_cache:
		ac->flags |= PS4_NO_CACHE;
		break;
	case OPT_GLOBAL_no_check_certificate:
		ps4_io_url_no_check_certificate();
		break;
	case OPT_GLOBAL_cache_dir:
		ac->cache_dir = optarg;
		break;
	case OPT_GLOBAL_update_cache:
		/* Make it one minute, to avoid updating indexes twice
		 * when doing self-upgrade's re-exec */
		ac->cache_max_age = 60;
		break;
	case OPT_GLOBAL_cache_max_age:
		ac->cache_max_age = atoi(optarg) * 60;
		break;
	case OPT_GLOBAL_timeout:
		ps4_io_url_set_timeout(atoi(optarg));
		break;
	case OPT_GLOBAL_arch:
		ac->arch = optarg;
		break;
	case OPT_GLOBAL_print_arch:
		puts(PS4_DEFAULT_ARCH);
		return -ESHUTDOWN;
#ifdef TEST_MODE
	case OPT_GLOBAL_test_repo:
		ps4_string_array_add(&test_repos, (char*) optarg);
		break;
	case OPT_GLOBAL_test_instdb:
		test_installed_db = optarg;
		break;
	case OPT_GLOBAL_test_world:
		test_world = optarg;
		break;
#endif
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct ps4_option_group optgroup_global = {
	.desc = optiondesc_global,
	.parse = option_parse_global,
};

#define COMMIT_OPTIONS(OPT) \
	OPT(OPT_COMMIT_clean_protected,		"clean-protected") \
	OPT(OPT_COMMIT_initramfs_diskless_boot,	"initramfs-diskless-boot") \
	OPT(OPT_COMMIT_no_commit_hooks,		"no-commit-hooks") \
	OPT(OPT_COMMIT_no_scripts,		"no-scripts") \
	OPT(OPT_COMMIT_overlay_from_stdin,	"overlay-from-stdin") \
	OPT(OPT_COMMIT_simulate,		PS4_OPT_SH("s") "simulate")

PS4_OPT_GROUP(optiondesc_commit, "Commit", COMMIT_OPTIONS);

static int option_parse_commit(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	switch (opt) {
	case OPT_COMMIT_simulate:
		ac->flags |= PS4_SIMULATE;
		break;
	case OPT_COMMIT_clean_protected:
		ac->flags |= PS4_CLEAN_PROTECTED;
		break;
	case OPT_COMMIT_overlay_from_stdin:
		ac->flags |= PS4_OVERLAY_FROM_STDIN;
		break;
	case OPT_COMMIT_no_scripts:
		ac->flags |= PS4_NO_SCRIPTS;
		break;
	case OPT_COMMIT_no_commit_hooks:
		ac->flags |= PS4_NO_COMMIT_HOOKS;
		break;
	case OPT_COMMIT_initramfs_diskless_boot:
		ac->open_flags |= PS4_OPENF_CREATE;
		ac->flags |= PS4_NO_COMMIT_HOOKS;
		ac->force |= PS4_FORCE_OVERWRITE | PS4_FORCE_OLD_PS4
			|  PS4_FORCE_BROKEN_WORLD | PS4_FORCE_NON_REPOSITORY;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct ps4_option_group optgroup_commit = {
	.desc = optiondesc_commit,
	.parse = option_parse_commit,
};

#define SOURCE_OPTIONS(OPT) \
	OPT(OPT_SOURCE_from,		PS4_OPT_ARG "from")

PS4_OPT_GROUP(optiondesc_source, "Source", SOURCE_OPTIONS);

static int option_parse_source(void *ctx, struct ps4_ctx *ac, int opt, const char *optarg)
{
	const unsigned long all_flags = PS4_OPENF_NO_SYS_REPOS | PS4_OPENF_NO_INSTALLED_REPO | PS4_OPENF_NO_INSTALLED;
	unsigned long flags;

	switch (opt) {
	case OPT_SOURCE_from:
		if (strcmp(optarg, "none") == 0) {
			flags = PS4_OPENF_NO_SYS_REPOS | PS4_OPENF_NO_INSTALLED_REPO | PS4_OPENF_NO_INSTALLED;
		} else if (strcmp(optarg, "repositories") == 0) {
			flags = PS4_OPENF_NO_INSTALLED_REPO | PS4_OPENF_NO_INSTALLED;
		} else if (strcmp(optarg, "installed") == 0) {
			flags = PS4_OPENF_NO_SYS_REPOS;
		} else if (strcmp(optarg, "system") == 0) {
			flags = 0;
		} else
			return -ENOTSUP;

		ac->open_flags &= ~all_flags;
		ac->open_flags |= flags;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct ps4_option_group optgroup_source = {
	.desc = optiondesc_source,
	.parse = option_parse_source,
};

static int usage(struct ps4_out *out, struct ps4_applet *applet)
{
	version(out, NULL);
	ps4_applet_help(applet, out);
	return 1;
}

static struct ps4_applet *deduce_applet(int argc, char **argv)
{
	struct ps4_applet *a;
	const char *prog;
	int i;

	prog = strrchr(argv[0], '/');
	if (prog == NULL)
		prog = argv[0];
	else
		prog++;

	if (strncmp(prog, "ps4_", 4) == 0)
		return ps4_applet_find(prog + 4);

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') continue;
		a = ps4_applet_find(argv[i]);
		if (a) return a;
	}

	return NULL;
}

static int parse_options(int argc, char **argv, struct ps4_applet *applet, void *ctx, struct ps4_ctx *ac)
{
	struct ps4_out *out = &ac->out;
	const struct ps4_option_group *default_optgroups[] = { &optgroup_global, NULL };
	const struct ps4_option_group *og, **optgroups = default_optgroups;
	struct option all_options[80], *opt;
	char short_options[256], *sopt;
	unsigned short short_option_val[64];
	int r, p, num_short;

	memset(short_option_val, 0, sizeof short_option_val);

	if (applet && applet->optgroups[0]) optgroups = applet->optgroups;

	for (p = 0, opt = &all_options[0], sopt = short_options; (og = optgroups[p]) != 0; p++) {
		assert(opt < &all_options[ARRAY_SIZE(all_options)]);
		assert(sopt < &short_options[sizeof short_options]);
		const char *d = og->desc + strlen(og->desc) + 1;
		for (r = 0; *d; r++) {
			opt->val = (p << 10) + r;
			opt->flag = 0;
			opt->has_arg = no_argument;
			if ((unsigned char)*d == 0xaf) {
				opt->has_arg = required_argument;
				d++;
			}
			num_short = 0;
			if ((unsigned char)*d >= 0xf0)
				num_short = *d++ & 0x0f;
			for (; num_short > 0; num_short--) {
				unsigned char ch = *(unsigned char *)d;
				assert(ch >= 64 && ch < 128);
				short_option_val[ch-64] = opt->val;
				*sopt++ = *d++;
				if (opt->has_arg != no_argument)
					*sopt++ = ':';
			}
			opt->name = d;
			opt++;
			d += strlen(d) + 1;
		}
	}
	opt->name = 0;
	*sopt = 0;

	while ((p = getopt_long(argc, argv, short_options, all_options, NULL)) != -1) {
		if (p >= 64 && p < 128) p = short_option_val[p - 64];
		og = optgroups[p >> 10];
		r = og->parse(ctx, ac, p & 0x3ff, optarg);
		if (r == 0) continue;
		if (r == -EINVAL || r == -ENOTSUP)
			return usage(out, applet);
		return r;
	}

	return 0;
}

static void setup_automatic_flags(struct ps4_ctx *ac)
{
	const char *tmp;

	if ((tmp = getenv("PS4_PROGRESS_CHAR")) != NULL)
		ac->progress.progress_char = tmp;
	else if ((tmp = getenv("LANG")) != NULL && strstr(tmp, "UTF-8") != NULL)
		ac->progress.progress_char = "\u2588";
	else
		ac->progress.progress_char = "#";

	if (!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO) ||
	    !isatty(STDIN_FILENO))
		return;

	/* Enable progress bar by default, except on dumb terminals. */
	if (!(tmp = getenv("TERM")) || strcmp(tmp, "dumb") != 0)
		ac->progress.out = &ac->out;

	if (!(ac->flags & PS4_SIMULATE) &&
	    access("/etc/ps4/interactive", F_OK) == 0)
		ac->flags |= PS4_INTERACTIVE;
}

static struct ps4_ctx ctx;
static struct ps4_database db;

static void on_sigint(int s)
{
	ps4_db_close(&db);
	exit(128 + s);
}

static void on_sigwinch(int s)
{
	ps4_out_reset(&ctx.out);
}

static void setup_terminal(void)
{
	static char buf[200];
	setvbuf(stderr, buf, _IOLBF, sizeof buf);
	signal(SIGWINCH, on_sigwinch);
	signal(SIGPIPE, SIG_IGN);
}

static int remove_empty_strings(int count, char **args)
{
	int i, j;
	for (i = j = 0; i < count; i++) {
		args[j] = args[i];
		if (args[j][0]) j++;
	}
	return j;
}

static void redirect_callback(int code, const char *url)
{
	ps4_warn(&ctx.out, "Permanently redirected to %s", url);
}

int main(int argc, char **argv)
{
	void *applet_ctx = NULL;
	struct ps4_out *out = &ctx.out;
	struct ps4_string_array *args;
	struct ps4_applet *applet;
	int r;

	ps4_string_array_init(&args);
#ifdef TEST_MODE
	ps4_string_array_init(&test_repos);
#endif

	ps4_argv = malloc(sizeof(char*[argc+2]));
	memcpy(ps4_argv, argv, sizeof(char*[argc]));
	ps4_argv[argc] = NULL;
	ps4_argv[argc+1] = NULL;

	ps4_ctx_init(&ctx);
	umask(0);
	setup_terminal();

	applet = deduce_applet(argc, argv);
	if (applet != NULL) {
		if (applet->context_size != 0)
			applet_ctx = calloc(1, applet->context_size);
		ctx.open_flags = applet->open_flags;
		ctx.force |= applet->forced_force;
		for (int i = 0; applet->optgroups[i]; i++)
			applet->optgroups[i]->parse(applet_ctx, &ctx, PS4_OPTIONS_INIT, NULL);
	}

	ps4_crypto_init();
	setup_automatic_flags(&ctx);
	ps4_io_url_init();
	ps4_io_url_set_timeout(60);
	ps4_io_url_set_redirect_callback(redirect_callback);

	r = parse_options(argc, argv, applet, applet_ctx, &ctx);
	if (r != 0) goto err;

	if (applet == NULL) {
		if (argc > 1) {
			ps4_err(out, "'%s' is not an ps4 command. See 'ps4 --help'.", argv[1]);
			return 1;
		}
		return usage(out, NULL);
	}

	argc -= optind;
	argv += optind;
	if (argc >= 1 && strcmp(argv[0], applet->name) == 0) {
		argc--;
		argv++;
	}
	if (applet->remove_empty_arguments)
		argc = remove_empty_strings(argc, argv);

	ps4_db_init(&db);
	signal(SIGINT, on_sigint);

#ifdef TEST_MODE
	ctx.open_flags &= ~(PS4_OPENF_WRITE | PS4_OPENF_CACHE_WRITE | PS4_OPENF_CREATE);
	ctx.open_flags |= PS4_OPENF_READ | PS4_OPENF_NO_STATE | PS4_OPENF_NO_REPOS;
	ctx.flags |= PS4_SIMULATE;
	ctx.flags &= ~PS4_INTERACTIVE;
	db.active_layers = BIT(0);
#endif

	r = ps4_ctx_prepare(&ctx);
	if (r != 0) goto err;

	ps4_out_log_argv(&ctx.out, ps4_argv);
	version(&ctx.out, PS4_OUT_LOG_ONLY);

	if (ctx.open_flags) {
		r = ps4_db_open(&db, &ctx);
		if (r != 0) {
			ps4_err(out, "Failed to open ps4 database: %s", ps4_error_str(r));
			goto err;
		}
	}

#ifdef TEST_MODE
	if (test_world != NULL) {
		ps4_blob_t b = PS4_BLOB_STR(test_world);
		ps4_blob_pull_deps(&b, &db, &db.world);
	}
	if (test_installed_db != NULL) {
		ps4_db_index_read(&db, ps4_istream_from_file(AT_FDCWD, test_installed_db), -1);
	}
	for (int i = 0; i < ps4_array_len(test_repos); i++) {
		ps4_blob_t spec = PS4_BLOB_STR(test_repos->item[i]), name, tag;
		int repo_tag = 0, repo = PS4_REPOSITORY_FIRST_CONFIGURED + i;

		if (spec.ptr[0] == '!') {
			/* cache's installed repository */
			spec.ptr++;
			spec.len--;
			repo = -2;
		}

		if (ps4_blob_split(spec, PS4_BLOB_STR(":"), &tag, &name)) {
			repo_tag = ps4_db_get_tag_id(&db, tag);
		} else {
			name = spec;
		}

		r = ps4_db_index_read(&db, ps4_istream_from_file(AT_FDCWD, name.ptr), repo);
		if (r != 0) {
			ps4_err(out, "Failed to open test repository " BLOB_FMT " : %s", BLOB_PRINTF(name), ps4_error_str(r));
			goto err;
		}

		if (repo != -2) {
			if (!(ctx.flags & PS4_NO_NETWORK))
				db.available_repos |= BIT(repo);
			db.repo_tags[repo_tag].allowed_repos |= BIT(repo);
		}
	}
	ps4_string_array_free(&test_repos);
#endif

	ps4_string_array_resize(&args, 0, argc);
	for (r = 0; r < argc; r++) ps4_string_array_add(&args, argv[r]);
	ps4_io_url_set_redirect_callback(NULL);

	r = applet->main(applet_ctx, &ctx, args);
	signal(SIGINT, SIG_IGN);
	ps4_db_close(&db);

#ifdef TEST_MODE
	/* in test mode, we need to always exit 0 since xargs dies otherwise */
	r = 0;
#endif

err:
	if (r == -ESHUTDOWN) r = 0;
	if (applet_ctx) free(applet_ctx);

	ps4_ctx_free(&ctx);
	ps4_string_array_free(&args);
	free(ps4_argv);

	if (r < 0) r = 250;
	if (r > 99) r = 99;
	return r;
}
