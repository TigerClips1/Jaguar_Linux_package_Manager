/* commit.c -  PS4linux package manager (PS4)
 * Apply solver calculated changes to database.
 *
 * Copyright (C) 2008-2013 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include "ps4_defines.h"
#include "ps4_database.h"
#include "ps4_package.h"
#include "ps4_solver.h"

#include "ps4_print.h"

struct ps4_stats {
	size_t bytes;
	unsigned int changes;
	unsigned int packages;
};

struct progress {
	struct ps4_progress prog;
	struct ps4_stats done;
	struct ps4_stats total;
	struct ps4_package *pkg;
	int total_changes_digits;
};

static inline int pkg_available(struct ps4_database *db, struct ps4_package *pkg)
{
	if (pkg->repos & db->available_repos)
		return TRUE;
	return FALSE;
}

static int print_change(struct ps4_database *db, struct ps4_change *change,
			struct progress *prog)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_name *name;
	struct ps4_package *oldpkg = change->old_pkg;
	struct ps4_package *newpkg = change->new_pkg;
	const char *msg = NULL;
	char status[32];
	ps4_blob_t *oneversion = NULL;
	int r;

	snprintf(status, sizeof status, "(%*i/%i)",
		prog->total_changes_digits, prog->done.changes+1,
		prog->total.changes);

	name = newpkg ? newpkg->name : oldpkg->name;
	if (oldpkg == NULL) {
		msg = "Installing";
		oneversion = newpkg->version;
	} else if (newpkg == NULL) {
		msg = "Purging";
		oneversion = oldpkg->version;
	} else if (newpkg == oldpkg) {
		if (change->reinstall) {
			if (pkg_available(db, newpkg))
				msg = "Reinstalling";
			else
				msg = "[ps4 unavailable, skipped] Reinstalling";
		} else if (change->old_repository_tag != change->new_repository_tag) {
			msg = "Updating pinning";
		}
		oneversion = newpkg->version;
	} else {
		r = ps4_pkg_version_compare(newpkg, oldpkg);
		switch (r) {
		case PS4_VERSION_LESS:
			msg = "Downgrading";
			break;
		case PS4_VERSION_EQUAL:
			msg = "Replacing";
			break;
		case PS4_VERSION_GREATER:
			msg = "Upgrading";
			break;
		}
	}
	if (msg == NULL)
		return FALSE;

	if (oneversion) {
		ps4_msg(out, "%s %s %s" BLOB_FMT " (" BLOB_FMT ")",
			status, msg,
			name->name,
			BLOB_PRINTF(db->repo_tags[change->new_repository_tag].tag),
			BLOB_PRINTF(*oneversion));
	} else {
		ps4_msg(out, "%s %s %s" BLOB_FMT " (" BLOB_FMT " -> " BLOB_FMT ")",
			status, msg,
			name->name,
			BLOB_PRINTF(db->repo_tags[change->new_repository_tag].tag),
			BLOB_PRINTF(*oldpkg->version),
			BLOB_PRINTF(*newpkg->version));
	}
	return TRUE;
}

static void count_change(struct ps4_change *change, struct ps4_stats *stats)
{
	if (change->new_pkg != change->old_pkg || change->reinstall) {
		if (change->new_pkg != NULL) {
			stats->bytes += change->new_pkg->installed_size;
			stats->packages++;
		}
		if (change->old_pkg != NULL)
			stats->packages++;
		stats->changes++;
	} else if (change->new_repository_tag != change->old_repository_tag) {
		stats->packages++;
		stats->changes++;
	}
}

static void progress_cb(void *ctx, size_t installed_bytes)
{
	struct progress *prog = (struct progress *) ctx;
	ps4_print_progress(&prog->prog,
			   prog->done.bytes + prog->done.packages + installed_bytes,
			   prog->total.bytes + prog->total.packages);
}

static int dump_packages(struct ps4_out *out, struct ps4_change_array *changes,
			 int (*cmp)(struct ps4_change *change),
			 const char *msg)
{
	struct ps4_change *change;
	struct ps4_name *name;
	struct ps4_indent indent;
	int match = 0;

	ps4_print_indented_init(&indent, out, 0);
	foreach_array_item(change, changes) {
		if (!cmp(change)) continue;
		if (!match) ps4_print_indented_group(&indent, 2, "%s:\n", msg);
		if (change->new_pkg != NULL)
			name = change->new_pkg->name;
		else
			name = change->old_pkg->name;

		ps4_print_indented(&indent, PS4_BLOB_STR(name->name));
		match++;
	}
	ps4_print_indented_end(&indent);
	return match;
}

static int sort_change(const void *a, const void *b)
{
	const struct ps4_change *ca = a;
	const struct ps4_change *cb = b;
	const struct ps4_name *na = ca->old_pkg ? ca->old_pkg->name : ca->new_pkg->name;
	const struct ps4_name *nb = cb->old_pkg ? cb->old_pkg->name : cb->new_pkg->name;
	return ps4_name_cmp_display(na, nb);
}

static int cmp_remove(struct ps4_change *change)
{
	return change->new_pkg == NULL;
}

static int cmp_new(struct ps4_change *change)
{
	return change->old_pkg == NULL;
}

static int cmp_reinstall(struct ps4_change *change)
{
	return change->reinstall;
}

static int cmp_downgrade(struct ps4_change *change)
{
	if (change->new_pkg == NULL || change->old_pkg == NULL)
		return 0;
	if (ps4_pkg_version_compare(change->new_pkg, change->old_pkg)
	    & PS4_VERSION_LESS)
		return 1;
	return 0;
}

static int cmp_upgrade(struct ps4_change *change)
{
	if (change->new_pkg == NULL || change->old_pkg == NULL)
		return 0;

	/* Count swapping package as upgrade too - this can happen if
	 * same package version is used after it was rebuilt against
	 * newer libraries. Basically, different (and probably newer)
	 * package, but equal version number. */
	if ((ps4_pkg_version_compare(change->new_pkg, change->old_pkg) &
	     (PS4_VERSION_GREATER | PS4_VERSION_EQUAL)) &&
	    (change->new_pkg != change->old_pkg))
		return 1;

	return 0;
}

static int run_triggers(struct ps4_database *db, struct ps4_changeset *changeset)
{
	struct ps4_change *change;
	struct ps4_installed_package *ipkg;
	int errors = 0;

	if (ps4_db_fire_triggers(db) == 0)
		return 0;

	foreach_array_item(change, changeset->changes) {
		struct ps4_package *pkg = change->new_pkg;
		if (pkg == NULL)
			continue;
		ipkg = pkg->ipkg;
		if (ipkg == NULL || ps4_array_len(ipkg->pending_triggers) == 0)
			continue;

		ps4_string_array_add(&ipkg->pending_triggers, NULL);
		errors += ps4_ipkg_run_script(ipkg, db, PS4_SCRIPT_TRIGGER,
					      ipkg->pending_triggers->item) != 0;
		ps4_string_array_free(&ipkg->pending_triggers);
	}
	return errors;
}

#define PRE_COMMIT_HOOK		0
#define POST_COMMIT_HOOK	1

struct ps4_commit_hook {
	struct ps4_database *db;
	int type;
};

static int run_commit_hook(void *ctx, int dirfd, const char *file)
{
	static char *const commit_hook_str[] = { "pre-commit", "post-commit" };
	struct ps4_commit_hook *hook = (struct ps4_commit_hook *) ctx;
	struct ps4_database *db = hook->db;
	struct ps4_out *out = &db->ctx->out;
	char fn[PATH_MAX], *argv[] = { fn, (char *) commit_hook_str[hook->type], NULL };

	if (file[0] == '.') return 0;
	if ((db->ctx->flags & (PS4_NO_SCRIPTS | PS4_SIMULATE)) != 0) return 0;

	snprintf(fn, sizeof(fn), "etc/ps4/commit_hooks.d/%s", file);
	if ((db->ctx->flags & PS4_NO_COMMIT_HOOKS) != 0) {
		ps4_msg(out, "Skipping: %s %s", fn, commit_hook_str[hook->type]);
		return 0;
	}
	ps4_dbg(out, "Executing: %s %s", fn, commit_hook_str[hook->type]);

	if (ps4_db_run_script(db, fn, argv) < 0 && hook->type == PRE_COMMIT_HOOK)
		return -2;

	return 0;
}

static int run_commit_hooks(struct ps4_database *db, int type)
{
	struct ps4_commit_hook hook = { .db = db, .type = type };
	return ps4_dir_foreach_file(openat(db->root_fd, "etc/ps4/commit_hooks.d", O_RDONLY | O_CLOEXEC),
				    run_commit_hook, &hook);
}

static int calc_precision(unsigned int num)
{
	int precision = 1;
	while (num >= 10) {
		precision++;
		num /= 10;
	}
	return precision;
}

int ps4_solver_commit_changeset(struct ps4_database *db,
				struct ps4_changeset *changeset,
				struct ps4_dependency_array *world)
{
	struct ps4_out *out = &db->ctx->out;
	struct progress prog = { .prog = db->ctx->progress };
	struct ps4_change *change;
	char buf[32];
	const char *size_unit;
	off_t humanized, size_diff = 0, download_size = 0;
	int r, errors = 0, pkg_diff = 0;

	assert(world);
	if (ps4_db_check_world(db, world) != 0) {
		ps4_err(out, "Not committing changes due to missing repository tags. "
			"Use --force-broken-world to override.");
		return -1;
	}

	if (changeset->changes == NULL)
		goto all_done;

	/* Count what needs to be done */
	foreach_array_item(change, changeset->changes) {
		count_change(change, &prog.total);
		if (change->new_pkg) {
			size_diff += change->new_pkg->installed_size;
			pkg_diff++;
			if (change->new_pkg != change->old_pkg &&
			    !(change->new_pkg->repos & db->local_repos))
				download_size += change->new_pkg->size;
		}
		if (change->old_pkg) {
			size_diff -= change->old_pkg->installed_size;
			pkg_diff--;
		}
	}
	prog.total_changes_digits = calc_precision(prog.total.changes);

	if ((ps4_out_verbosity(out) > 1 || (db->ctx->flags & PS4_INTERACTIVE)) &&
	    !(db->ctx->flags & PS4_SIMULATE)) {
		struct ps4_change_array *sorted;

		ps4_change_array_init(&sorted);
		ps4_change_array_copy(&sorted, changeset->changes);
		ps4_array_qsort(sorted, sort_change);

		r = dump_packages(out, sorted, cmp_remove,
				  "The following packages will be REMOVED");
		r += dump_packages(out, sorted, cmp_downgrade,
				   "The following packages will be DOWNGRADED");
		if (r || (db->ctx->flags & PS4_INTERACTIVE) || ps4_out_verbosity(out) > 2) {
			r += dump_packages(out, sorted, cmp_new,
					   "The following NEW packages will be installed");
			r += dump_packages(out, sorted, cmp_upgrade,
					   "The following packages will be upgraded");
			r += dump_packages(out, sorted, cmp_reinstall,
					   "The following packages will be reinstalled");
			if (download_size) {
				size_unit = ps4_get_human_size(download_size, &humanized);
				ps4_msg(out, "Need to download %lld %s of packages.",
					(long long)humanized, size_unit);
			}
			size_unit = ps4_get_human_size(llabs(size_diff), &humanized);
			ps4_msg(out, "After this operation, %lld %s of %s.",
				(long long)humanized,
				size_unit,
				(size_diff < 0) ?
				"disk space will be freed" :
				"additional disk space will be used");
		}
		ps4_change_array_free(&sorted);

		if (r > 0 && (db->ctx->flags & PS4_INTERACTIVE)) {
			printf("Do you want to continue [Y/n]? ");
			fflush(stdout);
			r = fgetc(stdin);
			if (r != 'y' && r != 'Y' && r != '\n' && r != EOF)
				return -1;
		}
	}

	if (run_commit_hooks(db, PRE_COMMIT_HOOK) == -2)
		return -1;

	/* Go through changes */
	foreach_array_item(change, changeset->changes) {
		r = change->old_pkg &&
			(change->old_pkg->ipkg->broken_files ||
			 change->old_pkg->ipkg->broken_script);
		if (print_change(db, change, &prog)) {
			prog.pkg = change->new_pkg;
			progress_cb(&prog, 0);

			if (!(db->ctx->flags & PS4_SIMULATE) &&
			    ((change->old_pkg != change->new_pkg) ||
			     (change->reinstall && pkg_available(db, change->new_pkg)))) {
				r = ps4_db_install_pkg(db, change->old_pkg, change->new_pkg,
						       progress_cb, &prog) != 0;
			}
			if (r == 0 && change->new_pkg && change->new_pkg->ipkg)
				change->new_pkg->ipkg->repository_tag = change->new_repository_tag;
		}
		errors += r;
		count_change(change, &prog.done);
	}
	ps4_print_progress(&prog.prog, prog.total.bytes + prog.total.packages,
			   prog.total.bytes + prog.total.packages);

	errors += db->num_dir_update_errors;
	errors += run_triggers(db, changeset);

all_done:
	ps4_dependency_array_copy(&db->world, world);
	if (ps4_db_write_config(db) != 0) errors++;
	run_commit_hooks(db, POST_COMMIT_HOOK);

	if (!db->performing_self_upgrade) {
		if (errors)
			snprintf(buf, sizeof(buf), "%d error%s;", errors,
				 errors > 1 ? "s" : "");
		else
			strcpy(buf, "OK:");

		off_t installed_bytes = db->installed.stats.bytes;
		int installed_packages = db->installed.stats.packages;
		if (db->ctx->flags & PS4_SIMULATE) {
			installed_bytes += size_diff;
			installed_packages += pkg_diff;
		}

		if (ps4_out_verbosity(out) > 1) {
			ps4_msg(out, "%s %d packages, %d dirs, %d files, %zu MiB",
				buf,
				installed_packages,
				db->installed.stats.dirs,
				db->installed.stats.files,
				installed_bytes / (1024 * 1024)
				);
		} else {
			ps4_msg(out, "%s %zu MiB in %d packages",
				buf,
				installed_bytes / (1024 * 1024),
				installed_packages);
		}
	}
	return errors;
}

enum {
	STATE_PRESENT		= 0x80000000,
	STATE_MISSING		= 0x40000000,
	STATE_VIRTUAL_ONLY	= 0x20000000,
	STATE_INSTALLIF		= 0x10000000,
	STATE_COUNT_MASK	= 0x0000ffff,
};

struct print_state {
	struct ps4_database *db;
	struct ps4_dependency_array *world;
	struct ps4_indent i;
	const char *label;
	int num_labels;
	int match;
};

static void label_start(struct print_state *ps, const char *text)
{
	if (ps->label) {
		ps4_print_indented_line(&ps->i, "  %s:\n", ps->label);
		ps->label = NULL;
		ps->num_labels++;
	}
	if (!ps->i.x) ps4_print_indented_group(&ps->i, 0, "    %s", text);
}
static void label_end(struct print_state *ps)
{
	ps4_print_indented_end(&ps->i);
}

static void print_pinning_errors(struct print_state *ps, struct ps4_package *pkg, unsigned int tag)
{
	struct ps4_database *db = ps->db;
	int i;

	if (pkg->ipkg != NULL)
		return;

	if (!(pkg->repos & db->available_repos)) {
		label_start(ps, "masked in:");
		ps4_print_indented_fmt(&ps->i, "--no-network");
	} else if (!(BIT(pkg->layer) & db->active_layers)) {
		label_start(ps, "masked in:");
		ps4_print_indented_fmt(&ps->i, "layer");
	} else if (pkg->repos == BIT(PS4_REPOSITORY_CACHED) && !pkg->filename_ndx) {
		label_start(ps, "masked in:");
		ps4_print_indented_fmt(&ps->i, "cache");
	} else {
		if (pkg->repos & ps4_db_get_pinning_mask_repos(db, PS4_DEFAULT_PINNING_MASK | BIT(tag)))
			return;
		for (i = 0; i < db->num_repo_tags; i++) {
			if (pkg->repos & db->repo_tags[i].allowed_repos) {
				label_start(ps, "masked in:");
				ps4_print_indented(&ps->i, db->repo_tags[i].tag);
			}
		}
	}
	label_end(ps);
}

static void print_conflicts(struct print_state *ps, struct ps4_package *pkg)
{
	struct ps4_provider *p;
	struct ps4_dependency *d;
	int once;

	foreach_array_item(p, pkg->name->providers) {
		if (p->pkg == pkg || !p->pkg->marked)
			continue;
		label_start(ps, "conflicts:");
		ps4_print_indented_fmt(&ps->i, PKG_VER_FMT, PKG_VER_PRINTF(p->pkg));
	}
	foreach_array_item(d, pkg->provides) {
		once = 1;
		foreach_array_item(p, d->name->providers) {
			if (!p->pkg->marked)
				continue;
			if (d->version == &ps4_atom_null &&
			    p->version == &ps4_atom_null)
				continue;
			if (once && p->pkg == pkg &&
			    p->version == d->version) {
				once = 0;
				continue;
			}
			label_start(ps, "conflicts:");
			ps4_print_indented_fmt(
				&ps->i, PKG_VER_FMT "[" DEP_FMT "]",
				PKG_VER_PRINTF(p->pkg),
				DEP_PRINTF(d));
		}
	}
	label_end(ps);
}

static void print_dep(struct ps4_package *pkg0, struct ps4_dependency *d0, struct ps4_package *pkg, void *ctx)
{
	struct print_state *ps = (struct print_state *) ctx;
	const char *label = (ps->match & PS4_DEP_SATISFIES) ? "satisfies:" : "breaks:";

	label_start(ps, label);
	if (pkg0 == NULL)
		ps4_print_indented_fmt(&ps->i, "world[" DEP_FMT "]", DEP_PRINTF(d0));
	else
		ps4_print_indented_fmt(&ps->i, PKG_VER_FMT "[" DEP_FMT "]",
				       PKG_VER_PRINTF(pkg0),
				       DEP_PRINTF(d0));
}

static void print_deps(struct print_state *ps, struct ps4_package *pkg, int match)
{
	ps->match = match;
	match |= PS4_FOREACH_MARKED | PS4_FOREACH_DEP;
	ps4_pkg_foreach_matching_dependency(NULL, ps->world, match|ps4_foreach_genid(), pkg, print_dep, ps);
	ps4_pkg_foreach_reverse_dependency(pkg, match|ps4_foreach_genid(), print_dep, ps);
	label_end(ps);
}

static void print_broken_deps(struct print_state *ps, struct ps4_dependency_array *deps, const char *label)
{
	struct ps4_dependency *dep;

	foreach_array_item(dep, deps) {
		if (!dep->broken) continue;
		label_start(ps, label);
		ps4_print_indented_fmt(&ps->i, DEP_FMT, DEP_PRINTF(dep));
	}
	label_end(ps);
}

static void analyze_package(struct print_state *ps, struct ps4_package *pkg, unsigned int tag)
{
	char pkgtext[256];

	snprintf(pkgtext, sizeof(pkgtext), PKG_VER_FMT, PKG_VER_PRINTF(pkg));
	ps->label = pkgtext;

	if (pkg->uninstallable) {
		label_start(ps, "error:");
		ps4_print_indented_fmt(&ps->i, "uninstallable");
		label_end(ps);
		print_broken_deps(ps, pkg->depends, "depends:");
		print_broken_deps(ps, pkg->provides, "provides:");
		print_broken_deps(ps, pkg->install_if, "install_if:");
	}

	print_pinning_errors(ps, pkg, tag);
	print_conflicts(ps, pkg);
	print_deps(ps, pkg, PS4_DEP_CONFLICTS);
	if (ps->label == NULL)
		print_deps(ps, pkg, PS4_DEP_SATISFIES);
}

static void analyze_missing_name(struct print_state *ps, struct ps4_name *name)
{
	struct ps4_name **pname0, *name0;
	struct ps4_provider *p0;
	struct ps4_dependency *d0;
	char tmp[256];
	unsigned int genid;
	int refs;

	if (ps4_array_len(name->providers) != 0) {
		snprintf(tmp, sizeof(tmp), "%s (virtual)", name->name);
		ps->label = tmp;

		label_start(ps, "note:");
		ps4_print_indented_words(&ps->i, "please select one of the 'provided by' packages explicitly");
		label_end(ps);

		label_start(ps, "provided by:");
		foreach_array_item(p0, name->providers)
			p0->pkg->name->state_int++;
		foreach_array_item(p0, name->providers) {
			name0 = p0->pkg->name;
			refs = (name0->state_int & STATE_COUNT_MASK);
			if (refs == ps4_array_len(name0->providers)) {
				/* name only */
				ps4_print_indented(&ps->i, PS4_BLOB_STR(name0->name));
				name0->state_int &= ~STATE_COUNT_MASK;
			} else if (refs > 0) {
				/* individual package */
				ps4_print_indented_fmt(&ps->i, PKG_VER_FMT, PKG_VER_PRINTF(p0->pkg));
				name0->state_int--;
			}
		}
		label_end(ps);
	} else {
		snprintf(tmp, sizeof(tmp), "%s (no such package)", name->name);
		ps->label = tmp;
	}

	label_start(ps, "required by:");
	foreach_array_item(d0, ps->world) {
		if (d0->name != name || ps4_dep_conflict(d0))
			continue;
		ps4_print_indented_fmt(&ps->i, "world[" DEP_FMT "]",
			DEP_PRINTF(d0));
	}
	genid = ps4_foreach_genid();
	foreach_array_item(pname0, name->rdepends) {
		name0 = *pname0;
		foreach_array_item(p0, name0->providers) {
			if (!p0->pkg->marked)
				continue;
			if (p0->pkg->foreach_genid == genid)
				continue;
			p0->pkg->foreach_genid = genid;
			foreach_array_item(d0, p0->pkg->depends) {
				if (d0->name != name || ps4_dep_conflict(d0))
					continue;
				ps4_print_indented_fmt(&ps->i,
					PKG_VER_FMT "[" DEP_FMT "]",
					PKG_VER_PRINTF(p0->pkg),
					DEP_PRINTF(d0));
				break;
			}
			if (d0 != NULL)
				break;
		}
	}
	label_end(ps);
}

static void analyze_deps(struct print_state *ps, struct ps4_dependency_array *deps)
{
	struct ps4_dependency *d0;
	struct ps4_name *name0;

	foreach_array_item(d0, deps) {
		name0 = d0->name;
		if (ps4_dep_conflict(d0)) continue;
		if ((name0->state_int & (STATE_INSTALLIF | STATE_PRESENT | STATE_MISSING)) != 0)
			continue;
		name0->state_int |= STATE_MISSING;
		analyze_missing_name(ps, name0);
	}
}

static void discover_deps(struct ps4_dependency_array *deps);
static void discover_name(struct ps4_name *name, int pkg_state);

static void discover_reverse_iif(struct ps4_name *name)
{
	struct ps4_name **pname0, *name0;
	struct ps4_dependency *d;
	struct ps4_provider *p;

	foreach_array_item(pname0, name->rinstall_if) {
		name0 = *pname0;

		foreach_array_item(p, name0->providers) {
			int ok = 1;
			if (!p->pkg->marked) continue;
			if (ps4_array_len(p->pkg->install_if) == 0) continue;
			foreach_array_item(d, p->pkg->install_if) {
				if (ps4_dep_conflict(d) == !!(d->name->state_int & (STATE_PRESENT|STATE_INSTALLIF))) {
					ok = 0;
					break;
				}
			}
			if (ok) {
				discover_name(p->pkg->name, STATE_INSTALLIF);
				foreach_array_item(d, p->pkg->provides)
					discover_name(d->name, STATE_INSTALLIF);
			}
		}
	}
}

static int is_name_concrete(struct ps4_package *pkg, struct ps4_name *name)
{
	struct ps4_dependency *d;
	if (pkg->name == name) return 1;
	foreach_array_item(d, pkg->provides) {
		if (d->name != name) continue;
		if (d->version == &ps4_atom_null) continue;
		return 1;
	}
	return 0;
}

static void discover_name(struct ps4_name *name, int pkg_state)
{
	struct ps4_provider *p;
	struct ps4_dependency *d;

	foreach_array_item(p, name->providers) {
		int state = pkg_state;
		if (!p->pkg->marked) continue;
		if ((state == STATE_PRESENT || state == STATE_INSTALLIF) &&
		    !p->pkg->provider_priority && !is_name_concrete(p->pkg, name))
			state = STATE_VIRTUAL_ONLY;
		if (p->pkg->state_int & state) continue;
		p->pkg->state_int |= state;

		p->pkg->name->state_int |= state;
		foreach_array_item(d, p->pkg->provides) {
			int dep_state = state;
			if (dep_state == STATE_INSTALLIF && d->version == &ps4_atom_null)
				dep_state = STATE_VIRTUAL_ONLY;
			d->name->state_int |= dep_state;
		}

		discover_deps(p->pkg->depends);
		if (state == STATE_PRESENT || state == STATE_INSTALLIF) {
			discover_reverse_iif(p->pkg->name);
			foreach_array_item(d, p->pkg->provides)
				discover_reverse_iif(d->name);
		}
	}
}

static void discover_deps(struct ps4_dependency_array *deps)
{
	struct ps4_dependency *d;

	foreach_array_item(d, deps) {
		if (ps4_dep_conflict(d)) continue;
		discover_name(d->name, STATE_PRESENT);
	}
}

void ps4_solver_print_errors(struct ps4_database *db,
			     struct ps4_changeset *changeset,
			     struct ps4_dependency_array *world)
{
	struct ps4_out *out = &db->ctx->out;
	struct print_state ps;
	struct ps4_change *change;

	/* ERROR: unsatisfiable dependencies:
	 *   name:
	 *     required by: a b c d e
	 *     not available in any repository
	 *   name (virtual):
	 *     required by: a b c d e
	 *     provided by: foo bar zed
	 *   pkg-1.2:
	 *     masked by: @testing
	 *     satisfies: a[pkg]
	 *     conflicts: pkg-2.0 foo-1.2 bar-1.2
	 *     breaks: b[pkg>2] c[foo>2] d[!pkg]
	 *
	 * When two packages provide same name 'foo':
	 *   a-1:
	 *     satisfies: world[a]
	 *     conflicts: b-1[foo]
	 *   b-1:
	 *     satisfies: world[b]
	 *     conflicts: a-1[foo]
	 * 
	 *   c-1:
	 *     satisfies: world[a]
	 *     conflicts: c-1[foo]  (self-conflict by providing foo twice)
	 *
	 * When two packages get pulled in:
	 *   a-1:
	 *     satisfies: app1[so:a.so.1]
	 *     conflicts: a-2
	 *   a-2:
	 *     satisfies: app2[so:a.so.2]
	 *     conflicts: a-1
	 *
	 * satisfies lists all dependencies that is not satisfiable by
	 * any other selected version. or all of them with -v.
	 */
 
	/* Construct information about names */
	foreach_array_item(change, changeset->changes) {
		struct ps4_package *pkg = change->new_pkg;
		if (pkg) pkg->marked = 1;
	}
	discover_deps(world);

	/* Analyze is package, and missing names referred to */
	ps = (struct print_state) {
		.db = db,
		.world = world,
	};
	ps4_err(out, "unable to select packages:");
	ps4_print_indented_init(&ps.i, out, 1);
	analyze_deps(&ps, world);
	foreach_array_item(change, changeset->changes) {
		struct ps4_package *pkg = change->new_pkg;
		if (!pkg) continue;
		analyze_package(&ps, pkg, change->new_repository_tag);
		analyze_deps(&ps, pkg->depends);
	}

	if (!ps.num_labels)
		ps4_print_indented_line(&ps.i, "Huh? Error reporter did not find the broken constraints.\n");
}

int ps4_solver_commit(struct ps4_database *db,
		      unsigned short solver_flags,
		      struct ps4_dependency_array *world)
{
	struct ps4_out *out = &db->ctx->out;
	struct ps4_changeset changeset = {};
	int r;

	if (ps4_db_check_world(db, world) != 0) {
		ps4_err(out, "Not committing changes due to missing repository tags. "
			"Use --force-broken-world to override.");
		return -1;
	}

	ps4_change_array_init(&changeset.changes);
	r = ps4_solver_solve(db, solver_flags, world, &changeset);
	if (r == 0)
		r = ps4_solver_commit_changeset(db, &changeset, world);
	else
		ps4_solver_print_errors(db, &changeset, world);
	ps4_change_array_free(&changeset.changes);
	return r;
}
