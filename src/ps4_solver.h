/* ps4_solver.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2013 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_SOLVER_H
#define PS4_SOLVER_H

struct ps4_name;
struct ps4_package;

struct ps4_change {
	struct ps4_package *old_pkg;
	struct ps4_package *new_pkg;
	unsigned old_repository_tag : 15;
	unsigned new_repository_tag : 15;
	unsigned reinstall : 1;
};
PS4_ARRAY(ps4_change_array, struct ps4_change);

struct ps4_changeset {
	int num_install, num_remove, num_adjust;
	int num_total_changes;
	struct ps4_change_array *changes;
};

#define PS4_SOLVERF_UPGRADE		0x0001
#define PS4_SOLVERF_AVAILABLE		0x0002
#define PS4_SOLVERF_REINSTALL		0x0004
#define PS4_SOLVERF_LATEST		0x0008
#define PS4_SOLVERF_IGNORE_CONFLICT	0x0010
#define PS4_SOLVERF_INSTALLED	 	0x0020
#define PS4_SOLVERF_REMOVE		0x0040

void ps4_solver_set_name_flags(struct ps4_name *name,
			       unsigned short solver_flags,
			       unsigned short solver_flags_inheritable);
int ps4_solver_solve(struct ps4_database *db,
		     unsigned short solver_flags,
		     struct ps4_dependency_array *world,
		     struct ps4_changeset *changeset);

int ps4_solver_commit_changeset(struct ps4_database *db,
				struct ps4_changeset *changeset,
				struct ps4_dependency_array *world);
void ps4_solver_print_errors(struct ps4_database *db,
			     struct ps4_changeset *changeset,
			     struct ps4_dependency_array *world);

int ps4_solver_commit(struct ps4_database *db, unsigned short solver_flags,
		      struct ps4_dependency_array *world);

#endif

