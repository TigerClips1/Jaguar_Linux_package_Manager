ps4-search(8)

# NAME

ps4 search - search for packages by name or description

# SYNOPSIS

*ps4 search* [<_options_>...] _pattern_...

# DESCRIPTION

*ps4 search* searches all repositories for packages matching at least one
pattern. If no pattern is given, it lists all packages in the configured
repositories (see *ps4-repositories*(5)). A pattern matches if it is a
case-insensitive substring of the package name.

# OPTIONS

In addition to the global options (see *ps4*(8)), *ps4 search* supports the
following options:

*-a, --all*
	Print all matching package versions. By default, *ps4* only shows the
	latest version.

*-d, --description*
	Also search for _pattern_ in the package description. By default, *ps4*
	does not search package descriptions.

*-e, -x, --exact*
	Match package names exactly.

*--has-origin*
	Match by package origin. Shows all packages whose base package name
	matches _pattern_ exactly. Implies *--all* and *--exact*.

*-o, --origin*
	Print base package name.

*-r, --rdepends*
	Print reverse dependencies (other packages which depend on the
	package).
