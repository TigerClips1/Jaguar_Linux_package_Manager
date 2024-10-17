ps4-fix(8)

# NAME

ps4 fix - repair packages or system

# SYNOPSIS

*ps4 fix* [<_options_>...] [_packages_...]

# DESCRIPTION

*ps4 fix* applies repair strategies to correct errors in the installation of
the specified packages, or all installed packages if none are specified.

# OPTIONS

*ps4 fix* supports the commit options described in *ps4*(8), as well as the
following options:

*-d, --depends*
	Also fix dependencies of specified packages.

*-r, --reinstall*
	Reinstall packages (default).

*-u, --upgrade*
	Upgrade name _PACKAGE_ if an upgrade exists and does not break
	dependencies.

*-x, --xattr*
	Fix packages with broken xattrs.

*--directory-permissions*
	Reset all directory permissions.
