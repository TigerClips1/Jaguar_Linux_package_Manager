ps4-del(8)

# NAME

ps4 del - remove constraints from _world_ and commit changes

# SYNOPSIS

*ps4 del* [<_options_>...] _constraints_...

# DESCRIPTION

*ps4 del* removes constraints from _world_ (see *ps4-world*(5)) and
commits changes to disk. This usually involves removing unneeded packages,
but may also cause other changes to the installed packages.

# OPTIONS

*ps4 del* supports the commit options described in *ps4*(8), as well as the
following options:

*-r, --rdepends*
	Recursively delete all top-level reverse dependencies, too.
