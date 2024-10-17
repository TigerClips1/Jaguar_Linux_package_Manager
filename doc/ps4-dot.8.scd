ps4-dot(8)

# NAME

ps4 dot - generate graphviz graphs

# SYNOPSIS

*ps4 dot* [<_options_>...] [_pkgmask_...]

# DESCRIPTION

*ps4 dot* renders package dependencies as graphviz graphs.

The graph is generated for the packages matching the masks given, or for every
known package if unspecified (this will generate a large and unwieldy graph).

# OPTIONS

*--errors*
	Consider only packages with errors. This is useful for visually reporting
	e.g. cyclic dependencies and missing packages.

*--installed*
	Consider only installed packages.
