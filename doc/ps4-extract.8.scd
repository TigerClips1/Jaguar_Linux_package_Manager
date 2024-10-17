ps4-extract(8)

# NAME

ps4 extract - Extract package file contents

# SYNOPSIS

*ps4 extract* [<_options_>...] _packages_...

# DESCRIPTION

*ps4 extract* will extract package contents of specified package file
to the current or to an explicitly specified directory.
Each package is extracted without checking dependencies or other metadata.

If extract is ran as non-root user the file owners and xattrs are not
preserved.

# OPTIONS

*--destination* _PATH_
	Extract files to _PATH_.

*--no-chown*
	Do not preserve file owner.
