ps4-mkpkg(8)

# NAME

ps4 mkpkg - create ps4v3 package files

# SYNOPSIS

*ps4 mkpkg* [<_options_>...]

# DESCRIPTION

*ps4 mkpkg* creates a package file from given metadata and data files.

# OPTIONS

*-F, --files* _PATH_
	Specify the build root path from where the files are collected
	from to be included in the package.

*-I, --info* _KEY:VALUE_
	Specify metadata for the package. Assigns a metadata field _KEY_
	with the value _VALUE_. Refer to *ps4-package*(5) for the list
	of ps4v3 metadata fields. This can assign to either "package info"
	or "package" metadata field.

*-o, --output* _FILE_
	Specify the _FILE_ as the output file name. If not specified,
	a default name will be deduced from the package metadata fields.

*--rootnode, --no-rootnode*
	Generate or do not generate the rootnode entry in package PATHS.
	The packages generated without rootnode are not backwards compatible
	so this is off by default for now.

*-s, --script* _TYPE:SCRIPT_
	Add the specified *SCRIPT* with the *TYPE*. Refer to *ps4-package*(5)
	*PACKAGE METADATA* / *scripts* for list of scripts types and when
	they are executed.

*-t, --trigger* _TRIGGER_
	Append _TRIGGER_ path specification to list triggers which affect
	when the *trigger* script is executed.
