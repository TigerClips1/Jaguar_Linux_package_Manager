ps4-adbdump(8)

# NAME

ps4 adbdump - dump v3 files in textual representation

# SYNOPSIS

*ps4 adbdump* _files_...

# DESCRIPTION

*ps4 adbdump* will dump the metadata portion of given _files_ (packages,
indexes, installeddb) to its textual representation.

The output is YAML "like" (see BUGS) output which can be used to inspect
the metadata. *ps4 adbgen*(8) can convert the textual representation back
to the binary format.

# OPTIONS

*ps4 adbdump* does not support any specific options. See *ps4*(8) for global
options.

# BUGS

YAML compliant quoting is not impemented correctly at this time.

# SEE ALSO

*ps4-adbgen*(8), *ps4-package*(5), *ps4-v3*(5)
