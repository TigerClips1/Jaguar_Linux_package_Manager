ps4-adbsign(8)

# NAME

ps4 adbsign - sign, resign or recompress ps4 v3 packages or indexes

# SYNOPSIS

*ps4 adbsign* [<_options_>...] _files_...

# DESCRIPTION

*ps4 adbsign* will process specified _files_ and add or replace
the signatures in addition to recompressing it. The original compression
algorithm and level is used unless specified.

# OPTIONS

See also *ps4*(8) for additional package generation options.

*--reset-signatures*
	Remove all existing signatures.
