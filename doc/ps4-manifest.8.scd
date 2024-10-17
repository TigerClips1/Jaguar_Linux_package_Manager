ps4-manifest(8)

# NAME

ps4 manifest - Show checksums of package contents

# SYNOPSIS

*ps4 manifest* [<_options_>...] _packages_...

# DESCRIPTION

*ps4 manifest* prints the checksums of files in the listed packages. One file
is printed per line, the checksum first, followed by a space, and then the path
to the file.

The checksum itself is printed in the format _algorithm_:_hash_. Supported
algorithms are:

- *md5*
- *sha1*

*sha1* is used for new packages.

# OPTIONS

*ps4 manifest* does not support any specific options. See *ps4*(8) for global
options.
