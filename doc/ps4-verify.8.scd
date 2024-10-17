ps4-verify(8)

# NAME

ps4 verify - verify package integrity and signature

# SYNOPSIS

*ps4 verify* [<_options_>...] _files_...

# DESCRIPTION

*ps4 verify* verifies the integrity of the package files specified, validating
the checksums and cryptographic signature.

*ps4 verify* prints a summary of the results on stdout, and exits with status
code zero if all packages were successfully verified. If any failed, *ps4
verify* exits with a nonzero status.

# OPTIONS

*ps4 verify* does not support any specific options. See *ps4*(8) for global
options.
