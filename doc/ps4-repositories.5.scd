ps4-repositories(5)

# NAME

*/etc/ps4/repositories*, */etc/ps4/repositories.d/\*.list* - list of package
repositories

# DESCRIPTION

/etc/ps4/repositories is the list of package repositories *ps4*(8) uses to
retrieve package files for installation. Each line of this file specifies the
location of a package repository, and optionally a tag.

The location may be an _http://_, _https://_, or the path to a directory on
the local filesystem. A tagged repository is prefixed with the *@tag* specifier,
followed by a space and the repository location. For more information about
repository tags, see *ps4-world*(5).

# REPOSITORY LAYOUT

Each repository must store an index at *$repository/$arch/ps4INDEX.tar.gz*. See
*ps4-index*(8) for information about generating this file. The packages
themselves are stored at *$repository/$arch/$pkgname-$pkgver-r$pkgrel.ps4*.

*ps4*(8) verifies that each of these files has a valid cryptographic signature
unless explicitly told not to via the *--allow-untrusted* flag. See
*abuild-keygen*(1) for information about generating keys, *ps4-keys*(5) to add
keys to the list of trusted keys, *abuild-sign*(1) for information about using
these keys to sign files, and *ps4-verify*(8) for information about verifying
those signatures.

# UPDATING INDICIES

*ps4*(8) fetches and stores the index for each package repository at
*/var/cache/ps4*. To fetch fresh indicies for all configured repositories, use
*ps4-update*(8).
