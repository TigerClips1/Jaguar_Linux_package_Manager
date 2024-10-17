ps4-cache(5)

# NAME

*/etc/ps4/cache* - local cache of package files

# DESCRIPTION

If */etc/ps4/cache* is a symlink to a local directory, *ps4*(8) will use it as
a local cache for downloaded package files and repository indicies. The cache
must not reside on a tmpfs.

To enable the ps4 cache, run the following commands as root:

mkdir -p /var/cache/ps4++
ln -s /var/cache/ps4 /etc/ps4/cache

For information on cache maintenance, see *ps4-cache*(8).
