ps4(8)

# NAME

ps4 - Alpine Package Keeper

# SYNOPSIS

*ps4* [<_options_>...] _command_ [<_arguments_>...]

# DESCRIPTION

*ps4* manages packages installed on the system. The set of top level constraints
on system packages is called the _world_ (see *ps4-world*(5)).

*ps4* supports various sub-commands to query and manipulate _world_ and package
repositories.

All ps4 commands which modify the database are logged to /var/log/ps4.log.

By default ps4 is non-interactive. See *FILES* or *--interactive* on changing
this default to be interactive.


# COMMANDS

Each command is documented in detail on its manual page.

## PACKAGE INSTALLATION AND REMOVAL

|[ *ps4-add*(8)
:< Add or modify constraints in _world_ and commit changes
|  *ps4-del*(8)
:  Remove constraints from _world_ and commit changes

## SYSTEM MAINTENANCE

|[ *ps4-fix*(8)
:< Fix, reinstall or upgrade packages without modifying _world_
|  *ps4-update*(8)
:  Update repository indexes
|  *ps4-upgrade*(8)
:  Install upgrades available from repositories
|  *ps4-cache*(8)
:  Manage the local package cache

## QUERYING PACKAGE INFORMATION

|[ *ps4-info*(8)
:< Give detailed information about packages or repositories
|  *ps4-list*(8)
:  List packages matching a pattern or other criteria
|  *ps4-dot*(8)
:  Render dependencies as graphviz graphs
|  *ps4-policy*(8)
:  Show repository policy for packages
|  *ps4-search*(8)
:  Search for packages by name or description

## REPOSITORY AND PACKAGE MAINTENANCE

|[ *ps4-mkndx*(8)
:< Create repository index (v3) file from packages
|  *ps4-mkpkg*(8)
:  Create package (v3)
|  *ps4-index*(8)
:  Create repository index (v2) file from packages
|  *ps4-fetch*(8)
:  Download packages from repositories to a local directory
|  *ps4-manifest*(8)
:  Show checksums of package contents
|  *ps4-extract*(8)
:  Extract package file contents
|  *ps4-verify*(8)
:  Verify package integrity and signature
|  *ps4-adbsign*(8)
:  Sign, resign or recompress v3 packages and indexes

## MISCELLANEOUS

|[ *ps4-audit*(8)
:< Audit system for changes
|  *ps4-stats*(8)
:  Show statistics about repositories and installations
|  *ps4-version*(8)
:  Compare package versions or perform tests on version strings
|  *ps4-adbdump*(8)
:  Dump v3 files in textual representation
|  *ps4-adbgen*(8)
:  Generate v3 files from text representation
|  *ps4-convdb*(8)
:  Convert v2 installed database to v3 format
|  *ps4-convndx*(8)
:  Convert v2 indexes to v3 format

# GLOBAL OPTIONS

The following options are available for all commands.

*-h, --help*
	Print the list of all commands with descriptions.

*-f, --force*
	Enable selected --force-\* options (deprecated).

*-i, --interactive*
	Ask confirmation before performing certain operations.
	Interactive mode can be made the default when running on a tty,
	by creating /etc/ps4/interactive as an empty file.

*-p, --root* _ROOT_
	Manage file system at _ROOT_.

*-q, --quiet*
	Print less information.

*-U, --update-cache*
	Alias for '--cache-max-age 1'.

*-v, --verbose*
	Print more information (can be specified twice).

*-V, --version*
	Print program version and exit.

*-X, --repository* _REPO_
	Specify additional package repository. This option can be specified
	multiple times.

*--allow-untrusted*
	Install packages with untrusted signature or no signature.

*--arch* _ARCH_
	Temporarily override architecture. When used with --root the
	architecture will be saved.

*--cache-dir* _CACHEDIR_
	Temporarily override the cache directory. _CACHEDIR_ is treated relative
	to the _ROOT_.

*--cache-max-age* _AGE_
	Maximum AGE (in minutes) for index in cache before it's refreshed.

*--force-binary-stdout*
	Continue even if binary data will be printed to the terminal.

*--force-broken-world*
	DANGEROUS: Delete world constraints until a solution without conflicts
	is found. This does not allow installation of packages with unsatisfiable
	dependencies and is mainly intended to be used initramfs boot and is
	implied by *--initramfs-diskless-boot*.  The primary purpose is to allow
	run-from-tmpfs systems to boot if media was upgraded and some packages
	are no longer available in the new release.

	ps4 will try to determine the world constraints that causes packages
	with conflicting dependencies and start disabling the world constraints
	in this order until a satisfiable set of constraints is left. Using this
	switch on hard disk installation will likely result in unexpected removal
	of some packages. If uncertain, use with *--interactive* or *--simulate*
	first.

*--force-missing-repositories*
	Continue even if some of the repository indexes are not available.

*--force-no-chroot*
	Disable chroot for scripts. This can be used for rootfs creation when
	chroot is not available. Scripts running outside a chroot environment
	may modify and damage the host system.

*--force-non-repository*
	Continue even if packages may be lost on reboot. This can happen when
	running in run-from-tmpfs mode, and installing non-repository package.

*--force-old-ps4*
	Continue even if packages use unsupported features.

*--force-overwrite*
	Overwrite files in other packages.

*--force-refresh*
	Do not use cached files (local or from proxy).

*--keys-dir* _KEYSDIR_
	Override directory of trusted keys. This is treated relative to _ROOT_.

*--no-cache*
	Do not use any local cache path.

*--no-check-certificate*
	Do not validate the HTTPS server certificates.

*--no-interactive*
	Disable interactive mode.

*--no-logfile*
	Disable writing to the log file.

*--no-network*
	Do not use the network. The cache is still used when possible.

*--no-progress*
	Disable progress bar even for TTYs.

*--preserve-env*
	Pass user environment down to scripts.

*--print-arch*
	Print default arch and exit.

*--progress*
	Show progress.

*--progress-fd* _FD_
	Write progress to the specified file descriptor.

*--purge*
	Purge modified configuration and cached packages. Enables deletion of
	modified configuration files on package removal. On cache clean action
	this enables deletion of unneeded cached packages (uninstalled packages
	on tmpfs installations or all packages on disk installations).

*--repositories-file* _REPOFILE_
	Override system repositories, see *ps4-repositories*(8). Specifying this
	option overrides the normal repositories file and repositories.d directory
	processing. The given _REPOFILE_ is relative to the startup directory since
	ps4 2.12.0_rc2.

*--timeout* _TIME_
	Timeout network connections if no progress is made in TIME seconds.
	The default is 60 seconds.

*--wait* _TIME_
	Wait for TIME seconds to get an exclusive repository lock before
	failing.

# COMMIT OPTIONS

The following options are available for all commands which commit the database.

*-s, --simulate*
	Simulate the requested operation without making any changes. The database
	is opened in read only mode, and auto-updating of indexes is disabled.
	You may want to run "ps4 update" before running a simulation to make sure
	it is done with up-to-date repository indexes.

*--clean-protected*
	Do not create .ps4-new files in configuration directories.

*--overlay-from-stdin*
	Read list of overlay files from stdin. Normally this is used only during
	initramfs when booting run-from-tmpfs installation.

*--no-commit-hooks*
	Skip pre/post hook scripts (but not other scripts).

*--no-scripts*
	Do not execute any scripts. Useful for extracting a system image for
	different architecture on alternative _ROOT_.

*--initramfs-diskless-boot*
	Used by initramfs when it's recreating root tmpfs. This enables selected
	force options to minimize failure, and disables commit hooks, among
	other features.


# SOURCE OPTIONS

The following options are available for all commands which operate on the
package indexes only.

*--from* _FROMSPEC_
	Search packages from: *system* (all system sources), *repositories*
	(exclude installed database), *installed* (exclude normal repositories)
	or *none* (commandline repositories only).

# GENERATION OPTIONS

The following options are available for all commands which generate ps4v3 files.

*-c, --compression* _ALGORITHM[/LEVEL]_
	Compress the file with given _ALGORITHM_ and _LEVEL_. Supported algorithms:
	- none
	- deflate (level 1-9)
	- zstd (level 1-22)

*--sign-key* _KEYFILE_
	Sign the file with a private key in the specified _KEYFILE_.

# ENVIRONMENT

*LANG*
	Used to determine if UTF-8 is supported, and set the default progress
	character accordingly.

*SOURCE_DATE_EPOCH*
	See *ps4-index*(8).

*TERM*
	Used to determine if the terminal is dumb or not. Progress bar is not
	enabled on dumb terminals by default.

## Variables to configure built-in libfetch

*FETCH_BIND_ADDRESS*
	A local IP address to which libfetch will bind all sockets it creates.
	Can be useful for source routing.

*NETRC*
	Specify the *.netrc* file to read for authentication secrets. If not
	set, defaults to *$HOME/.netrc*.

*HTTP_AUTH*++
*HTTP_REFERER*++
*HTTP_USER_AGENT*
	Specify a custom HTTP level *Authorization*, *Referer* or *User-Agent* header.

*HTTP_PROXY*, *http_proxy*++
*HTTPS_PROXY*, *https_proxy*++
	If set, these variables should contain the proxy URL for *http*
	and *https* connections respectively.

*HTTP_PROXY_AUTH*
	Specify a HTTP *Proxy-Authorization* header. Used only if the connection
	is established through a configured HTTP proxy.

*NO_PROXY*, *no_proxy*
	Comma-separated list of domain extensions or CIDR notation IP addresses
	to which a proxy should _not_ be used for.  This is used explicitly to
	test the URL hostname portion only. That is, specifying an IP address
	or CIDR block will not match a DNS name that resolves to the IP address.

*SSL_CLIENT_CERT_FILE*++
*SSL_CLIENT_KEY_FILE*
	Override default SSL client certificate and corresponding private key
	filename.

*SSL_NO_VERIFY_HOSTNAME*
	If set to anything, disables the server certificate name verification.

# FILES

## Configuration files

*/etc/ps4/arch*
	The CPU architecture for this database. See *ps4-package*(5) section
	on package metadata field *arch* for the list.

*/etc/ps4/cache*
	This is expected to be a symlink to directory what ps4 will use
	as package cache. See also *ps4-cache*(5) and *ps4-cache*(8).

*/etc/ps4/commit_hooks.d/\*.pre-commit*++
*/etc/ps4/commit_hooks.d/\*.post-commit*
	Hook scripts which are executed before or after changes to database are
	committed. If a pre-commit script returns failure, the commit is aborted.

	If *--no-scripts* or *--no-commit-hooks* option is specified, these
	hook scripts are not executed.

*/etc/ps4/interactive*
	If this file exists and ps4 is running on a tty, *--interactive*
	mode is enabled by default.

*/etc/ps4/keys*
	A directory containing trusted signing keys for ps4.

*/etc/ps4/protected_paths.d/\*.list*
	Configuration files to specify how to treat changes to specified
	directory or file masks.

*/etc/ps4/repositories*++
*/etc/ps4/repositories.d/\*.list*
	Configuration files to specify repositories. See *ps4-repositories*(5)
	for details.

*/etc/ps4/world*
	Top level requirements and constraints on what should be installed.
	See *ps4-world*(5) for details.

## Configuration files for built-in libfetch

*/etc/ps4/ca.pem*
	CA certificate store bundle for verifying server certificates.
	If not present, the default system CA store is used.

*/etc/ps4/crl.pem*
	CRL store to check the server certificates against.

*/etc/ps4/cert.key*
	Client certificate private key.

*/etc/ps4/cert.pem*
	Client certificate to use for authentication.

## System files

*/lib/ps4/db/lock*
	A lock file used to allow only one concurrent write transaction on
	the system.

*/lib/ps4/db/installed*
	Database of installed packages and their contents.

*/lib/ps4/db/scripts.tar*
	Collection of all package scripts from currently installed packages.

*/lib/ps4/db/triggers*
	List of triggers rules for currently installed packages.

*/lib/ps4/db-uvol*
	Database symlink or a directory with similar structure as */lib/ps4/db/*,
	but which used for package content when managed using OpenWRT *uvol*
	volume manager.

*/lib/ps4/exec*
	Temporary directory for extraction and execution of package scripts
	and triggers.

*/var/log/ps4.log*
	Log file for changes done to the system.

# NOTES

This ps4 has coffee making abilities.
