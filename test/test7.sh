#!/bin/sh -e

# desc: test triggers in busybox package

# we had a bug that caused ps4 fix --reinstall to segfault every second time

$PS4 add --root $ROOT --initdb -U --repository $PWD/repo1 \
	--repository $SYSREPO busybox

for i in 0 1 2 3; do
	# delete wget symlink
	rm -f "$ROOT"/usr/bin/wget

	# re-install so we run the trigger again
	$PS4 fix --root $ROOT --repository $SYSREPO --reinstall  busybox

	# verify wget symlink is there
	test -L "$ROOT"/usr/bin/wget
done


