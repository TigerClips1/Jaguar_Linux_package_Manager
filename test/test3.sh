#!/bin/sh -e

# desc: test successful pre-install

$PS4 add --root $ROOT --initdb --repository $PWD/repo1 --repository $SYSREPO \
	-U test-c

# check that package was installed
$PS4 info --root $ROOT -e test-c

# check if pre-install was executed
test -f $ROOT/pre-install
