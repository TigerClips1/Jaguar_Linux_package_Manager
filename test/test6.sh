#!/bin/sh -e

# desc: test triggers in kernel package

$PS4 add --root $ROOT --initdb -U --repository $PWD/repo1 \
	--repository $SYSREPO alpine-keys linux-lts

test -e "$ROOT"/boot/vmlinuz-lts

test -e "$ROOT"/boot/initramfs-lts

