#!/bin/sh

. ${SRC:-.}/test-lib.sh

t_case "help" && {
	help_normal=$($PS4 version --help 2>/dev/null) || true
	[ "${#help_normal}" -gt 2000 ]
	help_invalid=$($PS4 version --invalid-option 2>/dev/null) || true
	[ "$help_normal" = "$help_invalid" ]
}

t_case "version" && {
	sed 's/[[:blank:]]*#.*//g' < $SRC/version.data | tr '\n' '\0' | xargs -0 $PS4 vertest
}

t_end
