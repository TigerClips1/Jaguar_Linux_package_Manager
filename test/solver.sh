#!/bin/sh

get_block() {
	awk '/^@'$1'/{p=1;next} /^@/{p=0} p{print}'
}

PS4_TEST="$VALGRIND ../src/ps4-test"
TEST_TO_RUN="$@"

fail=0
pass=0
for test in ${TEST_TO_RUN:-*.test}; do
	get_block ARGS < $test | xargs $PS4_TEST > .$test.got 2>&1

	if ! get_block EXPECT < $test | cmp .$test.got > /dev/null 2>&1; then
		fail=$((fail+1))
		echo "FAIL: $test"
		get_block EXPECT < $test | diff -ru - .$test.got
	else
		pass=$((pass+1))
	fi
done

total=$((fail+pass))
if [ "$fail" != "0" ]; then
	echo "FAIL: $fail of $total test cases failed"
else
	echo "OK: all $total solver test cases passed"
fi

exit $fail
