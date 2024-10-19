#!/bin/sh -e

# desc: test if upgrade works when package is missing in repo

$PS4 add --root $ROOT --initdb --repository $PWD/repo1 test-a

$PS4 upgrade --root $ROOT 
