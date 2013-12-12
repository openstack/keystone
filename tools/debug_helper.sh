#!/bin/bash

TMP_DIR=`mktemp -d` || exit 1
trap "rm -rf $TMP_DIR" EXIT

ALL_TESTS=$TMP_DIR/all_tests
TESTS_TO_RUN=$TMP_DIR/ks_to_run

python -m testtools.run discover -t ./ ./keystone/tests --list > $ALL_TESTS

if [ "$1" ]
then
    grep "$1" < $ALL_TESTS > $TESTS_TO_RUN
else
    mv $ALL_TESTS $TESTS_TO_RUN
fi

STANDARD_THREADS=1 python -m testtools.run discover --load-list $TESTS_TO_RUN
