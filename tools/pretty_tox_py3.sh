#!/usr/bin/env bash

set -o pipefail

TESTRARGS=$1
python setup.py testr --testr-args="--subunit $TESTRARGS" | subunit-trace -f
retval=$?
# NOTE(mtreinish) The pipe above would eat the slowest display from pbr's testr
# wrapper so just manually print the slowest tests.
echo -e "\nSlowest Tests:\n"
testr slowest
exit $retval
