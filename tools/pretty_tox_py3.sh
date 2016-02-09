#!/usr/bin/env bash

set -o pipefail

TESTRARGS=`python -c 'print ("^((?!%s).)*$" % "|".join(f.strip() for f in open("tests-py3-blacklist.txt")))'`
python setup.py testr --testr-args="--subunit $TESTRARGS" | subunit-trace -f
retval=$?
# NOTE(mtreinish) The pipe above would eat the slowest display from pbr's testr
# wrapper so just manually print the slowest tests.
echo -e "\nSlowest Tests:\n"
testr slowest
exit $retval
