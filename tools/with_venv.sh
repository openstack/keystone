#!/bin/bash
TOOLS=`dirname $0`
VENV=$TOOLS/../.keystone-venv
source $VENV/bin/activate && $@
