#!/bin/bash
TOOLS=`dirname $0`
VENV=$TOOLS/../.ksl-venv
source $VENV/bin/activate && $@
