# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
virtualenv installation script
"""

import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
VENV = os.path.join(ROOT, '.venv')
PIP_REQUIRES = os.path.join(ROOT, 'tools', 'pip-requires')
TEST_REQUIRES = os.path.join(ROOT, 'tools', 'test-requires')
PY_VERSION = "python%s.%s" % (sys.version_info[0], sys.version_info[1])


def die(message, *args):
    print >>sys.stderr, message % args
    sys.exit(1)


def check_python_version():
    if sys.version_info < (2, 6):
        die("Need Python Version >= 2.6")


def run_command(cmd, redirect_output=True, check_exit_code=True):
    """
    Runs a command in an out-of-process shell, returning the
    output of that command.  Working directory is ROOT.
    """
    if redirect_output:
        stdout = subprocess.PIPE
    else:
        stdout = None

    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=stdout)
    output = proc.communicate()[0]
    if check_exit_code and proc.returncode != 0:
        die('Command "%s" failed.\n%s', ' '.join(cmd), output)
    return output


HAS_EASY_INSTALL = bool(run_command(['which', 'easy_install'],
                    check_exit_code=False).strip())
HAS_VIRTUALENV = bool(run_command(['which', 'virtualenv'],
                    check_exit_code=False).strip())


def check_dependencies():
    """Make sure virtualenv is in the path."""

    print 'Checking for virtualenv...'
    if not HAS_VIRTUALENV:
        print 'not found.'
        # Try installing it via easy_install...
        if HAS_EASY_INSTALL:
            print 'Installing virtualenv via easy_install...',
            if not (run_command(['which', 'easy_install']) and
                    run_command(['easy_install', 'virtualenv'])):
                die('ERROR: virtualenv not found.\n\nNova development'
                    ' requires virtualenv, please install it using your'
                    ' favorite package management tool')
            print 'done.'
    print 'done.'


def create_virtualenv(venv=VENV):
    """Creates the virtual environment and installs PIP only into the
    virtual environment
    """
    print 'Creating venv...',
    run_command(['virtualenv', '-q', '--no-site-packages', VENV])
    print 'done.'
    print 'Installing pip in virtualenv...',
    if not run_command(['tools/with_venv.sh', 'easy_install', 'pip']).strip():
        die("Failed to install pip.")
    print 'done.'


def install_dependencies(venv=VENV):
    print 'Installing dependencies with pip (this can take a while)...'
    run_command(['tools/with_venv.sh', 'pip', 'install', '-r',
                PIP_REQUIRES, '-r', TEST_REQUIRES], redirect_output=False)


def print_help():
    help = """
    Virtual environment configuration complete.

    To activate the virtualenv for the extent of your current shell
    session you can run:

    $ source %s/bin/activate

    Or, if you prefer, you can run commands in the virtualenv on a case by case
    basis by running:

    $ tools/with_venv.sh <your command>

    """ % VENV
    print help


def main(argv):
    check_python_version()
    check_dependencies()
    create_virtualenv()
    install_dependencies()
    print_help()

if __name__ == '__main__':
    main(sys.argv)
