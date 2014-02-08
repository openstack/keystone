# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys

from keystone.openstack.common import gettextutils

# gettextutils.install() must run to set _ before importing any modules that
# contain static translated strings.
gettextutils.install('keystone')

from oslo.config import cfg

from keystone.contrib.kds.common import service
from keystone.contrib.kds.db import migration

CONF = cfg.CONF


def do_db_version():
    """Print database's current migration level."""
    print(migration.db_version())


def do_db_sync():
    """Place a database under migration control and upgrade,
    creating first if necessary.
    """
    return migration.db_sync(CONF.command.version)


def add_command_parsers(subparsers):
    parser = subparsers.add_parser('db_version')
    parser.set_defaults(func=do_db_version)

    parser = subparsers.add_parser('db_sync')
    parser.set_defaults(func=do_db_sync)
    parser.add_argument('version', nargs='?')


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main():
    CONF.register_cli_opt(command_opt)
    service.prepare_service(sys.argv)

    try:
        CONF.command.func()
    except Exception as e:
        sys.exit("ERROR: %s" % e)
