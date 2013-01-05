# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
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

from __future__ import absolute_import

from keystone import config
from keystone.common import openssl
from keystone.openstack.common import cfg
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils

CONF = config.CONF


class BaseApp(object):

    name = None

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = subparsers.add_parser(cls.name, help=cls.__doc__)
        parser.set_defaults(cmd_class=cls)
        return parser


class DbSync(BaseApp):
    """Sync the database."""

    name = 'db_sync'

    @staticmethod
    def main():
        for k in ['identity', 'catalog', 'policy', 'token']:
            driver = importutils.import_object(getattr(CONF, k).driver)
            if hasattr(driver, 'db_sync'):
                driver.db_sync()


class PKISetup(BaseApp):
    """Set up Key pairs and certificates for token signing and verification."""

    name = 'pki_setup'

    @staticmethod
    def main():
        conf_ssl = openssl.ConfigurePKI()
        conf_ssl.run()


class ImportLegacy(BaseApp):
    """Import a legacy database."""

    name = 'import_legacy'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(ImportLegacy, cls).add_argument_parser(subparsers)
        parser.add_argument('old_db')
        return parser

    @staticmethod
    def main():
        from keystone.common.sql import legacy
        migration = legacy.LegacyMigration(CONF.command.old_db)
        migration.migrate_all()


class ExportLegacyCatalog(BaseApp):
    """Export the service catalog from a legacy database."""

    name = 'export_legacy_catalog'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(ExportLegacyCatalog,
                       cls).add_argument_parser(subparsers)
        parser.add_argument('old_db')
        return parser

    @staticmethod
    def main():
        from keystone.common.sql import legacy
        migration = legacy.LegacyMigration(CONF.command.old_db)
        print '\n'.join(migration.dump_catalog())


class ImportNovaAuth(BaseApp):
    """Import a dump of nova auth data into keystone."""

    name = 'import_nova_auth'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(ImportNovaAuth, cls).add_argument_parser(subparsers)
        parser.add_argument('dump_file')
        return parser

    @staticmethod
    def main():
        from keystone.common.sql import nova
        dump_data = jsonutils.loads(open(CONF.command.dump_file).read())
        nova.import_auth(dump_data)


CMDS = [
    DbSync,
    ExportLegacyCatalog,
    ImportLegacy,
    ImportNovaAuth,
    PKISetup,
]


def add_command_parsers(subparsers):
    for cmd in CMDS:
        cmd.add_argument_parser(subparsers)


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main(argv=None, config_files=None):
    CONF.register_cli_opt(command_opt)
    CONF(args=argv[1:],
         project='keystone',
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=config_files)
    CONF.command.cmd_class.main()
