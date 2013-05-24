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

import grp
import pwd

from oslo.config import cfg
import pbr.version

from keystone.common import openssl
from keystone import config
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils
from keystone import token

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
        for k in ['identity', 'catalog', 'policy', 'token', 'credential']:
            driver = importutils.import_object(getattr(CONF, k).driver)
            if hasattr(driver, 'db_sync'):
                driver.db_sync()


class BaseCertificateSetup(BaseApp):
    """Common user/group setup for PKI and SSL generation."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BaseCertificateSetup,
                       cls).add_argument_parser(subparsers)
        parser.add_argument('--keystone-user')
        parser.add_argument('--keystone-group')
        return parser

    @staticmethod
    def get_user_group():
        keystone_user_id = None
        keystone_group_id = None

        try:
            a = CONF.command.keystone_user
            if a:
                keystone_user_id = pwd.getpwnam(a).pw_uid
        except KeyError:
            raise ValueError("Unknown user '%s' in --keystone-user" % a)

        try:
            a = CONF.command.keystone_group
            if a:
                keystone_group_id = grp.getgrnam(a).gr_gid
        except KeyError:
            raise ValueError("Unknown group '%s' in --keystone-group" % a)

        return keystone_user_id, keystone_group_id


class PKISetup(BaseCertificateSetup):
    """Set up Key pairs and certificates for token signing and verification."""

    name = 'pki_setup'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_pki = openssl.ConfigurePKI(keystone_user_id, keystone_group_id)
        conf_pki.run()


class SSLSetup(BaseCertificateSetup):
    """Create key pairs and certificates for HTTPS connections."""

    name = 'ssl_setup'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_ssl = openssl.ConfigureSSL(keystone_user_id, keystone_group_id)
        conf_ssl.run()


class TokenFlush(BaseApp):
    """Flush expired tokens from the backend."""

    name = 'token_flush'

    @classmethod
    def main(cls):
        token_manager = token.Manager()
        token_manager.driver.flush_expired_tokens()


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
    SSLSetup,
    TokenFlush,
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
         version=pbr.version.VersionInfo('keystone').version_string(),
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=config_files)
    config.setup_logging(CONF)
    CONF.command.cmd_class.main()
