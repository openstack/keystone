# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import os

from migrate import exceptions

from oslo.config import cfg
import pbr.version

from keystone.common import openssl
from keystone.common.sql import migration
from keystone.common import utils
from keystone import config
from keystone import contrib
from keystone.openstack.common import importutils
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

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DbSync, cls).add_argument_parser(subparsers)
        parser.add_argument('version', default=None, nargs='?',
                            help=('Migrate the database up to a specified '
                                  'version. If not provided, db_sync will '
                                  'migrate the database to the latest known '
                                  'version.'))
        parser.add_argument('--extension', default=None,
                            help=('Migrate the database for the specified '
                                  'extension. If not provided, db_sync will '
                                  'migrate the common repository.'))

        return parser

    @staticmethod
    def main():
        version = CONF.command.version
        extension = CONF.command.extension
        if not extension:
            migration.db_sync(version=version)
        else:
            package_name = "%s.%s.migrate_repo" % (contrib.__name__, extension)
            try:
                package = importutils.import_module(package_name)
                repo_path = os.path.abspath(os.path.dirname(package.__file__))
            except ImportError:
                print(_("This extension does not provide migrations."))
                exit(0)
            try:
                # Register the repo with the version control API
                # If it already knows about the repo, it will throw
                # an exception that we can safely ignore
                migration.db_version_control(version=None, repo_path=repo_path)
            except exceptions.DatabaseAlreadyControlledError:
                pass
            migration.db_sync(version=version, repo_path=repo_path)


class DbVersion(BaseApp):
    """Print the current migration version of the database."""

    name = 'db_version'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DbVersion, cls).add_argument_parser(subparsers)
        parser.add_argument('--extension', default=None,
                            help=('Migrate the database for the specified '
                                  'extension. If not provided, db_sync will '
                                  'migrate the common repository.'))

    @staticmethod
    def main():
        extension = CONF.command.extension
        if extension:
            try:
                package_name = ("%s.%s.migrate_repo" %
                                (contrib.__name__, extension))
                package = importutils.import_module(package_name)
                repo_path = os.path.abspath(os.path.dirname(package.__file__))
                print(migration.db_version(repo_path))
            except ImportError:
                print(_("This extension does not provide migrations."))
                exit(1)
        else:
            print(migration.db_version())


class BaseCertificateSetup(BaseApp):
    """Common user/group setup for PKI and SSL generation."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BaseCertificateSetup,
                       cls).add_argument_parser(subparsers)
        running_as_root = (os.geteuid() == 0)
        parser.add_argument('--keystone-user', required=running_as_root)
        parser.add_argument('--keystone-group', required=running_as_root)
        return parser

    @staticmethod
    def get_user_group():
        keystone_user_id = None
        keystone_group_id = None

        try:
            a = CONF.command.keystone_user
            if a:
                keystone_user_id = utils.get_unix_user(a)[0]
        except KeyError:
            raise ValueError("Unknown user '%s' in --keystone-user" % a)

        try:
            a = CONF.command.keystone_group
            if a:
                keystone_group_id = utils.get_unix_group(a)[0]
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


CMDS = [
    DbSync,
    DbVersion,
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
