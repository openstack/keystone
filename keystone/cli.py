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

from oslo.config import cfg
import pbr.version

from keystone import assignment
from keystone.common import openssl
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone.common import utils
from keystone import config
from keystone.i18n import _
from keystone import identity
from keystone.openstack.common import log
from keystone import token


LOG = log.getLogger(__name__)

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
        migration_helpers.sync_database_to_version(extension, version)


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
        migration_helpers.print_db_version(extension)


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
    """Set up Key pairs and certificates for token signing and verification.

    This is NOT intended for production use, see Keystone Configuration
    documentation for details.
    """

    name = 'pki_setup'

    @classmethod
    def main(cls):
        msg = _('keystone-manage pki_setup is not recommended for production '
                'use.')
        LOG.warn(msg)
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_pki = openssl.ConfigurePKI(keystone_user_id, keystone_group_id)
        conf_pki.run()


class SSLSetup(BaseCertificateSetup):
    """Create key pairs and certificates for HTTPS connections.

    This is NOT intended for production use, see Keystone Configuration
    documentation for details.
    """

    name = 'ssl_setup'

    @classmethod
    def main(cls):
        msg = _('keystone-manage ssl_setup is not recommended for production '
                'use.')
        LOG.warn(msg)
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_ssl = openssl.ConfigureSSL(keystone_user_id, keystone_group_id)
        conf_ssl.run()


class TokenFlush(BaseApp):
    """Flush expired tokens from the backend."""

    name = 'token_flush'

    @classmethod
    def main(cls):
        token_manager = token.persistence.PersistenceManager()
        token_manager.driver.flush_expired_tokens()


class MappingPurge(BaseApp):
    """Purge the mapping table."""

    name = 'mapping_purge'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(MappingPurge, cls).add_argument_parser(subparsers)
        parser.add_argument('--all', default=False, action='store_true',
                            help=('Purge all mappings.'))
        parser.add_argument('--domain-name', default=None,
                            help=('Purge any mappings for the domain '
                                  'specified.'))
        parser.add_argument('--public-id', default=None,
                            help=('Purge the mapping for the Public ID '
                                  'specified.'))
        parser.add_argument('--local-id', default=None,
                            help=('Purge the mappings for the Local ID '
                                  'specified.'))
        parser.add_argument('--type', default=None, choices=['user', 'group'],
                            help=('Purge any mappings for the type '
                                  'specified.'))
        return parser

    @staticmethod
    def main():
        def validate_options():
            # NOTE(henry-nash); It would be nice to use the argparse automated
            # checking for this validation, but the only way I can see doing
            # that is to make the default (i.e. if no optional parameters
            # are specified) to purge all mappings - and that sounds too
            # dangerous as a default.  So we use it in a slightly
            # unconventional way, where all parameters are optional, but you
            # must specify at least one.
            if (CONF.command.all is False and
                CONF.command.domain_name is None and
                CONF.command.public_id is None and
                CONF.command.local_id is None and
                    CONF.command.type is None):
                raise ValueError(_('At least one option must be provided'))

            if (CONF.command.all is True and
                (CONF.command.domain_name is not None or
                 CONF.command.public_id is not None or
                 CONF.command.local_id is not None or
                 CONF.command.type is not None)):
                raise ValueError(_('--all option cannot be mixed with '
                                   'other options'))

        def get_domain_id(name):
            try:
                identity.Manager()
                assignment_manager = assignment.Manager()
                return assignment_manager.driver.get_domain_by_name(name)['id']
            except KeyError:
                raise ValueError(_("Unknown domain '%(name)s' specified by "
                                   "--domain-name") % {'name': name})

        validate_options()
        # Now that we have validated the options, we know that at least one
        # option has been specified, and if it was the --all option then this
        # was the only option specified.
        #
        # The mapping dict is used to filter which mappings are purged, so
        # leaving it empty means purge them all
        mapping = {}
        if CONF.command.domain_name is not None:
            mapping['domain_id'] = get_domain_id(CONF.command.domain_name)
        if CONF.command.public_id is not None:
            mapping['public_id'] = CONF.command.public_id
        if CONF.command.local_id is not None:
            mapping['local_id'] = CONF.command.local_id
        if CONF.command.type is not None:
            mapping['type'] = CONF.command.type

        mapping_manager = identity.MappingManager()
        mapping_manager.driver.purge_mappings(mapping)


class SamlIdentityProviderMetadata(BaseApp):
    """Generate Identity Provider metadata."""

    name = 'saml_idp_metadata'

    @staticmethod
    def main():
        # NOTE(marek-denis): Since federation is currently an extension import
        # corresponding modules only when they are really going to be used.
        from keystone.contrib.federation import idp
        metadata = idp.MetadataGenerator().generate_metadata()
        print(metadata.to_string())


CMDS = [
    DbSync,
    DbVersion,
    MappingPurge,
    PKISetup,
    SamlIdentityProviderMetadata,
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

    config.configure()
    sql.initialize()
    config.set_default_for_default_log_levels()

    CONF(args=argv[1:],
         project='keystone',
         version=pbr.version.VersionInfo('keystone').version_string(),
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=config_files)
    config.setup_logging()
    CONF.command.cmd_class.main()
