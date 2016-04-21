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
from __future__ import print_function

import os
import sys
import uuid

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
from oslo_serialization import jsonutils
import pbr.version

from keystone.common import config
from keystone.common import driver_hints
from keystone.common import openssl
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone.common import utils
from keystone import exception
from keystone.federation import idp
from keystone.federation import utils as mapping_engine
from keystone.i18n import _, _LE, _LI, _LW
from keystone.server import backends
from keystone import token


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class BaseApp(object):

    name = None

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = subparsers.add_parser(cls.name, help=cls.__doc__)
        parser.set_defaults(cmd_class=cls)
        return parser


class BootStrap(BaseApp):
    """Perform the basic bootstrap process."""

    name = "bootstrap"

    def __init__(self):
        self.load_backends()
        self.project_id = uuid.uuid4().hex
        self.role_id = uuid.uuid4().hex
        self.service_id = None
        self.service_name = None
        self.username = None
        self.project_name = None
        self.role_name = None
        self.password = None
        self.public_url = None
        self.internal_url = None
        self.admin_url = None
        self.region_id = None
        self.endpoints = {}

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BootStrap, cls).add_argument_parser(subparsers)
        parser.add_argument('--bootstrap-username', default='admin',
                            metavar='OS_BOOTSTRAP_USERNAME',
                            help=('The username of the initial keystone '
                                  'user during bootstrap process.'))
        # NOTE(morganfainberg): See below for ENV Variable that can be used
        # in lieu of the command-line arguments.
        parser.add_argument('--bootstrap-password', default=None,
                            metavar='OS_BOOTSTRAP_PASSWORD',
                            help='The bootstrap user password')
        parser.add_argument('--bootstrap-project-name', default='admin',
                            metavar='OS_BOOTSTRAP_PROJECT_NAME',
                            help=('The initial project created during the '
                                  'keystone bootstrap process.'))
        parser.add_argument('--bootstrap-role-name', default='admin',
                            metavar='OS_BOOTSTRAP_ROLE_NAME',
                            help=('The initial role-name created during the '
                                  'keystone bootstrap process.'))
        parser.add_argument('--bootstrap-service-name', default='keystone',
                            metavar='OS_BOOTSTRAP_SERVICE_NAME',
                            help=('The initial name for the initial identity '
                                  'service created during the keystone '
                                  'bootstrap process.'))
        parser.add_argument('--bootstrap-admin-url',
                            metavar='OS_BOOTSTRAP_ADMIN_URL',
                            help=('The initial identity admin url created '
                                  'during the keystone bootstrap process. '
                                  'e.g. http://127.0.0.1:35357/v2.0'))
        parser.add_argument('--bootstrap-public-url',
                            metavar='OS_BOOTSTRAP_PUBLIC_URL',
                            help=('The initial identity public url created '
                                  'during the keystone bootstrap process. '
                                  'e.g. http://127.0.0.1:5000/v2.0'))
        parser.add_argument('--bootstrap-internal-url',
                            metavar='OS_BOOTSTRAP_INTERNAL_URL',
                            help=('The initial identity internal url created '
                                  'during the keystone bootstrap process. '
                                  'e.g. http://127.0.0.1:5000/v2.0'))
        parser.add_argument('--bootstrap-region-id',
                            metavar='OS_BOOTSTRAP_REGION_ID',
                            help=('The initial region_id endpoints will be '
                                  'placed in during the keystone bootstrap '
                                  'process.'))
        return parser

    def load_backends(self):
        drivers = backends.load_backends()
        self.resource_manager = drivers['resource_api']
        self.identity_manager = drivers['identity_api']
        self.assignment_manager = drivers['assignment_api']
        self.catalog_manager = drivers['catalog_api']
        self.role_manager = drivers['role_api']

    def _get_config(self):
        self.username = (
            os.environ.get('OS_BOOTSTRAP_USERNAME') or
            CONF.command.bootstrap_username)
        self.project_name = (
            os.environ.get('OS_BOOTSTRAP_PROJECT_NAME') or
            CONF.command.bootstrap_project_name)
        self.role_name = (
            os.environ.get('OS_BOOTSTRAP_ROLE_NAME') or
            CONF.command.bootstrap_role_name)
        self.password = (
            os.environ.get('OS_BOOTSTRAP_PASSWORD') or
            CONF.command.bootstrap_password)
        self.service_name = (
            os.environ.get('OS_BOOTSTRAP_SERVICE_NAME') or
            CONF.command.bootstrap_service_name)
        self.admin_url = (
            os.environ.get('OS_BOOTSTRAP_ADMIN_URL') or
            CONF.command.bootstrap_admin_url)
        self.public_url = (
            os.environ.get('OS_BOOTSTRAP_PUBLIC_URL') or
            CONF.command.bootstrap_public_url)
        self.internal_url = (
            os.environ.get('OS_BOOTSTRAP_INTERNAL_URL') or
            CONF.command.bootstrap_internal_url)
        self.region_id = (
            os.environ.get('OS_BOOTSTRAP_REGION_ID') or
            CONF.command.bootstrap_region_id)

    def do_bootstrap(self):
        """Perform the bootstrap actions.

        Create bootstrap user, project, and role so that CMS, humans, or
        scripts can continue to perform initial setup (domains, projects,
        services, endpoints, etc) of Keystone when standing up a new
        deployment.
        """
        self._get_config()

        if self.password is None:
            print(_('Either --bootstrap-password argument or '
                    'OS_BOOTSTRAP_PASSWORD must be set.'))
            raise ValueError

        # NOTE(morganfainberg): Ensure the default domain is in-fact created
        default_domain = {
            'id': CONF.identity.default_domain_id,
            'name': 'Default',
            'enabled': True,
            'description': 'The default domain'
        }
        try:
            self.resource_manager.create_domain(
                domain_id=default_domain['id'],
                domain=default_domain)
            LOG.info(_LI('Created domain %s'), default_domain['id'])
        except exception.Conflict:
            # NOTE(morganfainberg): Domain already exists, continue on.
            LOG.info(_LI('Domain %s already exists, skipping creation.'),
                     default_domain['id'])

        try:
            self.resource_manager.create_project(
                project_id=self.project_id,
                project={'enabled': True,
                         'id': self.project_id,
                         'domain_id': default_domain['id'],
                         'description': 'Bootstrap project for initializing '
                                        'the cloud.',
                         'name': self.project_name}
            )
            LOG.info(_LI('Created project %s'), self.project_name)
        except exception.Conflict:
            LOG.info(_LI('Project %s already exists, skipping creation.'),
                     self.project_name)
            project = self.resource_manager.get_project_by_name(
                self.project_name, default_domain['id'])
            self.project_id = project['id']

        # NOTE(morganfainberg): Do not create the user if it already exists.
        try:
            user = self.identity_manager.get_user_by_name(self.username,
                                                          default_domain['id'])
            LOG.info(_LI('User %s already exists, skipping creation.'),
                     self.username)
        except exception.UserNotFound:
            user = self.identity_manager.create_user(
                user_ref={'name': self.username,
                          'enabled': True,
                          'domain_id': default_domain['id'],
                          'password': self.password
                          }
            )
            LOG.info(_LI('Created user %s'), self.username)

        # NOTE(morganfainberg): Do not create the role if it already exists.
        try:
            self.role_manager.create_role(
                role_id=self.role_id,
                role={'name': self.role_name,
                      'id': self.role_id},
            )
            LOG.info(_LI('Created role %s'), self.role_name)
        except exception.Conflict:
            LOG.info(_LI('Role %s exists, skipping creation.'), self.role_name)
            # NOTE(davechen): There is no backend method to get the role
            # by name, so build the hints to list the roles and filter by
            # name instead.
            hints = driver_hints.Hints()
            hints.add_filter('name', self.role_name)
            role = self.role_manager.list_roles(hints)
            self.role_id = role[0]['id']

        # NOTE(morganfainberg): Handle the case that the role assignment has
        # already occurred.
        try:
            self.assignment_manager.add_role_to_user_and_project(
                user_id=user['id'],
                tenant_id=self.project_id,
                role_id=self.role_id
            )
            LOG.info(_LI('Granted %(role)s on %(project)s to user'
                         ' %(username)s.'),
                     {'role': self.role_name,
                      'project': self.project_name,
                      'username': self.username})
        except exception.Conflict:
            LOG.info(_LI('User %(username)s already has %(role)s on '
                         '%(project)s.'),
                     {'username': self.username,
                      'role': self.role_name,
                      'project': self.project_name})

        if self.region_id:
            try:
                self.catalog_manager.create_region(
                    region_ref={'id': self.region_id}
                )
                LOG.info(_LI('Created region %s'), self.region_id)
            except exception.Conflict:
                LOG.info(_LI('Region %s exists, skipping creation.'),
                         self.region_id)

        if self.public_url or self.admin_url or self.internal_url:
            hints = driver_hints.Hints()
            hints.add_filter('type', 'identity')
            services = self.catalog_manager.list_services(hints)

            if services:
                service_ref = services[0]

                hints = driver_hints.Hints()
                hints.add_filter('service_id', service_ref['id'])
                if self.region_id:
                    hints.add_filter('region_id', self.region_id)

                endpoints = self.catalog_manager.list_endpoints(hints)
            else:
                service_ref = {'id': uuid.uuid4().hex,
                               'name': self.service_name,
                               'type': 'identity',
                               'enabled': True}

                self.catalog_manager.create_service(
                    service_id=service_ref['id'],
                    service_ref=service_ref)

                endpoints = []

            self.service_id = service_ref['id']

            available_interfaces = {e['interface']: e for e in endpoints}
            expected_endpoints = {'public': self.public_url,
                                  'internal': self.internal_url,
                                  'admin': self.admin_url}

            for interface, url in expected_endpoints.items():
                if not url:
                    # not specified to bootstrap command
                    continue

                try:
                    endpoint_ref = available_interfaces[interface]
                except KeyError:
                    endpoint_ref = {'id': uuid.uuid4().hex,
                                    'interface': interface,
                                    'url': url,
                                    'service_id': self.service_id,
                                    'enabled': True}

                    if self.region_id:
                        endpoint_ref['region_id'] = self.region_id

                    self.catalog_manager.create_endpoint(
                        endpoint_id=endpoint_ref['id'],
                        endpoint_ref=endpoint_ref)

                    LOG.info(_LI('Created %(interface)s endpoint %(url)s'),
                             {'interface': interface, 'url': url})
                else:
                    # NOTE(jamielennox): electing not to update existing
                    # endpoints here. There may be call to do so in future.
                    LOG.info(_LI('Skipping %s endpoint as already created'),
                             interface)

                self.endpoints[interface] = endpoint_ref['id']

    @classmethod
    def main(cls):
        klass = cls()
        klass.do_bootstrap()


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
                                  'version. Schema downgrades are not '
                                  'supported.'))
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
                            help=('Print the migration version of the '
                                  'database for the specified extension. If '
                                  'not provided, print it for the common '
                                  'repository.'))

    @staticmethod
    def main():
        extension = CONF.command.extension
        migration_helpers.print_db_version(extension)


class BasePermissionsSetup(BaseApp):
    """Common user/group setup for file permissions."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BasePermissionsSetup,
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


class BaseCertificateSetup(BasePermissionsSetup):
    """Provides common options for certificate setup."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BaseCertificateSetup,
                       cls).add_argument_parser(subparsers)
        parser.add_argument('--rebuild', default=False, action='store_true',
                            help=('Rebuild certificate files: erase previous '
                                  'files and regenerate them.'))
        return parser


class PKISetup(BaseCertificateSetup):
    """Set up Key pairs and certificates for token signing and verification.

    This is NOT intended for production use, see Keystone Configuration
    documentation for details. As of the Mitaka release, this command has
    been DEPRECATED and may be removed in the 'O' release.
    """

    name = 'pki_setup'

    @classmethod
    def main(cls):
        versionutils.report_deprecated_feature(
            LOG,
            _LW("keystone-manage pki_setup is deprecated as of Mitaka in "
                "favor of not using PKI tokens and may be removed in 'O' "
                "release."))
        LOG.warning(_LW('keystone-manage pki_setup is not recommended for '
                        'production use.'))
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_pki = openssl.ConfigurePKI(keystone_user_id, keystone_group_id,
                                        rebuild=CONF.command.rebuild)
        conf_pki.run()


class FernetSetup(BasePermissionsSetup):
    """Setup a key repository for Fernet tokens.

    This also creates a primary key used for both creating and validating
    Fernet tokens. To improve security, you should rotate your keys (using
    keystone-manage fernet_rotate, for example).

    """

    name = 'fernet_setup'

    @classmethod
    def main(cls):
        from keystone.token.providers.fernet import utils as fernet

        keystone_user_id, keystone_group_id = cls.get_user_group()
        fernet.create_key_directory(keystone_user_id, keystone_group_id)
        if fernet.validate_key_repository(requires_write=True):
            fernet.initialize_key_repository(
                keystone_user_id, keystone_group_id)


class FernetRotate(BasePermissionsSetup):
    """Rotate Fernet encryption keys.

    This assumes you have already run keystone-manage fernet_setup.

    A new primary key is placed into rotation, which is used for new tokens.
    The old primary key is demoted to secondary, which can then still be used
    for validating tokens. Excess secondary keys (beyond [fernet_tokens]
    max_active_keys) are revoked. Revoked keys are permanently deleted. A new
    staged key will be created and used to validate tokens. The next time key
    rotation takes place, the staged key will be put into rotation as the
    primary key.

    Rotating keys too frequently, or with [fernet_tokens] max_active_keys set
    too low, will cause tokens to become invalid prior to their expiration.

    """

    name = 'fernet_rotate'

    @classmethod
    def main(cls):
        from keystone.token.providers.fernet import utils as fernet

        keystone_user_id, keystone_group_id = cls.get_user_group()
        if fernet.validate_key_repository(requires_write=True):
            fernet.rotate_keys(keystone_user_id, keystone_group_id)


class TokenFlush(BaseApp):
    """Flush expired tokens from the backend."""

    name = 'token_flush'

    @classmethod
    def main(cls):
        token_manager = token.persistence.PersistenceManager()
        token_manager.flush_expired_tokens()


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
            # NOTE(henry-nash): It would be nice to use the argparse automated
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
                return resource_manager.get_domain_by_name(name)['id']
            except KeyError:
                raise ValueError(_("Unknown domain '%(name)s' specified by "
                                   "--domain-name") % {'name': name})

        validate_options()
        drivers = backends.load_backends()
        resource_manager = drivers['resource_api']
        mapping_manager = drivers['id_mapping_api']

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

        mapping_manager.purge_mappings(mapping)


DOMAIN_CONF_FHEAD = 'keystone.'
DOMAIN_CONF_FTAIL = '.conf'


def _domain_config_finder(conf_dir):
    """Return a generator of all domain config files found in a directory.

    Donmain configs match the filename pattern of
    'keystone.<domain_name>.conf'.

    :returns: generator yeilding (filename, domain_name) tuples
    """
    LOG.info(_LI('Scanning %r for domain config files'), conf_dir)
    for r, d, f in os.walk(conf_dir):
        for fname in f:
            if (fname.startswith(DOMAIN_CONF_FHEAD) and
                    fname.endswith(DOMAIN_CONF_FTAIL)):
                if fname.count('.') >= 2:
                    domain_name = fname[len(DOMAIN_CONF_FHEAD):
                                        -len(DOMAIN_CONF_FTAIL)]
                    yield (os.path.join(r, fname), domain_name)
                    continue

            LOG.warning(_LW('Ignoring file (%s) while scanning '
                            'domain config directory'), fname)


class DomainConfigUploadFiles(object):

    def __init__(self, domain_config_finder=_domain_config_finder):
        super(DomainConfigUploadFiles, self).__init__()
        self.load_backends()
        self._domain_config_finder = domain_config_finder

    def load_backends(self):
        drivers = backends.load_backends()
        self.resource_manager = drivers['resource_api']
        self.domain_config_manager = drivers['domain_config_api']

    def valid_options(self):
        """Validate the options, returning True if they are indeed valid.

        It would be nice to use the argparse automated checking for this
        validation, but the only way I can see doing that is to make the
        default (i.e. if no optional parameters are specified) to upload
        all configuration files - and that sounds too dangerous as a
        default. So we use it in a slightly unconventional way, where all
        parameters are optional, but you must specify at least one.

        """
        if (CONF.command.all is False and
                CONF.command.domain_name is None):
            print(_('At least one option must be provided, use either '
                    '--all or --domain-name'))
            return False

        if (CONF.command.all is True and
                CONF.command.domain_name is not None):
            print(_('The --all option cannot be used with '
                    'the --domain-name option'))
            return False

        return True

    def _upload_config_to_database(self, file_name, domain_name):
        """Upload a single config file to the database.

        :param file_name: the file containing the config options
        :param domain_name: the domain name
        :returns: a boolean indicating if the upload succeeded

        """
        try:
            domain_ref = (
                self.resource_manager.get_domain_by_name(domain_name))
        except exception.DomainNotFound:
            print(_('Invalid domain name: %(domain)s found in config file '
                    'name: %(file)s - ignoring this file.') % {
                        'domain': domain_name,
                        'file': file_name})
            return False

        if self.domain_config_manager.get_config_with_sensitive_info(
                domain_ref['id']):
            print(_('Domain: %(domain)s already has a configuration '
                    'defined - ignoring file: %(file)s.') % {
                        'domain': domain_name,
                        'file': file_name})
            return False

        sections = {}
        try:
            parser = cfg.ConfigParser(file_name, sections)
            parser.parse()
        except Exception:
            # We explicitly don't try and differentiate the error cases, in
            # order to keep the code in this tool more robust as oslo.config
            # changes.
            print(_('Error parsing configuration file for domain: %(domain)s, '
                    'file: %(file)s.') % {
                        'domain': domain_name,
                        'file': file_name})
            return False

        try:
            for group in sections:
                for option in sections[group]:
                        sections[group][option] = sections[group][option][0]
            self.domain_config_manager.create_config(domain_ref['id'],
                                                     sections)
            return True
        except Exception as e:
            msg = _LE('Error processing config file for domain: '
                      '%(domain_name)s, file: %(filename)s, error: %(error)s')
            LOG.error(msg,
                      {'domain_name': domain_name,
                       'filename': file_name,
                       'error': e},
                      exc_info=True)
            return False

    def read_domain_configs_from_files(self):
        """Read configs from file(s) and load into database.

        The command line parameters have already been parsed and the CONF
        command option will have been set. It is either set to the name of an
        explicit domain, or it's None to indicate that we want all domain
        config files.

        """
        domain_name = CONF.command.domain_name
        conf_dir = CONF.identity.domain_config_dir
        if not os.path.exists(conf_dir):
            print(_('Unable to locate domain config directory: %s') % conf_dir)
            raise ValueError

        if domain_name:
            # Request is to upload the configs for just one domain
            fname = DOMAIN_CONF_FHEAD + domain_name + DOMAIN_CONF_FTAIL
            if not self._upload_config_to_database(
                    os.path.join(conf_dir, fname), domain_name):
                return False
            return True

        for filename, domain_name in self._domain_config_finder(conf_dir):
            self._upload_config_to_database(filename, domain_name)

        return True

    def run(self):
        # First off, let's just check we can talk to the domain database
        try:
            self.resource_manager.list_domains(driver_hints.Hints())
        except Exception:
            # It is likely that there is some SQL or other backend error
            # related to set up
            print(_('Unable to access the keystone database, please check it '
                    'is configured correctly.'))
            raise

        if not self.valid_options():
            return 1

        if not self.read_domain_configs_from_files():
            return 1


class DomainConfigUpload(BaseApp):
    """Upload the domain specific configuration files to the database."""

    name = 'domain_config_upload'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DomainConfigUpload, cls).add_argument_parser(subparsers)
        parser.add_argument('--all', default=False, action='store_true',
                            help='Upload contents of all domain specific '
                                 'configuration files. Either use this option '
                                 'or use the --domain-name option to choose a '
                                 'specific domain.')
        parser.add_argument('--domain-name', default=None,
                            help='Upload contents of the specific '
                                 'configuration file for the given domain. '
                                 'Either use this option or use the --all '
                                 'option to upload contents for all domains.')
        return parser

    @staticmethod
    def main():
        dcu = DomainConfigUploadFiles()
        status = dcu.run()
        if status is not None:
            sys.exit(status)


class SamlIdentityProviderMetadata(BaseApp):
    """Generate Identity Provider metadata."""

    name = 'saml_idp_metadata'

    @staticmethod
    def main():
        metadata = idp.MetadataGenerator().generate_metadata()
        print(metadata.to_string())


class MappingEngineTester(BaseApp):
    """Execute mapping engine locally."""

    name = 'mapping_engine'

    @staticmethod
    def read_rules(path):
        try:
            with open(path) as file:
                return jsonutils.load(file)
        except ValueError as e:
            raise SystemExit(_('Error while parsing rules '
                               '%(path)s: %(err)s') % {'path': path, 'err': e})

    @staticmethod
    def read_file(path):
        try:
            with open(path) as file:
                return file.read().strip()
        except IOError as e:
            raise SystemExit(_("Error while opening file "
                               "%(path)s: %(err)s") % {'path': path, 'err': e})

    @staticmethod
    def normalize_assertion(assertion):
        def split(line):
            try:
                k, v = line.split(':', 1)
                return k.strip(), v.strip()
            except ValueError as e:
                msg = _("Error while parsing line: '%(line)s': %(err)s")
                raise SystemExit(msg % {'line': line, 'err': e})
        assertion = assertion.split('\n')
        assertion_dict = {}
        prefix = CONF.command.prefix
        for line in assertion:
            k, v = split(line)
            if prefix:
                if k.startswith(prefix):
                    assertion_dict[k] = v
            else:
                assertion_dict[k] = v
        return assertion_dict

    @staticmethod
    def normalize_rules(rules):
        if isinstance(rules, list):
            return {'rules': rules}
        else:
            return rules

    @classmethod
    def main(cls):
        if not CONF.command.engine_debug:
            mapping_engine.LOG.logger.setLevel('WARN')

        rules = MappingEngineTester.read_rules(CONF.command.rules)
        rules = MappingEngineTester.normalize_rules(rules)
        mapping_engine.validate_mapping_structure(rules)

        assertion = MappingEngineTester.read_file(CONF.command.input)
        assertion = MappingEngineTester.normalize_assertion(assertion)
        rp = mapping_engine.RuleProcessor(rules['rules'])
        print(jsonutils.dumps(rp.process(assertion), indent=2))

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(MappingEngineTester,
                       cls).add_argument_parser(subparsers)

        parser.add_argument('--rules', default=None, required=True,
                            help=("Path to the file with "
                                  "rules to be executed. "
                                  "Content must be a proper JSON structure, "
                                  "with a top-level key 'rules' and "
                                  "corresponding value being a list."))
        parser.add_argument('--input', default=None, required=True,
                            help=("Path to the file with input attributes. "
                                  "The content consists of ':' separated "
                                  "parameter names and their values. "
                                  "There is only one key-value pair per line. "
                                  "A ';' in the value is a separator and then "
                                  "a value is treated as a list. Example:\n "
                                  "EMAIL: me@example.com\n"
                                  "LOGIN: me\n"
                                  "GROUPS: group1;group2;group3"))
        parser.add_argument('--prefix', default=None,
                            help=("A prefix used for each environment "
                                  "variable in the assertion. For example, "
                                  "all environment variables may have the "
                                  "prefix ASDF_."))
        parser.add_argument('--engine-debug',
                            default=False, action="store_true",
                            help=("Enable debug messages from the mapping "
                                  "engine."))


CMDS = [
    BootStrap,
    DbSync,
    DbVersion,
    DomainConfigUpload,
    FernetRotate,
    FernetSetup,
    MappingPurge,
    MappingEngineTester,
    PKISetup,
    SamlIdentityProviderMetadata,
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
    if not CONF.default_config_files:
        LOG.warning(_LW('Config file not found, using default configs.'))
    config.setup_logging()
    CONF.command.cmd_class.main()
