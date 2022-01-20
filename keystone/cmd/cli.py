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

import argparse
import datetime
import os
import sys
import uuid

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log
from oslo_serialization import jsonutils
import pbr.version

from keystone.cmd import bootstrap
from keystone.cmd import doctor
from keystone.common import driver_hints
from keystone.common import fernet_utils
from keystone.common import jwt_utils
from keystone.common import sql
from keystone.common.sql import upgrades
from keystone.common import utils
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.federation import idp
from keystone.federation import utils as mapping_engine
from keystone.i18n import _
from keystone.server import backends

CONF = keystone.conf.CONF
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
        self.bootstrapper = bootstrap.Bootstrapper()

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
                                  'e.g. http://127.0.0.1:5000/v3'))
        parser.add_argument('--bootstrap-public-url',
                            metavar='OS_BOOTSTRAP_PUBLIC_URL',
                            help=('The initial identity public url created '
                                  'during the keystone bootstrap process. '
                                  'e.g. http://127.0.0.1:5000/v3'))
        parser.add_argument('--bootstrap-internal-url',
                            metavar='OS_BOOTSTRAP_INTERNAL_URL',
                            help=('The initial identity internal url created '
                                  'during the keystone bootstrap process. '
                                  'e.g. http://127.0.0.1:5000/v3'))
        parser.add_argument('--bootstrap-region-id',
                            metavar='OS_BOOTSTRAP_REGION_ID',
                            help=('The initial region_id endpoints will be '
                                  'placed in during the keystone bootstrap '
                                  'process.'))
        parser.add_argument('--immutable-roles',
                            default=True,
                            action='store_true',
                            help=('Whether default roles (admin, member, and '
                                  'reader) should be immutable. This is the '
                                  'default.'))
        parser.add_argument('--no-immutable-roles',
                            default=False,
                            action='store_true',
                            help=('Whether default roles (admin, member, and '
                                  'reader) should be immutable. Immutable '
                                  'default roles is the default, use this '
                                  'flag to opt out of immutable default '
                                  'roles.'))
        return parser

    def do_bootstrap(self):
        """Perform the bootstrap actions.

        Create bootstrap user, project, and role so that CMS, humans, or
        scripts can continue to perform initial setup (domains, projects,
        services, endpoints, etc) of Keystone when standing up a new
        deployment.
        """
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
        self.service_id = None
        self.endpoints = None

        if self.password is None:
            print(_('ERROR: Either --bootstrap-password argument or '
                    'OS_BOOTSTRAP_PASSWORD must be set.'))
            sys.exit(1)

        self.bootstrapper.admin_password = self.password
        self.bootstrapper.admin_username = self.username
        self.bootstrapper.project_name = self.project_name
        self.bootstrapper.admin_role_name = self.role_name
        self.bootstrapper.service_name = self.service_name
        self.bootstrapper.service_id = self.service_id
        self.bootstrapper.admin_url = self.admin_url
        self.bootstrapper.public_url = self.public_url
        self.bootstrapper.internal_url = self.internal_url
        self.bootstrapper.region_id = self.region_id
        if CONF.command.no_immutable_roles:
            self.bootstrapper.immutable_roles = False
        else:
            self.bootstrapper.immutable_roles = True

        self.bootstrapper.bootstrap()
        self.reader_role_id = self.bootstrapper.reader_role_id
        self.member_role_id = self.bootstrapper.member_role_id
        self.role_id = self.bootstrapper.admin_role_id
        self.project_id = self.bootstrapper.project_id

    @classmethod
    def main(cls):
        klass = cls()
        klass.do_bootstrap()


class Doctor(BaseApp):
    """Diagnose common problems with keystone deployments."""

    name = 'doctor'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(Doctor, cls).add_argument_parser(subparsers)
        return parser

    @staticmethod
    def main():
        # Return a non-zero exit code if we detect any symptoms.
        raise SystemExit(doctor.diagnose())


class DbSync(BaseApp):
    """Sync the database."""

    name = 'db_sync'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DbSync, cls).add_argument_parser(subparsers)
        parser.add_argument(
            'version',
            default=None,
            nargs='?',
            help=(
                'Migrate the database up to a specified version. '
                'If not provided, db_sync will migrate the database to the '
                'latest known version. '
                'Schema downgrades are not supported.'
            ),
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '--expand',
            default=False,
            action='store_true',
            help=(
                'Expand the database schema in preparation for data migration.'
            ),
        )
        group.add_argument(
            '--migrate',
            default=False,
            action='store_true',
            help=(
                'Copy all data that needs to be migrated within the database '
                'ahead of starting the first keystone node upgraded to the '
                'new release. '
                'This command should be run after the --expand command. '
                'Once the --migrate command has completed, you can upgrade '
                'all your keystone nodes to the new release and restart them.'
            ),
        )
        group.add_argument(
            '--contract',
            default=False,
            action='store_true',
            help=(
                'Remove any database tables and columns that are no longer '
                'required. This command should be run after all keystone '
                'nodes are running the new release.'
            ),
        )
        group.add_argument(
            '--check',
            default=False,
            action='store_true',
            help=(
                'Check for outstanding database actions that still need to be '
                'executed. This command can be used to verify the condition '
                'of the current database state.'
            ),
        )
        return parser

    @classmethod
    def check_db_sync_status(cls):
        status = 0
        try:
            expand_version = upgrades.get_db_version(branch='expand')
        except db_exception.DBMigrationError:
            LOG.info(
                'Your database is not currently under version '
                'control or the database is already controlled. '
                'Your first step is to run `keystone-manage db_sync --expand`.'
            )
            return 2

        if isinstance(expand_version, int):
            # we're still using sqlalchemy-migrate
            LOG.info(
                'Your database is currently using legacy version control. '
                'Your first step is to run `keystone-manage db_sync --expand`.'
            )
            return 2

        try:
            contract_version = upgrades.get_db_version(branch='contract')
        except db_exception.DBMigrationError:
            contract_version = None

        heads = upgrades.get_current_heads()

        if (
            upgrades.EXPAND_BRANCH not in heads or
            heads[upgrades.EXPAND_BRANCH] != expand_version
        ):
            LOG.info('Your database is not up to date. Your first step is '
                     'to run `keystone-manage db_sync --expand`.')
            status = 2
        elif (
            upgrades.CONTRACT_BRANCH not in heads or
            heads[upgrades.CONTRACT_BRANCH] != contract_version
        ):
            LOG.info('Expand version is ahead of contract. Your next '
                     'step is to run `keystone-manage db_sync --contract`.')
            status = 4
        else:
            LOG.info('All db_sync commands are upgraded to the same '
                     'version and up-to-date.')

        LOG.info(
            'Current repository versions:\n'
            'Expand: %(expand)s (head: %(expand_head)s)\n'
            'Contract: %(contract)s (head: %(contract_head)s)',
            {
                'expand': expand_version,
                'expand_head': heads.get(upgrades.EXPAND_BRANCH),
                'contract': contract_version,
                'contract_head': heads.get(upgrades.CONTRACT_BRANCH),
            },
        )
        return status

    @staticmethod
    def main():
        if CONF.command.check:
            sys.exit(DbSync.check_db_sync_status())
        elif CONF.command.expand:
            upgrades.expand_schema()
        elif CONF.command.migrate:
            upgrades.migrate_data()
        elif CONF.command.contract:
            upgrades.contract_schema()
        else:
            upgrades.offline_sync_database_to_version(
                CONF.command.version)


class DbVersion(BaseApp):
    """Print the current migration version of the database."""

    name = 'db_version'

    @staticmethod
    def main():
        print(upgrades.get_db_version())


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

    @classmethod
    def initialize_fernet_repository(
            cls, keystone_user_id, keystone_group_id, config_group=None):
        conf_group = getattr(CONF, config_group)
        futils = fernet_utils.FernetUtils(
            conf_group.key_repository,
            conf_group.max_active_keys,
            config_group
        )

        futils.create_key_directory(keystone_user_id, keystone_group_id)
        if futils.validate_key_repository(requires_write=True):
            futils.initialize_key_repository(
                keystone_user_id, keystone_group_id)

    @classmethod
    def rotate_fernet_repository(
            cls, keystone_user_id, keystone_group_id, config_group=None):
        conf_group = getattr(CONF, config_group)
        futils = fernet_utils.FernetUtils(
            conf_group.key_repository,
            conf_group.max_active_keys,
            config_group
        )
        if futils.validate_key_repository(requires_write=True):
            futils.rotate_keys(keystone_user_id, keystone_group_id)


class FernetSetup(BasePermissionsSetup):
    """Setup key repositories for Fernet tokens and auth receipts.

    This also creates a primary key used for both creating and validating
    Fernet tokens and auth receipts. To improve security, you should rotate
    your keys (using keystone-manage fernet_rotate, for example).

    """

    name = 'fernet_setup'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.initialize_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_tokens')

        if (os.path.abspath(CONF.fernet_tokens.key_repository) !=
                os.path.abspath(CONF.fernet_receipts.key_repository)):
            cls.initialize_fernet_repository(
                keystone_user_id, keystone_group_id, 'fernet_receipts')
        elif(CONF.fernet_tokens.max_active_keys !=
                CONF.fernet_receipts.max_active_keys):
            # WARNING(adriant): If the directories are the same,
            # 'max_active_keys' is ignored from fernet_receipts in favor of
            # fernet_tokens to avoid a potential mismatch. Only if the
            # directories are different do we create a different one for
            # receipts, and then respect 'max_active_keys' for receipts.
            LOG.warning(
                "Receipt and Token fernet key directories are the same "
                "but `max_active_keys` is different. Receipt "
                "`max_active_keys` will be ignored in favor of Token "
                "`max_active_keys`."
            )


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
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.rotate_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_tokens')
        if (os.path.abspath(CONF.fernet_tokens.key_repository) !=
                os.path.abspath(CONF.fernet_receipts.key_repository)):
            cls.rotate_fernet_repository(
                keystone_user_id, keystone_group_id, 'fernet_receipts')


class CreateJWSKeyPair(BasePermissionsSetup):
    """Create a key pair for signing and validating JWS tokens.

    This command creates a public and private key pair to use for signing and
    validating JWS token signatures. The key pair is written to the directory
    where the command is invoked.

    """

    name = 'create_jws_keypair'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(CreateJWSKeyPair, cls).add_argument_parser(subparsers)

        parser.add_argument(
            '--force', action='store_true',
            help=('Forcibly overwrite keys if they already exist')
        )
        return parser

    @classmethod
    def main(cls):
        current_directory = os.getcwd()
        private_key_path = os.path.join(current_directory, 'private.pem')
        public_key_path = os.path.join(current_directory, 'public.pem')

        if os.path.isfile(private_key_path) and not CONF.command.force:
            raise SystemExit(_('Private key %(path)s already exists')
                             % {'path': private_key_path})
        if os.path.isfile(public_key_path) and not CONF.command.force:
            raise SystemExit(_('Public key %(path)s already exists')
                             % {'path': public_key_path})

        jwt_utils.create_jws_keypair(private_key_path, public_key_path)


class TokenSetup(BasePermissionsSetup):
    """Setup a key repository for tokens.

    This also creates a primary key used for both creating and validating
    tokens. To improve security, you should rotate your keys (using
    keystone-manage token_rotate, for example).

    """

    name = 'token_setup'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.initialize_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_tokens')


class TokenRotate(BasePermissionsSetup):
    """Rotate token encryption keys.

    This assumes you have already run keystone-manage token_setup.

    A new primary key is placed into rotation, which is used for new tokens.
    The old primary key is demoted to secondary, which can then still be used
    for validating tokens. Excess secondary keys (beyond [token]
    max_active_keys) are revoked. Revoked keys are permanently deleted. A new
    staged key will be created and used to validate tokens. The next time key
    rotation takes place, the staged key will be put into rotation as the
    primary key.

    Rotating keys too frequently, or with [token] max_active_keys set
    too low, will cause tokens to become invalid prior to their expiration.

    """

    name = 'token_rotate'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.rotate_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_tokens')


class ReceiptSetup(BasePermissionsSetup):
    """Setup a key repository for auth receipts.

    This also creates a primary key used for both creating and validating
    receipts. To improve security, you should rotate your keys (using
    keystone-manage receipt_rotate, for example).

    """

    name = 'receipt_setup'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.initialize_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_receipts')


class ReceiptRotate(BasePermissionsSetup):
    """Rotate auth receipts encryption keys.

    This assumes you have already run keystone-manage receipt_setup.

    A new primary key is placed into rotation, which is used for new receipts.
    The old primary key is demoted to secondary, which can then still be used
    for validating receipts. Excess secondary keys (beyond [receipt]
    max_active_keys) are revoked. Revoked keys are permanently deleted. A new
    staged key will be created and used to validate receipts. The next time key
    rotation takes place, the staged key will be put into rotation as the
    primary key.

    Rotating keys too frequently, or with [receipt] max_active_keys set
    too low, will cause receipts to become invalid prior to their expiration.

    """

    name = 'receipt_rotate'

    @classmethod
    def main(cls):
        keystone_user_id, keystone_group_id = cls.get_user_group()
        cls.rotate_fernet_repository(
            keystone_user_id, keystone_group_id, 'fernet_receipts')


class CredentialSetup(BasePermissionsSetup):
    """Setup a Fernet key repository for credential encryption.

    The purpose of this command is very similar to `keystone-manage
    fernet_setup` only the keys included in this repository are for encrypting
    and decrypting credential secrets instead of token payloads. Keys can be
    rotated using `keystone-manage credential_rotate`.
    """

    name = 'credential_setup'

    @classmethod
    def main(cls):
        futils = fernet_utils.FernetUtils(
            CONF.credential.key_repository,
            credential_fernet.MAX_ACTIVE_KEYS,
            'credential'
        )

        keystone_user_id, keystone_group_id = cls.get_user_group()
        futils.create_key_directory(keystone_user_id, keystone_group_id)
        if futils.validate_key_repository(requires_write=True):
            futils.initialize_key_repository(
                keystone_user_id,
                keystone_group_id
            )


class CredentialRotate(BasePermissionsSetup):
    """Rotate Fernet encryption keys for credential encryption.

    This assumes you have already run `keystone-manage credential_setup`.

    A new primary key is placed into rotation only if all credentials are
    encrypted with the current primary key. If any credentials are encrypted
    with a secondary key the rotation will abort. This protects against
    removing a key that is still required to decrypt credentials. Once a key is
    removed from the repository, it is impossible to recover the original data
    without restoring from a backup external to keystone (more on backups
    below). To make sure all credentials are encrypted with the latest primary
    key, please see the `keystone-manage credential_migrate` command. Since the
    maximum number of keys in the credential repository is 3, once all
    credentials are encrypted with the latest primary key we can safely
    introduce a new primary key. All credentials will still be decryptable
    since they are all encrypted with the only secondary key in the repository.

    It is imperitive to understand the importance of backing up keys used to
    encrypt credentials. In the event keys are overrotated, applying a key
    repository from backup can help recover otherwise useless credentials.
    Persisting snapshots of the key repository in secure and encrypted source
    control, or a dedicated key management system are good examples of
    encryption key backups.

    The `keystone-manage credential_rotate` and `keystone-manage
    credential_migrate` commands are intended to be done in sequence. After
    performing a rotation, a migration must be done before performing another
    rotation. This ensures we don't over-rotate encryption keys.

    """

    name = 'credential_rotate'

    def __init__(self):
        drivers = backends.load_backends()
        self.credential_provider_api = drivers['credential_provider_api']
        self.credential_api = drivers['credential_api']

    def validate_primary_key(self):
        crypto, keys = credential_fernet.get_multi_fernet_keys()
        primary_key_hash = credential_fernet.primary_key_hash(keys)

        credentials = self.credential_api.driver.list_credentials(
            driver_hints.Hints()
        )
        for credential in credentials:
            if credential['key_hash'] != primary_key_hash:
                msg = _('Unable to rotate credential keys because not all '
                        'credentials are encrypted with the primary key. '
                        'Please make sure all credentials have been encrypted '
                        'with the primary key using `keystone-manage '
                        'credential_migrate`.')
                raise SystemExit(msg)

    @classmethod
    def main(cls):
        futils = fernet_utils.FernetUtils(
            CONF.credential.key_repository,
            credential_fernet.MAX_ACTIVE_KEYS,
            'credential'
        )

        keystone_user_id, keystone_group_id = cls.get_user_group()
        if futils.validate_key_repository(requires_write=True):
            klass = cls()
            klass.validate_primary_key()
            futils.rotate_keys(keystone_user_id, keystone_group_id)


class CredentialMigrate(BasePermissionsSetup):
    """Provides the ability to encrypt credentials using a new primary key.

    This assumes that there is already a credential key repository in place and
    that the database backend has been upgraded to at least the Newton schema.
    If the credential repository doesn't exist yet, you can use
    ``keystone-manage credential_setup`` to create one.

    """

    name = 'credential_migrate'

    def __init__(self):
        drivers = backends.load_backends()
        self.credential_provider_api = drivers['credential_provider_api']
        self.credential_api = drivers['credential_api']

    def migrate_credentials(self):
        crypto, keys = credential_fernet.get_multi_fernet_keys()
        primary_key_hash = credential_fernet.primary_key_hash(keys)

        # FIXME(lbragstad): We *should* be able to use Hints() to ask only for
        # credentials that have a key_hash equal to a secondary key hash or
        # None, but Hints() doesn't seem to honor None values. See
        # https://bugs.launchpad.net/keystone/+bug/1614154.  As a workaround -
        # we have to ask for *all* credentials and filter them ourselves.
        credentials = self.credential_api.driver.list_credentials(
            driver_hints.Hints()
        )
        for credential in credentials:
            if credential['key_hash'] != primary_key_hash:
                # If the key_hash isn't None but doesn't match the
                # primary_key_hash, then we know the credential was encrypted
                # with a secondary key. Let's decrypt it, and send it through
                # the update path to re-encrypt it with the new primary key.
                decrypted_blob = self.credential_provider_api.decrypt(
                    credential['encrypted_blob']
                )
                cred = {'blob': decrypted_blob}
                self.credential_api.update_credential(
                    credential['id'],
                    cred
                )

    @classmethod
    def main(cls):
        # Check to make sure we have a repository that works...
        futils = fernet_utils.FernetUtils(
            CONF.credential.key_repository,
            credential_fernet.MAX_ACTIVE_KEYS,
            'credential'
        )
        futils.validate_key_repository(requires_write=True)
        klass = cls()
        klass.migrate_credentials()


class TrustFlush(BaseApp):
    """Flush expired and non-expired soft deleted trusts from the backend."""

    name = 'trust_flush'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(TrustFlush, cls).add_argument_parser(subparsers)

        parser.add_argument('--project-id', default=None,
                            help=('The id of the project of which the '
                                  'expired or non-expired soft-deleted '
                                  'trusts is to be purged'))
        parser.add_argument('--trustor-user-id', default=None,
                            help=('The id of the trustor of which the '
                                  'expired or non-expired soft-deleted '
                                  'trusts is to be purged'))
        parser.add_argument('--trustee-user-id', default=None,
                            help=('The id of the trustee of which the '
                                  'expired or non-expired soft-deleted '
                                  'trusts is to be purged'))
        parser.add_argument('--date', default=datetime.datetime.utcnow(),
                            help=('The date of which the expired or '
                                  'non-expired soft-deleted trusts older '
                                  'than that will be purged. The format of '
                                  'the date to be "DD-MM-YYYY". If no date '
                                  'is supplied keystone-manage will use the '
                                  'system clock time at runtime'))
        return parser

    @classmethod
    def main(cls):
        drivers = backends.load_backends()
        trust_manager = drivers['trust_api']
        if CONF.command.date:
            if not isinstance(CONF.command.date, datetime.datetime):
                try:
                    CONF.command.date = datetime.datetime.strptime(
                        CONF.command.date, '%d-%m-%Y')
                except KeyError:
                    raise ValueError("'%s'Invalid input for date, should be "
                                     "DD-MM-YYYY", CONF.command.date)
            else:
                LOG.info("No date is supplied, keystone-manage will use the "
                         "system clock time at runtime ")

        trust_manager.flush_expired_and_soft_deleted_trusts(
            project_id=CONF.command.project_id,
            trustor_user_id=CONF.command.trustor_user_id,
            trustee_user_id=CONF.command.trustee_user_id,
            date=CONF.command.date
        )


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
            mapping['entity_type'] = CONF.command.type

        mapping_manager.purge_mappings(mapping)


DOMAIN_CONF_FHEAD = 'keystone.'
DOMAIN_CONF_FTAIL = '.conf'


def _domain_config_finder(conf_dir):
    """Return a generator of all domain config files found in a directory.

    Domain configs match the filename pattern of
    'keystone.<domain_name>.conf'.

    :returns: generator yielding (filename, domain_name) tuples
    """
    LOG.info('Scanning %r for domain config files', conf_dir)
    for r, d, f in os.walk(conf_dir):
        for fname in f:
            if (fname.startswith(DOMAIN_CONF_FHEAD) and
                    fname.endswith(DOMAIN_CONF_FTAIL)):
                if fname.count('.') >= 2:
                    domain_name = fname[len(DOMAIN_CONF_FHEAD):
                                        -len(DOMAIN_CONF_FTAIL)]
                    yield (os.path.join(r, fname), domain_name)
                    continue

            LOG.warning('Ignoring file (%s) while scanning '
                        'domain config directory', fname)


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
            msg = ('Error processing config file for domain: '
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

        success_cnt = 0
        failure_cnt = 0
        for filename, domain_name in self._domain_config_finder(conf_dir):
            if self._upload_config_to_database(filename, domain_name):
                success_cnt += 1
                LOG.info('Successfully uploaded domain config %r',
                         filename)
            else:
                failure_cnt += 1

        if success_cnt == 0:
            LOG.warning('No domain configs uploaded from %r', conf_dir)

        if failure_cnt:
            return False
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
        print(metadata)


class MappingEngineTester(BaseApp):
    """Execute mapping engine locally."""

    name = 'mapping_engine'

    def __init__(self):
        super(MappingEngineTester, self).__init__()
        self.mapping_id = uuid.uuid4().hex
        self.rules_pathname = None
        self.rules = None
        self.assertion_pathname = None
        self.assertion = None

    def read_rules(self, path):
        self.rules_pathname = path
        try:
            with open(path, "rb") as file:
                self.rules = jsonutils.load(file)
        except ValueError as e:
            raise SystemExit(_('Error while parsing rules '
                               '%(path)s: %(err)s') % {'path': path, 'err': e})

    def read_assertion(self, path):
        self.assertion_pathname = path
        try:
            with open(path) as file:
                self.assertion = file.read().strip()
        except IOError as e:
            raise SystemExit(_("Error while opening file "
                               "%(path)s: %(err)s") % {'path': path, 'err': e})

    def normalize_assertion(self):
        def split(line, line_num):
            try:
                k, v = line.split(':', 1)
                return k.strip(), v.strip()
            except ValueError:
                msg = _("assertion file %(pathname)s at line %(line_num)d "
                        "expected 'key: value' but found '%(line)s' "
                        "see help for file format")
                raise SystemExit(msg % {'pathname': self.assertion_pathname,
                                        'line_num': line_num,
                                        'line': line})
        assertion = self.assertion.splitlines()
        assertion_dict = {}
        prefix = CONF.command.prefix
        for line_num, line in enumerate(assertion, 1):
            line = line.strip()
            if line == '':
                continue
            k, v = split(line, line_num)
            if prefix:
                if k.startswith(prefix):
                    assertion_dict[k] = v
            else:
                assertion_dict[k] = v
        self.assertion = assertion_dict

    def normalize_rules(self):
        if isinstance(self.rules, list):
            self.rules = {'rules': self.rules}

    @classmethod
    def main(cls):
        if CONF.command.engine_debug:
            mapping_engine.LOG.logger.setLevel('DEBUG')
        else:
            mapping_engine.LOG.logger.setLevel('WARN')

        tester = cls()

        tester.read_rules(CONF.command.rules)
        tester.normalize_rules()
        mapping_engine.validate_mapping_structure(tester.rules)

        tester.read_assertion(CONF.command.input)
        tester.normalize_assertion()

        if CONF.command.engine_debug:
            print("Using Rules:\n%s" % (
                jsonutils.dumps(tester.rules, indent=2)))
            print("Using Assertion:\n%s" % (
                jsonutils.dumps(tester.assertion, indent=2)))

        rp = mapping_engine.RuleProcessor(tester.mapping_id,
                                          tester.rules['rules'])
        mapped = rp.process(tester.assertion)
        print(jsonutils.dumps(mapped, indent=2))

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(MappingEngineTester,
                       cls).add_argument_parser(subparsers)

        parser.formatter_class = argparse.RawTextHelpFormatter
        parser.add_argument('--rules', default=None, required=True,
                            help=("Path to the file with "
                                  "rules to be executed. "
                                  "Content must be\na proper JSON structure, "
                                  "with a top-level key 'rules' and\n"
                                  "corresponding value being a list."))
        parser.add_argument('--input', default=None, required=True,
                            help=("Path to the file with input attributes. "
                                  "The content\nconsists of ':' separated "
                                  "parameter names and their values.\nThere "
                                  "is only one key-value pair per line. "
                                  "A ';' in the\nvalue is a separator and "
                                  "then a value is treated as a list.\n"
                                  "Example:\n"
                                  "\tEMAIL: me@example.com\n"
                                  "\tLOGIN: me\n"
                                  "\tGROUPS: group1;group2;group3"))
        parser.add_argument('--prefix', default=None,
                            help=("A prefix used for each environment "
                                  "variable in the\nassertion. For example, "
                                  "all environment variables may have\nthe "
                                  "prefix ASDF_."))
        parser.add_argument('--engine-debug',
                            default=False, action="store_true",
                            help=("Enable debug messages from the mapping "
                                  "engine."))


class MappingPopulate(BaseApp):
    """Pre-populate entries from domain-specific backends.

    Running this command is not required. It should only be run right after
    the LDAP was configured, when many new users were added, or when
    "mapping_purge" is run.

    This command will take a while to run. It is perfectly fine for it to run
    more than several minutes.
    """

    name = "mapping_populate"

    @classmethod
    def load_backends(cls):
        drivers = backends.load_backends()
        cls.identity_api = drivers['identity_api']
        cls.resource_api = drivers['resource_api']

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(MappingPopulate, cls).add_argument_parser(
            subparsers)

        parser.add_argument('--domain-name', default=None, required=True,
                            help=("Name of the domain configured to use "
                                  "domain-specific backend"))
        return parser

    @classmethod
    def main(cls):
        """Process entries for id_mapping_api."""
        cls.load_backends()
        domain_name = CONF.command.domain_name
        try:
            domain_id = cls.resource_api.get_domain_by_name(domain_name)['id']
        except exception.DomainNotFound:
            print(_('Invalid domain name: %(domain)s') % {
                'domain': domain_name})
            return False
        # We don't actually need to tackle id_mapping_api in order to get
        # entries there, because list_users does this anyway. That's why it
        # will be enough to just make the call below.
        cls.identity_api.list_users(domain_scope=domain_id)


CMDS = [
    BootStrap,
    CredentialMigrate,
    CredentialRotate,
    CredentialSetup,
    DbSync,
    DbVersion,
    Doctor,
    DomainConfigUpload,
    FernetRotate,
    FernetSetup,
    CreateJWSKeyPair,
    MappingPopulate,
    MappingPurge,
    MappingEngineTester,
    ReceiptRotate,
    ReceiptSetup,
    SamlIdentityProviderMetadata,
    TokenRotate,
    TokenSetup,
    TrustFlush
]


def add_command_parsers(subparsers):
    for cmd in CMDS:
        cmd.add_argument_parser(subparsers)


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main(argv=None, developer_config_file=None):
    """Main entry point into the keystone-manage CLI utility.

    :param argv: Arguments supplied via the command line using the ``sys``
                 standard library.
    :type argv: list
    :param developer_config_file: The location of a configuration file normally
                                  found in development environments.
    :type developer_config_file: string

    """
    CONF.register_cli_opt(command_opt)

    keystone.conf.configure()
    sql.initialize()
    keystone.conf.set_default_for_default_log_levels()

    user_supplied_config_file = False
    if argv:
        for argument in argv:
            if argument == '--config-file':
                user_supplied_config_file = True

    if developer_config_file:
        developer_config_file = [developer_config_file]

    # NOTE(lbragstad): At this point in processing, the first element of argv
    # is the binary location of keystone-manage, which oslo.config doesn't need
    # and is keystone specific. Only pass a list of arguments so that
    # oslo.config can determine configuration file locations based on user
    # provided arguments, if present.
    CONF(args=argv[1:],
         project='keystone',
         version=pbr.version.VersionInfo('keystone').version_string(),
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=developer_config_file)

    if not CONF.default_config_files and not user_supplied_config_file:
        LOG.warning('Config file not found, using default configs.')
    keystone.conf.setup_logging()
    CONF.command.cmd_class.main()
