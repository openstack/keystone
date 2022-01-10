# Copyright 2013 OpenStack Foundation
# Copyright 2013 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import migrate
from migrate.versioning import api as versioning_api
from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import migration

from keystone.common import sql
from keystone import exception

INITIAL_VERSION = 72
EXPAND_REPO = 'expand_repo'
DATA_MIGRATION_REPO = 'data_migration_repo'
CONTRACT_REPO = 'contract_repo'


class Repository(object):
    def __init__(self, engine, repo_name):
        self.repo_name = repo_name

        self.repo_path = find_repo(self.repo_name)
        self.min_version = INITIAL_VERSION
        self.schema_ = versioning_api.ControlledSchema.create(
            engine, self.repo_path, self.min_version)
        self.max_version = self.schema_.repository.version().version

    def upgrade(self, version=None, current_schema=None):
        version = version or self.max_version
        err = ''
        upgrade = True
        version = versioning_api._migrate_version(
            self.schema_, version, upgrade, err)
        validate_upgrade_order(self.repo_name, target_repo_version=version)
        if not current_schema:
            current_schema = self.schema_
        changeset = current_schema.changeset(version)
        for ver, change in changeset:
            self.schema_.runchange(ver, change, changeset.step)

        if self.schema_.version != version:
            raise Exception(
                'Actual version (%s) of %s does not equal expected '
                'version (%s)' % (
                    self.schema_.version, self.repo_name, version))

    @property
    def version(self):
        with sql.session_for_read() as session:
            return migration.db_version(
                session.get_bind(), self.repo_path, self.min_version)


def find_repo(repo_name):
    """Return the absolute path to the named repository."""
    path = os.path.abspath(
        os.path.join(
            os.path.dirname(sql.__file__),
            'legacy_migrations',
            repo_name,
        )
    )

    if not os.path.isdir(path):
        raise exception.MigrationNotProvided(sql.__name__, path)

    return path


def _sync_repo(repo_name):
    abs_path = find_repo(repo_name)
    with sql.session_for_write() as session:
        engine = session.get_bind()
        migration.db_sync(
            engine,
            abs_path,
            init_version=INITIAL_VERSION,
            sanity_check=False,
        )


def offline_sync_database_to_version(version=None):
    """Perform and off-line sync of the database.

    Migrate the database up to the latest version, doing the equivalent of
    the cycle of --expand, --migrate and --contract, for when an offline
    upgrade is being performed.

    If a version is specified then only migrate the database up to that
    version. Downgrading is not supported. If version is specified, then only
    the main database migration is carried out - and the expand, migration and
    contract phases will NOT be run.
    """
    if version:
        raise Exception('Specifying a version is no longer supported')

    expand_schema()
    migrate_data()
    contract_schema()


def get_db_version(repo=EXPAND_REPO):
    with sql.session_for_read() as session:
        repo = find_repo(repo)
        return migration.db_version(session.get_bind(), repo, INITIAL_VERSION)


def validate_upgrade_order(repo_name, target_repo_version=None):
    """Validate the state of the migration repositories.

    This is run before allowing the db_sync command to execute. Ensure the
    upgrade step and version specified by the operator remains consistent with
    the upgrade process. I.e. expand's version is greater or equal to
    migrate's, migrate's version is greater or equal to contract's.

    :param repo_name: The name of the repository that the user is trying to
                      upgrade.
    :param target_repo_version: The version to upgrade the repo. Otherwise, the
                                version will be upgraded to the latest version
                                available.
    """
    # Initialize a dict to have each key assigned a repo with their value being
    # the repo that comes before.
    db_sync_order = {DATA_MIGRATION_REPO: EXPAND_REPO,
                     CONTRACT_REPO: DATA_MIGRATION_REPO}

    if repo_name == EXPAND_REPO:
        return

    # find the latest version that the current command will upgrade to if there
    # wasn't a version specified for upgrade.
    if not target_repo_version:
        abs_path = find_repo(repo_name)
        repo = migrate.versioning.repository.Repository(abs_path)
        target_repo_version = int(repo.latest)

    # get current version of the command that runs before the current command.
    dependency_repo_version = get_db_version(repo=db_sync_order[repo_name])

    if dependency_repo_version < target_repo_version:
        raise db_exception.DBMigrationError(
            'You are attempting to upgrade %s ahead of %s. Please refer to '
            'https://docs.openstack.org/keystone/latest/admin/'
            'identity-upgrading.html '
            'to see the proper steps for rolling upgrades.' % (
                repo_name, db_sync_order[repo_name]))


def expand_schema():
    """Expand the database schema ahead of data migration.

    This is run manually by the keystone-manage command before the first
    keystone node is migrated to the latest release.
    """
    validate_upgrade_order(EXPAND_REPO)
    _sync_repo(repo_name=EXPAND_REPO)


def migrate_data():
    """Migrate data to match the new schema.

    This is run manually by the keystone-manage command once the keystone
    schema has been expanded for the new release.
    """
    validate_upgrade_order(DATA_MIGRATION_REPO)
    _sync_repo(repo_name=DATA_MIGRATION_REPO)


def contract_schema():
    """Contract the database.

    This is run manually by the keystone-manage command once the keystone
    nodes have been upgraded to the latest release and will remove any old
    tables/columns that are no longer required.
    """
    validate_upgrade_order(CONTRACT_REPO)
    _sync_repo(repo_name=CONTRACT_REPO)
