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

from migrate import exceptions as migrate_exceptions
from migrate.versioning import api as migrate_api
from migrate.versioning import repository as migrate_repository
from oslo_db import exception as db_exception
import sqlalchemy as sa

from keystone.common import sql
from keystone import exception
from keystone.i18n import _

INITIAL_VERSION = 72
LATEST_VERSION = 79
EXPAND_BRANCH = 'expand'
DATA_MIGRATION_BRANCH = 'data_migration'
CONTRACT_BRANCH = 'contract'


def _get_migrate_repo_path(branch):
    abs_path = os.path.abspath(
        os.path.join(
            os.path.dirname(sql.__file__),
            'legacy_migrations',
            f'{branch}_repo',
        )
    )

    if not os.path.isdir(abs_path):
        raise exception.MigrationNotProvided(sql.__name__, abs_path)

    return abs_path


def _find_migrate_repo(abs_path):
    """Get the project's change script repository

    :param abs_path: Absolute path to migrate repository
    """
    if not os.path.exists(abs_path):
        raise db_exception.DBMigrationError("Path %s not found" % abs_path)
    return migrate_repository.Repository(abs_path)


def _migrate_db_version_control(engine, abs_path, version=None):
    """Mark a database as under this repository's version control.

    Once a database is under version control, schema changes should
    only be done via change scripts in this repository.

    :param engine: SQLAlchemy engine instance for a given database
    :param abs_path: Absolute path to migrate repository
    :param version: Initial database version
    """
    repository = _find_migrate_repo(abs_path)

    try:
        migrate_api.version_control(engine, repository, version)
    except migrate_exceptions.InvalidVersionError as ex:
        raise db_exception.DBMigrationError("Invalid version : %s" % ex)
    except migrate_exceptions.DatabaseAlreadyControlledError:
        raise db_exception.DBMigrationError("Database is already controlled.")

    return version


def _migrate_db_version(engine, abs_path, init_version):
    """Show the current version of the repository.

    :param engine: SQLAlchemy engine instance for a given database
    :param abs_path: Absolute path to migrate repository
    :param init_version: Initial database version
    """
    repository = _find_migrate_repo(abs_path)
    try:
        return migrate_api.db_version(engine, repository)
    except migrate_exceptions.DatabaseNotControlledError:
        pass

    meta = sa.MetaData()
    meta.reflect(bind=engine)
    tables = meta.tables
    if (
        len(tables) == 0 or
        'alembic_version' in tables or
        'migrate_version' in tables
    ):
        _migrate_db_version_control(engine, abs_path, version=init_version)
        return migrate_api.db_version(engine, repository)

    msg = _(
        "The database is not under version control, but has tables. "
        "Please stamp the current version of the schema manually."
    )
    raise db_exception.DBMigrationError(msg)


def _migrate_db_sync(engine, abs_path, version=None, init_version=0):
    """Upgrade or downgrade a database.

    Function runs the upgrade() or downgrade() functions in change scripts.

    :param engine: SQLAlchemy engine instance for a given database
    :param abs_path: Absolute path to migrate repository.
    :param version: Database will upgrade/downgrade until this version.
        If None - database will update to the latest available version.
    :param init_version: Initial database version
    """

    if version is not None:
        try:
            version = int(version)
        except ValueError:
            msg = _("version should be an integer")
            raise db_exception.DBMigrationError(msg)

    current_version = _migrate_db_version(engine, abs_path, init_version)
    repository = _find_migrate_repo(abs_path)

    if version is None or version > current_version:
        try:
            return migrate_api.upgrade(engine, repository, version)
        except Exception as ex:
            raise db_exception.DBMigrationError(ex)
    else:
        return migrate_api.downgrade(engine, repository, version)


def get_db_version(branch=EXPAND_BRANCH):
    abs_path = _get_migrate_repo_path(branch)
    with sql.session_for_read() as session:
        return _migrate_db_version(
            session.get_bind(),
            abs_path,
            INITIAL_VERSION,
        )


def _db_sync(branch):
    abs_path = _get_migrate_repo_path(branch)
    with sql.session_for_write() as session:
        engine = session.get_bind()
        _migrate_db_sync(
            engine=engine,
            abs_path=abs_path,
            init_version=INITIAL_VERSION,
        )


def _validate_upgrade_order(branch, target_repo_version=None):
    """Validate the state of the migration repositories.

    This is run before allowing the db_sync command to execute. Ensure the
    upgrade step and version specified by the operator remains consistent with
    the upgrade process. I.e. expand's version is greater or equal to
    migrate's, migrate's version is greater or equal to contract's.

    :param branch: The name of the repository that the user is trying to
                      upgrade.
    :param target_repo_version: The version to upgrade the repo. Otherwise, the
                                version will be upgraded to the latest version
                                available.
    """
    # Initialize a dict to have each key assigned a repo with their value being
    # the repo that comes before.
    db_sync_order = {
        DATA_MIGRATION_BRANCH: EXPAND_BRANCH,
        CONTRACT_BRANCH: DATA_MIGRATION_BRANCH,
    }

    if branch == EXPAND_BRANCH:
        return

    # find the latest version that the current command will upgrade to if there
    # wasn't a version specified for upgrade.
    if not target_repo_version:
        abs_path = _get_migrate_repo_path(branch)
        repo = _find_migrate_repo(abs_path)
        target_repo_version = int(repo.latest)

    # get current version of the command that runs before the current command.
    dependency_repo_version = get_db_version(branch=db_sync_order[branch])

    if dependency_repo_version < target_repo_version:
        raise db_exception.DBMigrationError(
            'You are attempting to upgrade %s ahead of %s. Please refer to '
            'https://docs.openstack.org/keystone/latest/admin/'
            'identity-upgrading.html '
            'to see the proper steps for rolling upgrades.' % (
                branch, db_sync_order[branch]))


def expand_schema():
    """Expand the database schema ahead of data migration.

    This is run manually by the keystone-manage command before the first
    keystone node is migrated to the latest release.
    """
    _validate_upgrade_order(EXPAND_BRANCH)
    _db_sync(branch=EXPAND_BRANCH)


def migrate_data():
    """Migrate data to match the new schema.

    This is run manually by the keystone-manage command once the keystone
    schema has been expanded for the new release.
    """
    _validate_upgrade_order(DATA_MIGRATION_BRANCH)
    _db_sync(branch=DATA_MIGRATION_BRANCH)


def contract_schema():
    """Contract the database.

    This is run manually by the keystone-manage command once the keystone
    nodes have been upgraded to the latest release and will remove any old
    tables/columns that are no longer required.
    """
    _validate_upgrade_order(CONTRACT_BRANCH)
    _db_sync(branch=CONTRACT_BRANCH)


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
