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
from migrate import exceptions
from oslo_db.sqlalchemy import migration
import six
import sqlalchemy

from keystone.common import sql
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF


#  Different RDBMSs use different schemes for naming the Foreign Key
#  Constraints.  SQLAlchemy does not yet attempt to determine the name
#  for the constraint, and instead attempts to deduce it from the column.
#  This fails on MySQL.
def get_constraints_names(table, column_name):
    fkeys = [fk.name for fk in table.constraints
             if (isinstance(fk, sqlalchemy.ForeignKeyConstraint) and
                 column_name in fk.columns)]
    return fkeys


#  remove_constraints and add_constraints both accept a list of dictionaries
#  that contain:
#  {'table': a sqlalchemy table. The constraint is added to dropped from
#           this table.
#  'fk_column': the name of a column on the above table,  The constraint
#               is added to or dropped from this column
#  'ref_column':a sqlalchemy column object.  This is the reference column
#               for the constraint.
def remove_constraints(constraints):
    for constraint_def in constraints:
        constraint_names = get_constraints_names(constraint_def['table'],
                                                 constraint_def['fk_column'])
        for constraint_name in constraint_names:
            migrate.ForeignKeyConstraint(
                columns=[getattr(constraint_def['table'].c,
                                 constraint_def['fk_column'])],
                refcolumns=[constraint_def['ref_column']],
                name=constraint_name).drop()


def add_constraints(constraints):
    for constraint_def in constraints:

        if constraint_def['table'].kwargs.get('mysql_engine') == 'MyISAM':
            # Don't try to create constraint when using MyISAM because it's
            # not supported.
            continue

        ref_col = constraint_def['ref_column']
        ref_engine = ref_col.table.kwargs.get('mysql_engine')
        if ref_engine == 'MyISAM':
            # Don't try to create constraint when using MyISAM because it's
            # not supported.
            continue

        migrate.ForeignKeyConstraint(
            columns=[getattr(constraint_def['table'].c,
                             constraint_def['fk_column'])],
            refcolumns=[constraint_def['ref_column']]).create()


def rename_tables_with_constraints(renames, constraints, engine):
    """Rename tables with foreign key constraints.

    Tables are renamed after first removing constraints. The constraints are
    replaced after the rename is complete.

    This works on databases that don't support renaming tables that have
    constraints on them (DB2).

    `renames` is a dict, mapping {'to_table_name': from_table, ...}
    """
    if engine.name != 'sqlite':
        # SQLite doesn't support constraints, so nothing to remove.
        remove_constraints(constraints)

    for to_table_name in renames:
        from_table = renames[to_table_name]
        from_table.rename(to_table_name)

    if engine != 'sqlite':
        add_constraints(constraints)


def find_migrate_repo(package=None, repo_name='migrate_repo'):
    package = package or sql
    path = os.path.abspath(os.path.join(
        os.path.dirname(package.__file__), repo_name))
    if os.path.isdir(path):
        return path
    raise exception.MigrationNotProvided(package.__name__, path)


def _sync_common_repo(version):
    abs_path = find_migrate_repo()
    init_version = get_init_version()
    with sql.session_for_write() as session:
        engine = session.get_bind()
        _assert_not_schema_downgrade(version=version)
        migration.db_sync(engine, abs_path, version=version,
                          init_version=init_version, sanity_check=False)


def _sync_repo(repo_name):
    abs_path = find_migrate_repo(repo_name=repo_name)
    with sql.session_for_write() as session:
        engine = session.get_bind()
        # Register the repo with the version control API
        # If it already knows about the repo, it will throw
        # an exception that we can safely ignore
        try:
            migration.db_version_control(engine, abs_path)
        except (migration.exception.DbMigrationError,
                exceptions.DatabaseAlreadyControlledError):  # nosec
            pass
        init_version = get_init_version(abs_path=abs_path)
        migration.db_sync(engine, abs_path,
                          init_version=init_version, sanity_check=False)


def get_init_version(abs_path=None):
    """Get the initial version of a migrate repository.

    :param abs_path: Absolute path to migrate repository.
    :return:         initial version number or None, if DB is empty.
    """
    if abs_path is None:
        abs_path = find_migrate_repo()

    repo = migrate.versioning.repository.Repository(abs_path)

    # Sadly, Repository has a `latest` but not an `oldest`.
    # The value is a VerNum object which needs to be converted into an int.
    oldest = int(min(repo.versions.versions))

    if oldest < 1:
        return None

    # The initial version is one less
    return oldest - 1


def _assert_not_schema_downgrade(version=None):
    if version is not None:
        try:
            current_ver = int(six.text_type(get_db_version()))
            if int(version) < current_ver:
                raise migration.exception.DbMigrationError(
                    _("Unable to downgrade schema"))
        except exceptions.DatabaseNotControlledError:  # nosec
            # NOTE(morganfainberg): The database is not controlled, this action
            # cannot be a downgrade.
            pass


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
        _sync_common_repo(version)
    else:
        expand_schema()
        migrate_data()
        contract_schema()


def get_db_version():
    with sql.session_for_write() as session:
        return migration.db_version(session.get_bind(),
                                    find_migrate_repo(),
                                    get_init_version())


def print_db_version():
    print(get_db_version())


def expand_schema():
    """Expand the database schema ahead of data migration.

    This is run manually by the keystone-manage command before the first
    keystone node is migrated to the latest release.

    """
    # Make sure all the legacy migrations are run before we run any new
    # expand migrations.
    _sync_common_repo(version=None)
    _sync_repo(repo_name='expand_repo')


def migrate_data():
    """Migrate data to match the new schema.

    This is run manually by the keystone-manage command once the keystone
    schema has been expanded for the new release.

    """
    _sync_repo(repo_name='data_migration_repo')


def contract_schema():
    """Contract the database.

    This is run manually by the keystone-manage command once the keystone
    nodes have been upgraded to the latest release and will remove any old
    tables/columns that are no longer required.

    """
    _sync_repo(repo_name='contract_repo')
