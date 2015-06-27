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
import sys

import migrate
from migrate import exceptions
from oslo_config import cfg
from oslo_db.sqlalchemy import migration
from oslo_serialization import jsonutils
from oslo_utils import importutils
import six
import sqlalchemy

from keystone.common import sql
from keystone.common.sql import migrate_repo
from keystone import contrib
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
DEFAULT_EXTENSIONS = ['endpoint_filter',
                      'endpoint_policy',
                      'federation',
                      'oauth1',
                      'revoke',
                      ]


def get_default_domain():
    # Return the reference used for the default domain structure during
    # sql migrations.
    return {
        'id': CONF.identity.default_domain_id,
        'name': 'Default',
        'enabled': True,
        'extra': jsonutils.dumps({'description': 'Owns users and tenants '
                                                 '(i.e. projects) available '
                                                 'on Identity API v2.'})}


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
    """Renames tables with foreign key constraints.

    Tables are renamed after first removing constraints. The constraints are
    replaced after the rename is complete.

    This works on databases that don't support renaming tables that have
    constraints on them (DB2).

    `renames` is a dict, mapping {'to_table_name': from_table, ...}
    """

    if engine.name != 'sqlite':
        # Sqlite doesn't support constraints, so nothing to remove.
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
    init_version = migrate_repo.DB_INIT_VERSION
    engine = sql.get_engine()
    _assert_not_schema_downgrade(version=version)
    migration.db_sync(engine, abs_path, version=version,
                      init_version=init_version, sanity_check=False)


def _assert_not_schema_downgrade(extension=None, version=None):
    if version is not None:
        try:
            current_ver = int(six.text_type(get_db_version(extension)))
            if int(version) < current_ver:
                raise migration.exception.DbMigrationError()
        except exceptions.DatabaseNotControlledError:
            # NOTE(morganfainberg): The database is not controlled, this action
            # cannot be a downgrade.
            pass


def _sync_extension_repo(extension, version):
    init_version = 0
    engine = sql.get_engine()

    try:
        package_name = '.'.join((contrib.__name__, extension))
        package = importutils.import_module(package_name)
    except ImportError:
        raise ImportError(_("%s extension does not exist.")
                          % package_name)
    try:
        abs_path = find_migrate_repo(package)
        try:
            migration.db_version_control(sql.get_engine(), abs_path)
        # Register the repo with the version control API
        # If it already knows about the repo, it will throw
        # an exception that we can safely ignore
        except exceptions.DatabaseAlreadyControlledError:
            pass
    except exception.MigrationNotProvided as e:
        print(e)
        sys.exit(1)

    _assert_not_schema_downgrade(extension=extension, version=version)

    migration.db_sync(engine, abs_path, version=version,
                      init_version=init_version, sanity_check=False)


def sync_database_to_version(extension=None, version=None):
    if not extension:
        _sync_common_repo(version)
        # If version is greater than 0, it is for the common
        # repository only, and only that will be synchronized.
        if version is None:
            for default_extension in DEFAULT_EXTENSIONS:
                _sync_extension_repo(default_extension, version)
    else:
        _sync_extension_repo(extension, version)


def get_db_version(extension=None):
    if not extension:
        return migration.db_version(sql.get_engine(), find_migrate_repo(),
                                    migrate_repo.DB_INIT_VERSION)

    try:
        package_name = '.'.join((contrib.__name__, extension))
        package = importutils.import_module(package_name)
    except ImportError:
        raise ImportError(_("%s extension does not exist.")
                          % package_name)

    return migration.db_version(
        sql.get_engine(), find_migrate_repo(package), 0)


def print_db_version(extension=None):
    try:
        db_version = get_db_version(extension=extension)
        print(db_version)
    except exception.MigrationNotProvided as e:
        print(e)
        sys.exit(1)
