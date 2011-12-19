# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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

import logging
import os

from migrate.versioning import api as versioning_api
# See LP bug #719834. sqlalchemy-migrate changed location of
# exceptions.py after 0.6.0.
try:
    from migrate.versioning import exceptions as versioning_exceptions
except ImportError:
    from migrate import exceptions as versioning_exceptions

from keystone.logic.types import fault


logger = logging.getLogger(__name__)


def get_migrate_repo_path():
    """Get the path for the migrate repository."""
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'migrate_repo')
    assert os.path.exists(path)
    return path


def get_migrate_repo(repo_path):
    return versioning_api.repository.Repository(repo_path)


def get_schema(engine, repo_path):
    return versioning_api.schema.ControlledSchema(engine, repo_path)


def get_repo_version(repo_path):
    return get_migrate_repo(repo_path).latest


def get_db_version(engine, repo_path):
    return get_schema(engine, repo_path).version


def db_goto_version(options, version):
    """
    Jump to a specific database version without performing migrations.

    :param options: options dict
    :param version: version to jump to
    """

    @versioning_api.with_engine
    def set_db_version(url, repository, old_v, new_v, **opts):
        engine = opts.pop('engine')
        schema = get_schema(engine, repo_path)
        schema.update_repository_table(old_v, new_v)
        return True

    repo_path = get_migrate_repo_path()
    sql_connection = options['sql_connection']
    new_version = int(version)
    try:
        old_version = versioning_api.db_version(sql_connection, repo_path)
        if new_version != old_version:
            return set_db_version(sql_connection, repo_path, old_version,
                new_version)
    except versioning_exceptions.DatabaseNotControlledError:
        msg = (_("database '%(sql_connection)s' is not under "
                 "migration control") % locals())
        raise fault.DatabaseMigrationError(msg)


def db_version(options):
    """
    Return the database's current migration number

    :param options: options dict
    :retval version number
    """
    repo_path = get_migrate_repo_path()
    sql_connection = options['sql_connection']
    try:
        return versioning_api.db_version(sql_connection, repo_path)
    except versioning_exceptions.DatabaseNotControlledError:
        msg = (_("database '%(sql_connection)s' is not under "
                 "migration control") % locals())
        raise fault.DatabaseMigrationError(msg)


def upgrade(options, version=None):
    """
    Upgrade the database's current migration level

    :param options: options dict
    :param version: version to upgrade (defaults to latest)
    :retval version number
    """
    db_version(options)  # Ensure db is under migration control
    repo_path = get_migrate_repo_path()
    sql_connection = options['sql_connection']
    version_str = version or 'latest'
    logger.info(_("Upgrading %(sql_connection)s to version %(version_str)s") %
                locals())
    return versioning_api.upgrade(sql_connection, repo_path, version)


def downgrade(options, version):
    """
    Downgrade the database's current migration level

    :param options: options dict
    :param version: version to downgrade to
    :retval version number
    """
    db_version(options)  # Ensure db is under migration control
    repo_path = get_migrate_repo_path()
    sql_connection = options['sql_connection']
    logger.info(_("Downgrading %(sql_connection)s to version %(version)s") %
                locals())
    return versioning_api.downgrade(sql_connection, repo_path, version)


def version_control(options):
    """
    Place a database under migration control

    :param options: options dict
    """
    sql_connection = options['sql_connection']
    try:
        _version_control(options)
    except versioning_exceptions.DatabaseAlreadyControlledError:
        msg = (_("database '%(sql_connection)s' is already under migration "
               "control") % locals())
        raise fault.DatabaseMigrationError(msg)


def _version_control(options):
    """
    Place a database under migration control

    :param options: options dict
    """
    repo_path = get_migrate_repo_path()
    sql_connection = options['sql_connection']
    return versioning_api.version_control(sql_connection, repo_path)


def db_sync(options, version=None):
    """
    Place a database under migration control and perform an upgrade

    :param options: options dict
    :retval version number
    """
    try:
        _version_control(options)
    except versioning_exceptions.DatabaseAlreadyControlledError, e:
        pass

    upgrade(options, version=version)
