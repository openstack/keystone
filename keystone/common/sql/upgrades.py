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

from alembic import command as alembic_api
from alembic import config as alembic_config
from alembic import migration as alembic_migration
from alembic import script as alembic_script
from oslo_db import exception as db_exception
from oslo_log import log as logging
from oslo_utils import fileutils

from keystone.common import sql
import keystone.conf

CONF = keystone.conf.CONF
LOG = logging.getLogger(__name__)

ALEMBIC_INIT_VERSION = '27e647c0fad4'

EXPAND_BRANCH = 'expand'
DATA_MIGRATION_BRANCH = 'data_migration'
CONTRACT_BRANCH = 'contract'

RELEASES = ('yoga', 'bobcat', '2024.01')
MILESTONES = (
    'yoga',
    # Do not add the milestone until the end of the release
)
CURRENT_RELEASE = RELEASES[-1]
MIGRATION_BRANCHES = (EXPAND_BRANCH, CONTRACT_BRANCH)
VERSIONS_PATH = os.path.join(
    os.path.dirname(sql.__file__), 'migrations', 'versions'
)


def get_version_branch_path(release=None, branch=None):
    """Get the path to a version branch."""
    version_path = VERSIONS_PATH
    if branch and release:
        return os.path.join(version_path, release, branch)
    return version_path


def check_bootstrap_new_branch(branch, version_path, addn_kwargs):
    """Bootstrap a new migration branch if it does not exist."""
    addn_kwargs['version_path'] = version_path
    addn_kwargs['head'] = f'{branch}@head'
    if not os.path.exists(version_path):
        # Bootstrap initial directory structure
        fileutils.ensure_tree(version_path, mode=0o755)


def _find_alembic_conf():
    """Get the project's alembic configuration.

    :returns: An instance of ``alembic.config.Config``
    """
    path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), 'alembic.ini'
    )

    config = alembic_config.Config(os.path.abspath(path))

    config.set_main_option('sqlalchemy.url', CONF.database.connection)

    # we don't want to use the logger configuration from the file, which is
    # only really intended for the CLI
    # https://stackoverflow.com/a/42691781/613428
    config.attributes['configure_logger'] = False

    # we want to scan all the versioned subdirectories
    version_paths = [VERSIONS_PATH]
    for release in RELEASES:
        for branch in MIGRATION_BRANCHES:
            version_path = os.path.join(VERSIONS_PATH, release, branch)
            version_paths.append(version_path)
    config.set_main_option('version_locations', ' '.join(version_paths))

    return config


def get_alembic_config():
    return _find_alembic_conf()


def _get_current_heads(engine, config):
    script = alembic_script.ScriptDirectory.from_config(config)

    with engine.connect() as conn:
        context = alembic_migration.MigrationContext.configure(conn)
        heads = context.get_current_heads()

    heads_map = {}

    for head in heads:
        if CONTRACT_BRANCH in script.get_revision(head).branch_labels:
            heads_map[CONTRACT_BRANCH] = head
        else:
            heads_map[EXPAND_BRANCH] = head

    return heads_map


def get_current_heads():
    """Get the current head of each the expand and contract branches."""
    config = _find_alembic_conf()

    with sql.session_for_read() as session:
        engine = session.get_bind()

    # discard the URL encoded in alembic.ini in favour of the URL
    # configured for the engine by the database fixtures, casting from
    # 'sqlalchemy.engine.url.URL' to str in the process. This returns a
    # RFC-1738 quoted URL, which means that a password like "foo@" will be
    # turned into "foo%40". This in turns causes a problem for
    # set_main_option() because that uses ConfigParser.set, which (by
    # design) uses *python* interpolation to write the string out ... where
    # "%" is the special python interpolation character! Avoid this
    # mismatch by quoting all %'s for the set below.
    engine_url = engine.url.render_as_string(hide_password=False).replace(
        '%', '%%'
    )
    config.set_main_option('sqlalchemy.url', engine_url)

    heads = _get_current_heads(engine, config)

    return heads


def _is_database_under_alembic_control(engine):
    with engine.connect() as conn:
        context = alembic_migration.MigrationContext.configure(conn)
        return bool(context.get_current_heads())


def _upgrade_alembic(engine, config, branch):
    revision = 'heads'
    if branch:
        revision = f'{branch}@head'

    # re-use the connection rather than creating a new one
    with engine.begin() as connection:
        config.attributes['connection'] = connection
        alembic_api.upgrade(config, revision)


def get_db_version(branch=EXPAND_BRANCH, *, engine=None):
    config = _find_alembic_conf()

    if engine is None:
        with sql.session_for_read() as session:
            engine = session.get_bind()

    # discard the URL encoded in alembic.ini in favour of the URL
    # configured for the engine by the database fixtures, casting from
    # 'sqlalchemy.engine.url.URL' to str in the process. This returns a
    # RFC-1738 quoted URL, which means that a password like "foo@" will be
    # turned into "foo%40". This in turns causes a problem for
    # set_main_option() because that uses ConfigParser.set, which (by
    # design) uses *python* interpolation to write the string out ... where
    # "%" is the special python interpolation character! Avoid this
    # mismatch by quoting all %'s for the set below.
    engine_url = engine.url.render_as_string(hide_password=False).replace(
        '%', '%%'
    )
    config.set_main_option('sqlalchemy.url', engine_url)

    # we use '.get' since the particular branch might not have been created
    alembic_version = _get_current_heads(engine, config).get(branch)

    return alembic_version


def _db_sync(branch=None, *, engine=None):
    config = _find_alembic_conf()

    if engine is None:
        with sql.session_for_write() as session:
            engine = session.get_bind()

    # discard the URL encoded in alembic.ini in favour of the URL
    # configured for the engine by the database fixtures, casting from
    # 'sqlalchemy.engine.url.URL' to str in the process. This returns a
    # RFC-1738 quoted URL, which means that a password like "foo@" will be
    # turned into "foo%40". This in turns causes a problem for
    # set_main_option() because that uses ConfigParser.set, which (by
    # design) uses *python* interpolation to write the string out ... where
    # "%" is the special python interpolation character! Avoid this
    # mismatch by quoting all %'s for the set below.
    engine_url = engine.url.render_as_string(hide_password=False).replace(
        '%', '%%'
    )
    config.set_main_option('sqlalchemy.url', engine_url)

    _upgrade_alembic(engine, config, branch)


def _validate_upgrade_order(branch, *, engine=None):
    """Validate the upgrade order of the migration branches.

    This is run before allowing the db_sync command to execute. Ensure the
    expand steps have been run before the contract steps.

    :param branch: The name of the branch that the user is trying to
        upgrade.
    """
    if branch == EXPAND_BRANCH:
        return

    if branch == DATA_MIGRATION_BRANCH:
        # this is a no-op in alembic land
        return

    config = _find_alembic_conf()

    if engine is None:
        with sql.session_for_read() as session:
            engine = session.get_bind()

    script = alembic_script.ScriptDirectory.from_config(config)
    expand_head = None
    for head in script.get_heads():
        if EXPAND_BRANCH in script.get_revision(head).branch_labels:
            expand_head = head
            break

    with engine.connect() as conn:
        context = alembic_migration.MigrationContext.configure(conn)
        current_heads = context.get_current_heads()

    if expand_head not in current_heads:
        raise db_exception.DBMigrationError(
            'You are attempting to upgrade contract ahead of expand. '
            'Please refer to '
            'https://docs.openstack.org/keystone/latest/admin/'
            'identity-upgrading.html '
            'to see the proper steps for rolling upgrades.'
        )


def expand_schema(engine=None):
    """Expand the database schema ahead of data migration.

    This is run manually by the keystone-manage command before the first
    keystone node is migrated to the latest release.
    """
    _validate_upgrade_order(EXPAND_BRANCH, engine=engine)
    _db_sync(EXPAND_BRANCH, engine=engine)


def migrate_data(engine=None):
    """Migrate data to match the new schema.

    This is run manually by the keystone-manage command once the keystone
    schema has been expanded for the new release.
    """
    print(
        'Data migrations are no longer supported with alembic. '
        'This is now a no-op.'
    )


def contract_schema(engine=None):
    """Contract the database.

    This is run manually by the keystone-manage command once the keystone
    nodes have been upgraded to the latest release and will remove any old
    tables/columns that are no longer required.
    """
    _validate_upgrade_order(CONTRACT_BRANCH, engine=engine)
    _db_sync(CONTRACT_BRANCH, engine=engine)


def offline_sync_database_to_version(version=None, *, engine=None):
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

    _db_sync(engine=engine)
