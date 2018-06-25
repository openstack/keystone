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
"""
Test for SQL migration extensions.

To run these tests against a live database:

1. Set up a blank, live database.
2. Export database information to environment variable
   ``OS_TEST_DBAPI_ADMIN_CONNECTION``. For example::

    export OS_TEST_DBAPI_ADMIN_CONNECTION=postgresql://localhost/postgres?host=
    /var/folders/7k/pwdhb_mj2cv4zyr0kyrlzjx40000gq/T/tmpMGqN8C&port=9824

3. Run the tests using::

    tox -e py27 -- keystone.tests.unit.test_sql_upgrade

For further information, see `oslo.db documentation
<https://docs.openstack.org/oslo.db/latest/contributor/index.html#how-to-run-unit-tests>`_.

WARNING::

    Your database will be wiped.

    Do not do this against a database with valuable data as
    all data will be lost.
"""

import datetime
import json
import os
import uuid

import fixtures
import migrate
from migrate.versioning import repository
from migrate.versioning import script
import mock
from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
from oslo_log import log
from oslotest import base as test_base
import pytz
from sqlalchemy.engine import reflection
import sqlalchemy.exc
from testtools import matchers

from keystone.cmd import cli
from keystone.common import sql
from keystone.common.sql import upgrades
from keystone.credential.providers import fernet as credential_fernet
from keystone.resource.backends import base as resource_base
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database


# NOTE(morganfainberg): This should be updated when each DB migration collapse
# is done to mirror the expected structure of the DB in the format of
# { <DB_TABLE_NAME>: [<COLUMN>, <COLUMN>, ...], ... }
INITIAL_TABLE_STRUCTURE = {
    'credential': [
        'id', 'user_id', 'project_id', 'blob', 'type', 'extra',
    ],
    'domain': [
        'id', 'name', 'enabled', 'extra',
    ],
    'endpoint': [
        'id', 'legacy_endpoint_id', 'interface', 'region_id', 'service_id',
        'url', 'enabled', 'extra',
    ],
    'group': [
        'id', 'domain_id', 'name', 'description', 'extra',
    ],
    'policy': [
        'id', 'type', 'blob', 'extra',
    ],
    'project': [
        'id', 'name', 'extra', 'description', 'enabled', 'domain_id',
        'parent_id',
    ],
    'role': [
        'id', 'name', 'extra',
    ],
    'service': [
        'id', 'type', 'extra', 'enabled',
    ],
    'token': [
        'id', 'expires', 'extra', 'valid', 'trust_id', 'user_id',
    ],
    'trust': [
        'id', 'trustor_user_id', 'trustee_user_id', 'project_id',
        'impersonation', 'deleted_at', 'expires_at', 'remaining_uses', 'extra',
    ],
    'trust_role': [
        'trust_id', 'role_id',
    ],
    'user': [
        'id', 'name', 'extra', 'password', 'enabled', 'domain_id',
        'default_project_id',
    ],
    'user_group_membership': [
        'user_id', 'group_id',
    ],
    'region': [
        'id', 'description', 'parent_region_id', 'extra',
    ],
    'assignment': [
        'type', 'actor_id', 'target_id', 'role_id', 'inherited',
    ],
    'id_mapping': [
        'public_id', 'domain_id', 'local_id', 'entity_type',
    ],
    'whitelisted_config': [
        'domain_id', 'group', 'option', 'value',
    ],
    'sensitive_config': [
        'domain_id', 'group', 'option', 'value',
    ],
}

LEGACY_REPO = 'migrate_repo'
EXPAND_REPO = 'expand_repo'
DATA_MIGRATION_REPO = 'data_migration_repo'
CONTRACT_REPO = 'contract_repo'


# Test upgrades.get_init_version separately to ensure it works before
# using in the SqlUpgrade tests.
class SqlUpgradeGetInitVersionTests(unit.TestCase):
    @mock.patch.object(repository, 'Repository')
    def test_get_init_version_no_path(self, repo):
        migrate_versions = mock.MagicMock()
        # make a version list starting with zero. `get_init_version` will
        # return None for this value.
        migrate_versions.versions.versions = list(range(0, 5))
        repo.return_value = migrate_versions

        # os.path.isdir() is called by `find_repo()`. Mock it to avoid
        # an exception.
        with mock.patch('os.path.isdir', return_value=True):
            # since 0 is the smallest version expect None
            version = upgrades.get_init_version()
            self.assertIsNone(version)

        # check that the default path was used as the first argument to the
        # first invocation of repo. Cannot match the full path because it is
        # based on where the test is run.
        param = repo.call_args_list[0][0][0]
        self.assertTrue(param.endswith('/sql/' + LEGACY_REPO))

    @mock.patch.object(repository, 'Repository')
    def test_get_init_version_with_path_initial_version_0(self, repo):
        migrate_versions = mock.MagicMock()
        # make a version list starting with zero. `get_init_version` will
        # return None for this value.
        migrate_versions.versions.versions = list(range(0, 5))
        repo.return_value = migrate_versions

        # os.path.isdir() is called by `find_repo()`. Mock it to avoid
        # an exception.
        with mock.patch('os.path.isdir', return_value=True):
            path = '/keystone/' + LEGACY_REPO + '/'

            # since 0 is the smallest version expect None
            version = upgrades.get_init_version(abs_path=path)
            self.assertIsNone(version)

    @mock.patch.object(repository, 'Repository')
    def test_get_init_version_with_path(self, repo):
        initial_version = 10

        migrate_versions = mock.MagicMock()
        migrate_versions.versions.versions = list(range(initial_version + 1,
                                                        initial_version + 5))
        repo.return_value = migrate_versions

        # os.path.isdir() is called by `find_repo()`. Mock it to avoid
        # an exception.
        with mock.patch('os.path.isdir', return_value=True):
            path = '/keystone/' + LEGACY_REPO + '/'

            version = upgrades.get_init_version(abs_path=path)
            self.assertEqual(initial_version, version)


class SqlMigrateBase(db_fixtures.OpportunisticDBTestMixin,
                     test_base.BaseTestCase):
    def setUp(self):
        super(SqlMigrateBase, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()

        # NOTE(dstanek): Clear out sqlalchemy-migrate's script cache to allow
        # us to have multiple repos (expand, migrate, contract) where the
        # modules have the same name (001_awesome.py).
        self.addCleanup(script.PythonScript.clear)

        # NOTE(dstanek): SQLAlchemy's migrate makes some assumptions in the
        # SQLite driver about the lack of foreign key enforcement.
        database.initialize_sql_session(self.engine.url,
                                        enforce_sqlite_fks=False)

        # Override keystone's context manager to be oslo.db's global context
        # manager.
        sql.core._TESTING_USE_GLOBAL_CONTEXT_MANAGER = True
        self.addCleanup(setattr,
                        sql.core, '_TESTING_USE_GLOBAL_CONTEXT_MANAGER', False)
        self.addCleanup(sql.cleanup)

        self.repos = {
            LEGACY_REPO: upgrades.Repository(self.engine, LEGACY_REPO),
            EXPAND_REPO: upgrades.Repository(self.engine, EXPAND_REPO),
            DATA_MIGRATION_REPO: upgrades.Repository(
                self.engine, DATA_MIGRATION_REPO),
            CONTRACT_REPO: upgrades.Repository(self.engine, CONTRACT_REPO)}

    def upgrade(self, *args, **kwargs):
        """Upgrade the legacy migration repository."""
        self.repos[LEGACY_REPO].upgrade(*args, **kwargs)

    def expand(self, *args, **kwargs):
        """Expand database schema."""
        self.repos[EXPAND_REPO].upgrade(*args, **kwargs)

    def migrate(self, *args, **kwargs):
        """Migrate data."""
        self.repos[DATA_MIGRATION_REPO].upgrade(*args, **kwargs)

    def contract(self, *args, **kwargs):
        """Contract database schema."""
        self.repos[CONTRACT_REPO].upgrade(*args, **kwargs)

    @property
    def metadata(self):
        """A collection of tables and their associated schemas."""
        return sqlalchemy.MetaData(self.engine)

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertTableExists(self, table_name):
        try:
            self.select_table(table_name)
        except sqlalchemy.exc.NoSuchTableError:
            raise AssertionError('Table "%s" does not exist' % table_name)

    def assertTableDoesNotExist(self, table_name):
        """Assert that a given table exists cannot be selected by name."""
        # Switch to a different metadata otherwise you might still
        # detect renamed or dropped tables
        try:
            sqlalchemy.Table(table_name, self.metadata, autoload=True)
        except sqlalchemy.exc.NoSuchTableError:
            pass
        else:
            raise AssertionError('Table "%s" already exists' % table_name)

    def calc_table_row_count(self, table_name):
        """Return the number of rows in the table."""
        t = sqlalchemy.Table(table_name, self.metadata, autoload=True)
        session = self.sessionmaker()
        row_count = session.query(
            sqlalchemy.func.count('*')).select_from(t).scalar()
        return row_count

    def assertTableCountsMatch(self, table1_name, table2_name):
        table1_count = self.calc_table_row_count(table1_name)
        table2_count = self.calc_table_row_count(table2_name)
        if table1_count != table2_count:
            raise AssertionError('Table counts do not match: {0} ({1}), {2} '
                                 '({3})'.format(table1_name, table1_count,
                                                table2_name, table2_count))

    def assertTableColumns(self, table_name, expected_cols):
        """Assert that the table contains the expected set of columns."""
        table = self.select_table(table_name)
        actual_cols = [col.name for col in table.columns]
        # Check if the columns are equal, but allow for a different order,
        # which might occur after an upgrade followed by a downgrade
        self.assertItemsEqual(expected_cols, actual_cols,
                              '%s table' % table_name)

    def insert_dict(self, session, table_name, d, table=None):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        if table is None:
            this_table = sqlalchemy.Table(table_name, self.metadata,
                                          autoload=True)
        else:
            this_table = table
        insert = this_table.insert().values(**d)
        session.execute(insert)

    def does_pk_exist(self, table, pk_column):
        """Check whether a column is primary key on a table."""
        inspector = reflection.Inspector.from_engine(self.engine)
        pk_columns = inspector.get_pk_constraint(table)['constrained_columns']

        return pk_column in pk_columns

    def does_fk_exist(self, table, fk_column):
        inspector = reflection.Inspector.from_engine(self.engine)
        for fk in inspector.get_foreign_keys(table):
            if fk_column in fk['constrained_columns']:
                return True
        return False

    def does_constraint_exist(self, table_name, constraint_name):
        table = sqlalchemy.Table(table_name, self.metadata, autoload=True)
        return constraint_name in [con.name for con in table.constraints]

    def does_index_exist(self, table_name, index_name):
        table = sqlalchemy.Table(table_name, self.metadata, autoload=True)
        return index_name in [idx.name for idx in table.indexes]

    def does_unique_constraint_exist(self, table_name, column_name):
        inspector = reflection.Inspector.from_engine(self.engine)
        constraints = inspector.get_unique_constraints(table_name)
        for c in constraints:
            if (len(c['column_names']) == 1 and
                    column_name in c['column_names']):
                return True
        return False


class SqlLegacyRepoUpgradeTests(SqlMigrateBase):
    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[LEGACY_REPO].min_version,
            self.repos[LEGACY_REPO].version,
            'DB is not at version %s' % (
                self.repos[LEGACY_REPO].min_version)
        )

    def test_upgrade_add_initial_tables(self):
        self.upgrade(self.repos[LEGACY_REPO].min_version + 1)
        self.check_initial_table_structure()

    def check_initial_table_structure(self):
        for table in INITIAL_TABLE_STRUCTURE:
            self.assertTableColumns(table, INITIAL_TABLE_STRUCTURE[table])

    def test_kilo_squash(self):
        self.upgrade(67)

        # In 053 the size of ID and parent region ID columns were changed
        table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(255, table.c.id.type.length)
        self.assertEqual(255, table.c.parent_region_id.type.length)
        table = sqlalchemy.Table('endpoint', self.metadata, autoload=True)
        self.assertEqual(255, table.c.region_id.type.length)

        # In 054 an index was created for the actor_id of the assignment table
        table = sqlalchemy.Table('assignment', self.metadata, autoload=True)
        index_data = [(idx.name, list(idx.columns.keys()))
                      for idx in table.indexes]
        self.assertIn(('ix_actor_id', ['actor_id']), index_data)

        # In 055 indexes were created for user and trust IDs in the token table
        table = sqlalchemy.Table('token', self.metadata, autoload=True)
        index_data = [(idx.name, list(idx.columns.keys()))
                      for idx in table.indexes]
        self.assertIn(('ix_token_user_id', ['user_id']), index_data)
        self.assertIn(('ix_token_trust_id', ['trust_id']), index_data)

        # In 062 the role ID foreign key was removed from the assignment table
        if self.engine.name == "mysql":
            self.assertFalse(self.does_fk_exist('assignment', 'role_id'))

        # In 064 the domain ID FK was removed from the group and user tables
        if self.engine.name != 'sqlite':
            # sqlite does not support FK deletions (or enforcement)
            self.assertFalse(self.does_fk_exist('group', 'domain_id'))
            self.assertFalse(self.does_fk_exist('user', 'domain_id'))

        # In 067 the role ID index was removed from the assignment table
        if self.engine.name == "mysql":
            self.assertFalse(self.does_index_exist('assignment',
                                                   'assignment_role_id_fkey'))

    def test_insert_assignment_inherited_pk(self):
        ASSIGNMENT_TABLE_NAME = 'assignment'
        INHERITED_COLUMN_NAME = 'inherited'
        ROLE_TABLE_NAME = 'role'

        self.upgrade(72)

        # Check that the 'inherited' column is not part of the PK
        self.assertFalse(self.does_pk_exist(ASSIGNMENT_TABLE_NAME,
                                            INHERITED_COLUMN_NAME))

        session = self.sessionmaker()

        role = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
        self.insert_dict(session, ROLE_TABLE_NAME, role)

        # Create both inherited and noninherited role assignments
        inherited = {'type': 'UserProject',
                     'actor_id': uuid.uuid4().hex,
                     'target_id': uuid.uuid4().hex,
                     'role_id': role['id'],
                     'inherited': True}

        noninherited = inherited.copy()
        noninherited['inherited'] = False

        # Create another inherited role assignment as a spoiler
        spoiler = inherited.copy()
        spoiler['actor_id'] = uuid.uuid4().hex

        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, inherited)
        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, spoiler)

        # Since 'inherited' is not part of the PK, we can't insert noninherited
        self.assertRaises(db_exception.DBDuplicateEntry,
                          self.insert_dict,
                          session,
                          ASSIGNMENT_TABLE_NAME,
                          noninherited)

        session.close()

        self.upgrade(73)

        session = self.sessionmaker()

        # Check that the 'inherited' column is now part of the PK
        self.assertTrue(self.does_pk_exist(ASSIGNMENT_TABLE_NAME,
                                           INHERITED_COLUMN_NAME))

        # The noninherited role assignment can now be inserted
        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, noninherited)

        assignment_table = sqlalchemy.Table(ASSIGNMENT_TABLE_NAME,
                                            self.metadata,
                                            autoload=True)

        assignments = session.query(assignment_table).all()
        for assignment in (inherited, spoiler, noninherited):
            self.assertIn((assignment['type'], assignment['actor_id'],
                           assignment['target_id'], assignment['role_id'],
                           assignment['inherited']),
                          assignments)

    def test_endpoint_policy_upgrade(self):
        self.assertTableDoesNotExist('policy_association')
        self.upgrade(81)
        self.assertTableColumns('policy_association',
                                ['id', 'policy_id', 'endpoint_id',
                                 'service_id', 'region_id'])

    @mock.patch.object(upgrades, 'get_db_version', return_value=1)
    def test_endpoint_policy_already_migrated(self, mock_ep):

        # By setting the return value to 1, the migration has already been
        # run, and there's no need to create the table again

        self.upgrade(81)

        mock_ep.assert_called_once_with(extension='endpoint_policy',
                                        engine=mock.ANY)

        # It won't exist because we are mocking it, but we can verify
        # that 081 did not create the table
        self.assertTableDoesNotExist('policy_association')

    def test_create_federation_tables(self):
        self.identity_provider = 'identity_provider'
        self.federation_protocol = 'federation_protocol'
        self.service_provider = 'service_provider'
        self.mapping = 'mapping'
        self.remote_ids = 'idp_remote_ids'

        self.assertTableDoesNotExist(self.identity_provider)
        self.assertTableDoesNotExist(self.federation_protocol)
        self.assertTableDoesNotExist(self.service_provider)
        self.assertTableDoesNotExist(self.mapping)
        self.assertTableDoesNotExist(self.remote_ids)

        self.upgrade(82)
        self.assertTableColumns(self.identity_provider,
                                ['id', 'description', 'enabled'])

        self.assertTableColumns(self.federation_protocol,
                                ['id', 'idp_id', 'mapping_id'])

        self.assertTableColumns(self.mapping,
                                ['id', 'rules'])

        self.assertTableColumns(self.service_provider,
                                ['id', 'description', 'enabled', 'auth_url',
                                 'relay_state_prefix', 'sp_url'])

        self.assertTableColumns(self.remote_ids, ['idp_id', 'remote_id'])

        federation_protocol = sqlalchemy.Table(self.federation_protocol,
                                               self.metadata,
                                               autoload=True)
        self.assertFalse(federation_protocol.c.mapping_id.nullable)

        sp_table = sqlalchemy.Table(self.service_provider,
                                    self.metadata,
                                    autoload=True)
        self.assertFalse(sp_table.c.auth_url.nullable)
        self.assertFalse(sp_table.c.sp_url.nullable)

    @mock.patch.object(upgrades, 'get_db_version', return_value=8)
    def test_federation_already_migrated(self, mock_federation):

        # By setting the return value to 8, the migration has already been
        # run, and there's no need to create the table again.
        self.upgrade(82)

        mock_federation.assert_any_call(extension='federation',
                                        engine=mock.ANY)

        # It won't exist because we are mocking it, but we can verify
        # that 082 did not create the table.
        self.assertTableDoesNotExist('identity_provider')
        self.assertTableDoesNotExist('federation_protocol')
        self.assertTableDoesNotExist('mapping')
        self.assertTableDoesNotExist('service_provider')
        self.assertTableDoesNotExist('idp_remote_ids')

    def test_create_oauth_tables(self):
        consumer = 'consumer'
        request_token = 'request_token'
        access_token = 'access_token'
        self.assertTableDoesNotExist(consumer)
        self.assertTableDoesNotExist(request_token)
        self.assertTableDoesNotExist(access_token)
        self.upgrade(83)
        self.assertTableColumns(consumer,
                                ['id',
                                 'description',
                                 'secret',
                                 'extra'])
        self.assertTableColumns(request_token,
                                ['id',
                                 'request_secret',
                                 'verifier',
                                 'authorizing_user_id',
                                 'requested_project_id',
                                 'role_ids',
                                 'consumer_id',
                                 'expires_at'])
        self.assertTableColumns(access_token,
                                ['id',
                                 'access_secret',
                                 'authorizing_user_id',
                                 'project_id',
                                 'role_ids',
                                 'consumer_id',
                                 'expires_at'])

    @mock.patch.object(upgrades, 'get_db_version', return_value=5)
    def test_oauth1_already_migrated(self, mock_oauth1):

        # By setting the return value to 5, the migration has already been
        # run, and there's no need to create the table again.
        self.upgrade(83)

        mock_oauth1.assert_any_call(extension='oauth1', engine=mock.ANY)

        # It won't exist because we are mocking it, but we can verify
        # that 083 did not create the table.
        self.assertTableDoesNotExist('consumer')
        self.assertTableDoesNotExist('request_token')
        self.assertTableDoesNotExist('access_token')

    def test_create_revoke_table(self):
        self.assertTableDoesNotExist('revocation_event')
        self.upgrade(84)
        self.assertTableColumns('revocation_event',
                                ['id', 'domain_id', 'project_id', 'user_id',
                                 'role_id', 'trust_id', 'consumer_id',
                                 'access_token_id', 'issued_before',
                                 'expires_at', 'revoked_at',
                                 'audit_chain_id', 'audit_id'])

    @mock.patch.object(upgrades, 'get_db_version', return_value=2)
    def test_revoke_already_migrated(self, mock_revoke):

        # By setting the return value to 2, the migration has already been
        # run, and there's no need to create the table again.
        self.upgrade(84)

        mock_revoke.assert_any_call(extension='revoke', engine=mock.ANY)

        # It won't exist because we are mocking it, but we can verify
        # that 084 did not create the table.
        self.assertTableDoesNotExist('revocation_event')

    def test_project_is_domain_upgrade(self):
        self.upgrade(74)
        self.assertTableColumns('project',
                                ['id', 'name', 'extra', 'description',
                                 'enabled', 'domain_id', 'parent_id',
                                 'is_domain'])

    def test_implied_roles_upgrade(self):
        self.upgrade(87)
        self.assertTableColumns('implied_role',
                                ['prior_role_id', 'implied_role_id'])
        self.assertTrue(self.does_fk_exist('implied_role', 'prior_role_id'))
        self.assertTrue(self.does_fk_exist('implied_role', 'implied_role_id'))

    def test_add_config_registration(self):
        config_registration = 'config_register'
        self.upgrade(74)
        self.assertTableDoesNotExist(config_registration)
        self.upgrade(75)
        self.assertTableColumns(config_registration, ['type', 'domain_id'])

    def test_endpoint_filter_upgrade(self):
        def assert_tables_columns_exist():
            self.assertTableColumns('project_endpoint',
                                    ['endpoint_id', 'project_id'])
            self.assertTableColumns('endpoint_group',
                                    ['id', 'name', 'description', 'filters'])
            self.assertTableColumns('project_endpoint_group',
                                    ['endpoint_group_id', 'project_id'])

        self.assertTableDoesNotExist('project_endpoint')
        self.upgrade(85)
        assert_tables_columns_exist()

    @mock.patch.object(upgrades, 'get_db_version', return_value=2)
    def test_endpoint_filter_already_migrated(self, mock_endpoint_filter):

        # By setting the return value to 2, the migration has already been
        # run, and there's no need to create the table again.
        self.upgrade(85)

        mock_endpoint_filter.assert_any_call(extension='endpoint_filter',
                                             engine=mock.ANY)

        # It won't exist because we are mocking it, but we can verify
        # that 085 did not create the table.
        self.assertTableDoesNotExist('project_endpoint')
        self.assertTableDoesNotExist('endpoint_group')
        self.assertTableDoesNotExist('project_endpoint_group')

    def test_add_trust_unique_constraint_upgrade(self):
        self.upgrade(86)
        inspector = reflection.Inspector.from_engine(self.engine)
        constraints = inspector.get_unique_constraints('trust')
        constraint_names = [constraint['name'] for constraint in constraints]
        self.assertIn('duplicate_trust_constraint', constraint_names)

    def test_add_domain_specific_roles(self):
        """Check database upgraded successfully for domain specific roles.

        The following items need to be checked:

        - The domain_id column has been added
        - That it has been added to the uniqueness constraints
        - Existing roles have their domain_id columns set to the specific
          string of '<<null>>'

        """
        NULL_DOMAIN_ID = '<<null>>'

        self.upgrade(87)
        session = self.sessionmaker()
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        # Add a role before we upgrade, so we can check that its new domain_id
        # attribute is handled correctly
        role_id = uuid.uuid4().hex
        self.insert_dict(session, 'role',
                         {'id': role_id, 'name': uuid.uuid4().hex})
        session.close()

        self.upgrade(88)

        session = self.sessionmaker()
        self.assertTableColumns('role', ['id', 'name', 'domain_id', 'extra'])
        # Check the domain_id has been added to the uniqueness constraint
        inspector = reflection.Inspector.from_engine(self.engine)
        constraints = inspector.get_unique_constraints('role')
        constraint_columns = [
            constraint['column_names'] for constraint in constraints
            if constraint['name'] == 'ixu_role_name_domain_id']
        self.assertIn('domain_id', constraint_columns[0])

        # Now check our role has its domain_id attribute set correctly
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        cols = [role_table.c.domain_id]
        filter = role_table.c.id == role_id
        statement = sqlalchemy.select(cols).where(filter)
        role_entry = session.execute(statement).fetchone()
        self.assertEqual(NULL_DOMAIN_ID, role_entry[0])

    def test_add_root_of_all_domains(self):
        NULL_DOMAIN_ID = '<<keystone.domain.root>>'
        self.upgrade(89)
        session = self.sessionmaker()

        domain_table = sqlalchemy.Table(
            'domain', self.metadata, autoload=True)
        query = session.query(domain_table).filter_by(id=NULL_DOMAIN_ID)
        domain_from_db = query.one()
        self.assertIn(NULL_DOMAIN_ID, domain_from_db)

        project_table = sqlalchemy.Table(
            'project', self.metadata, autoload=True)
        query = session.query(project_table).filter_by(id=NULL_DOMAIN_ID)
        project_from_db = query.one()
        self.assertIn(NULL_DOMAIN_ID, project_from_db)

        session.close()

    def test_add_local_user_and_password_tables(self):
        local_user_table = 'local_user'
        password_table = 'password'
        self.upgrade(89)
        self.assertTableDoesNotExist(local_user_table)
        self.assertTableDoesNotExist(password_table)
        self.upgrade(90)
        self.assertTableColumns(local_user_table,
                                ['id',
                                 'user_id',
                                 'domain_id',
                                 'name'])
        self.assertTableColumns(password_table,
                                ['id',
                                 'local_user_id',
                                 'password'])

    def test_migrate_data_to_local_user_and_password_tables(self):
        def get_expected_users():
            expected_users = []
            for test_user in default_fixtures.USERS:
                user = {}
                user['id'] = uuid.uuid4().hex
                user['name'] = test_user['name']
                user['domain_id'] = test_user['domain_id']
                user['password'] = test_user['password']
                user['enabled'] = True
                user['extra'] = json.dumps(uuid.uuid4().hex)
                user['default_project_id'] = uuid.uuid4().hex
                expected_users.append(user)
            return expected_users

        def add_users_to_db(expected_users, user_table):
            for user in expected_users:
                ins = user_table.insert().values(
                    {'id': user['id'],
                     'name': user['name'],
                     'domain_id': user['domain_id'],
                     'password': user['password'],
                     'enabled': user['enabled'],
                     'extra': user['extra'],
                     'default_project_id': user['default_project_id']})
                ins.execute()

        def get_users_from_db(user_table, local_user_table, password_table):
            sel = (
                sqlalchemy.select([user_table.c.id,
                                   user_table.c.enabled,
                                   user_table.c.extra,
                                   user_table.c.default_project_id,
                                   local_user_table.c.name,
                                   local_user_table.c.domain_id,
                                   password_table.c.password])
                .select_from(user_table.join(local_user_table,
                                             user_table.c.id ==
                                             local_user_table.c.user_id)
                                       .join(password_table,
                                             local_user_table.c.id ==
                                             password_table.c.local_user_id))
            )
            user_rows = sel.execute()
            users = []
            for row in user_rows:
                users.append(
                    {'id': row['id'],
                     'name': row['name'],
                     'domain_id': row['domain_id'],
                     'password': row['password'],
                     'enabled': row['enabled'],
                     'extra': row['extra'],
                     'default_project_id': row['default_project_id']})
            return users

        user_table_name = 'user'
        local_user_table_name = 'local_user'
        password_table_name = 'password'

        # populate current user table
        self.upgrade(90)
        user_table = sqlalchemy.Table(
            user_table_name, self.metadata, autoload=True)
        expected_users = get_expected_users()
        add_users_to_db(expected_users, user_table)

        # upgrade to migration and test
        self.upgrade(91)
        self.assertTableCountsMatch(user_table_name, local_user_table_name)
        self.assertTableCountsMatch(local_user_table_name, password_table_name)
        user_table = sqlalchemy.Table(
            user_table_name, self.metadata, autoload=True)
        local_user_table = sqlalchemy.Table(
            local_user_table_name, self.metadata, autoload=True)
        password_table = sqlalchemy.Table(
            password_table_name, self.metadata, autoload=True)
        actual_users = get_users_from_db(user_table, local_user_table,
                                         password_table)
        self.assertItemsEqual(expected_users, actual_users)

    def test_migrate_user_with_null_password_to_password_tables(self):
        USER_TABLE_NAME = 'user'
        LOCAL_USER_TABLE_NAME = 'local_user'
        PASSWORD_TABLE_NAME = 'password'
        self.upgrade(90)
        user_ref = unit.new_user_ref(uuid.uuid4().hex)
        user_ref.pop('password')
        # pop extra attribute which doesn't recognized by SQL expression
        # layer.
        user_ref.pop('email')
        session = self.sessionmaker()
        self.insert_dict(session, USER_TABLE_NAME, user_ref)
        self.upgrade(91)
        # migration should be successful.
        self.assertTableCountsMatch(USER_TABLE_NAME, LOCAL_USER_TABLE_NAME)
        # no new entry was added to the password table because the
        # user doesn't have a password.
        rows = self.calc_table_row_count(PASSWORD_TABLE_NAME)
        self.assertEqual(0, rows)

    def test_migrate_user_skip_user_already_exist_in_local_user(self):
        USER_TABLE_NAME = 'user'
        LOCAL_USER_TABLE_NAME = 'local_user'
        self.upgrade(90)
        user1_ref = unit.new_user_ref(uuid.uuid4().hex)
        # pop extra attribute which doesn't recognized by SQL expression
        # layer.
        user1_ref.pop('email')
        user2_ref = unit.new_user_ref(uuid.uuid4().hex)
        user2_ref.pop('email')
        session = self.sessionmaker()
        self.insert_dict(session, USER_TABLE_NAME, user1_ref)
        self.insert_dict(session, USER_TABLE_NAME, user2_ref)
        user_id = user1_ref.pop('id')
        user_name = user1_ref.pop('name')
        domain_id = user1_ref.pop('domain_id')
        local_user_ref = {'user_id': user_id, 'name': user_name,
                          'domain_id': domain_id}
        self.insert_dict(session, LOCAL_USER_TABLE_NAME, local_user_ref)
        self.upgrade(91)
        # migration should be successful and user2_ref has been migrated to
        # `local_user` table.
        self.assertTableCountsMatch(USER_TABLE_NAME, LOCAL_USER_TABLE_NAME)

    def test_implied_roles_fk_on_delete_cascade(self):
        if self.engine.name == 'sqlite':
            self.skipTest('sqlite backend does not support foreign keys')

        self.upgrade(92)

        session = self.sessionmaker()

        ROLE_TABLE_NAME = 'role'
        role_table = sqlalchemy.Table(ROLE_TABLE_NAME, self.metadata,
                                      autoload=True)
        IMPLIED_ROLE_TABLE_NAME = 'implied_role'
        implied_role_table = sqlalchemy.Table(
            IMPLIED_ROLE_TABLE_NAME, self.metadata, autoload=True)

        def _create_three_roles():
            id_list = []
            for _ in range(3):
                new_role_fields = {
                    'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                }
                self.insert_dict(session, ROLE_TABLE_NAME, new_role_fields,
                                 table=role_table)
                id_list.append(new_role_fields['id'])
            return id_list

        role_id_list = _create_three_roles()
        implied_role_fields = {
            'prior_role_id': role_id_list[0],
            'implied_role_id': role_id_list[1],
        }
        self.insert_dict(session, IMPLIED_ROLE_TABLE_NAME, implied_role_fields,
                         table=implied_role_table)

        implied_role_fields = {
            'prior_role_id': role_id_list[0],
            'implied_role_id': role_id_list[2],
        }
        self.insert_dict(session, IMPLIED_ROLE_TABLE_NAME, implied_role_fields,
                         table=implied_role_table)

        # assert that there are two roles implied by role 0.
        implied_roles = session.query(implied_role_table).filter_by(
            prior_role_id=role_id_list[0]).all()
        self.assertThat(implied_roles, matchers.HasLength(2))

        session.execute(
            role_table.delete().where(role_table.c.id == role_id_list[0]))
        # assert the cascade deletion is effective.
        implied_roles = session.query(implied_role_table).filter_by(
            prior_role_id=role_id_list[0]).all()
        self.assertThat(implied_roles, matchers.HasLength(0))

    def test_domain_as_project_upgrade(self):

        def _populate_domain_and_project_tables(session):
            # Three domains, with various different attributes
            self.domains = [{'id': uuid.uuid4().hex,
                             'name': uuid.uuid4().hex,
                             'enabled': True,
                             'extra': {'description': uuid.uuid4().hex,
                                       'another_attribute': True}},
                            {'id': uuid.uuid4().hex,
                             'name': uuid.uuid4().hex,
                             'enabled': True,
                             'extra': {'description': uuid.uuid4().hex}},
                            {'id': uuid.uuid4().hex,
                             'name': uuid.uuid4().hex,
                             'enabled': False}]
            # Four projects, two top level, two children
            self.projects = []
            self.projects.append(unit.new_project_ref(
                domain_id=self.domains[0]['id'],
                parent_id=None))
            self.projects.append(unit.new_project_ref(
                domain_id=self.domains[0]['id'],
                parent_id=self.projects[0]['id']))
            self.projects.append(unit.new_project_ref(
                domain_id=self.domains[1]['id'],
                parent_id=None))
            self.projects.append(unit.new_project_ref(
                domain_id=self.domains[1]['id'],
                parent_id=self.projects[2]['id']))

            for domain in self.domains:
                this_domain = domain.copy()
                if 'extra' in this_domain:
                    this_domain['extra'] = json.dumps(this_domain['extra'])
                self.insert_dict(session, 'domain', this_domain)
            for project in self.projects:
                # Tags are done via relationship, not column
                project.pop('tags', None)
                self.insert_dict(session, 'project', project)

        def _check_projects(projects):

            def _assert_domain_matches_project(project):
                for domain in self.domains:
                    if project.id == domain['id']:
                        self.assertEqual(domain['name'], project.name)
                        self.assertEqual(domain['enabled'], project.enabled)
                        if domain['id'] == self.domains[0]['id']:
                            self.assertEqual(domain['extra']['description'],
                                             project.description)
                            self.assertEqual({'another_attribute': True},
                                             json.loads(project.extra))
                        elif domain['id'] == self.domains[1]['id']:
                            self.assertEqual(domain['extra']['description'],
                                             project.description)
                            self.assertEqual({}, json.loads(project.extra))

            # We had domains 3 we created, which should now be projects acting
            # as domains, To this we add the 4 original projects, plus the root
            # of all domains row.
            self.assertEqual(8, projects.count())

            project_ids = []
            for project in projects:
                if project.is_domain:
                    self.assertEqual(NULL_DOMAIN_ID, project.domain_id)
                    self.assertIsNone(project.parent_id)
                else:
                    self.assertIsNotNone(project.domain_id)
                    self.assertIsNotNone(project.parent_id)
                project_ids.append(project.id)

            for domain in self.domains:
                self.assertIn(domain['id'], project_ids)
            for project in self.projects:
                self.assertIn(project['id'], project_ids)

            # Now check the attributes of the domains came across OK
            for project in projects:
                _assert_domain_matches_project(project)

        NULL_DOMAIN_ID = '<<keystone.domain.root>>'
        self.upgrade(92)

        session = self.sessionmaker()

        _populate_domain_and_project_tables(session)

        self.upgrade(93)
        proj_table = sqlalchemy.Table('project', self.metadata, autoload=True)

        projects = session.query(proj_table)
        _check_projects(projects)

    def test_add_federated_user_table(self):
        federated_user_table = 'federated_user'
        self.upgrade(93)
        self.assertTableDoesNotExist(federated_user_table)
        self.upgrade(94)
        self.assertTableColumns(federated_user_table,
                                ['id',
                                 'user_id',
                                 'idp_id',
                                 'protocol_id',
                                 'unique_id',
                                 'display_name'])

    def test_add_int_pkey_to_revocation_event_table(self):
        REVOCATION_EVENT_TABLE_NAME = 'revocation_event'
        self.upgrade(94)
        revocation_event_table = sqlalchemy.Table(REVOCATION_EVENT_TABLE_NAME,
                                                  self.metadata, autoload=True)
        # assert id column is a string (before)
        self.assertEqual('VARCHAR(64)', str(revocation_event_table.c.id.type))
        self.upgrade(95)
        revocation_event_table = sqlalchemy.Table(REVOCATION_EVENT_TABLE_NAME,
                                                  self.metadata, autoload=True)
        # assert id column is an integer (after)
        self.assertIsInstance(revocation_event_table.c.id.type, sql.Integer)

    def _add_unique_constraint_to_role_name(self,
                                            constraint_name='ixu_role_name'):
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        migrate.UniqueConstraint(role_table.c.name,
                                 name=constraint_name).create()

    def _drop_unique_constraint_to_role_name(self,
                                             constraint_name='ixu_role_name'):
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        migrate.UniqueConstraint(role_table.c.name,
                                 name=constraint_name).drop()

    def _add_unique_constraint_to_user_name_domainid(
            self,
            constraint_name='ixu_role_name'):
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        migrate.UniqueConstraint(user_table.c.name, user_table.c.domain_id,
                                 name=constraint_name).create()

    def _add_name_domain_id_columns_to_user(self):
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        column_name = sqlalchemy.Column('name', sql.String(255))
        column_domain_id = sqlalchemy.Column('domain_id', sql.String(64))
        user_table.create_column(column_name)
        user_table.create_column(column_domain_id)

    def _drop_unique_constraint_to_user_name_domainid(
            self,
            constraint_name='ixu_user_name_domain_id'):
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        migrate.UniqueConstraint(user_table.c.name, user_table.c.domain_id,
                                 name=constraint_name).drop()

    def test_migration_88_drops_unique_constraint(self):
        self.upgrade(87)
        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertTrue(self.does_constraint_exist('role',
                                                       'ixu_role_name'))
        self.upgrade(88)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_migration_88_inconsistent_constraint_name(self):
        self.upgrade(87)
        self._drop_unique_constraint_to_role_name()

        constraint_name = uuid.uuid4().hex
        self._add_unique_constraint_to_role_name(
            constraint_name=constraint_name)

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('role', constraint_name))
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertTrue(self.does_constraint_exist('role',
                                                       constraint_name))
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

        self.upgrade(88)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', constraint_name))
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        constraint_name))
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_migration_91_drops_unique_constraint(self):
        self.upgrade(90)
        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('user',
                                                  'ixu_user_name_domain_id'))
        else:
            self.assertTrue(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))
        self.upgrade(91)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_91_inconsistent_constraint_name(self):
        self.upgrade(90)
        self._drop_unique_constraint_to_user_name_domainid()

        constraint_name = uuid.uuid4().hex
        self._add_unique_constraint_to_user_name_domainid(
            constraint_name=constraint_name)

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('user', constraint_name))
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertTrue(self.does_constraint_exist('user',
                                                       constraint_name))
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

        self.upgrade(91)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('user', constraint_name))
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist('user',
                                                        constraint_name))
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_96(self):
        self.upgrade(95)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

        self.upgrade(96)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_migration_96_constraint_exists(self):
        self.upgrade(95)
        self._add_unique_constraint_to_role_name()

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertTrue(self.does_constraint_exist('role',
                                                       'ixu_role_name'))

        self.upgrade(96)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_migration_97(self):
        self.upgrade(96)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

        self.upgrade(97)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_97_constraint_exists(self):
        self.upgrade(96)
        self._add_name_domain_id_columns_to_user()
        self._add_unique_constraint_to_user_name_domainid(
            constraint_name='ixu_user_name_domain_id')

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertTrue(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

        self.upgrade(97)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_97_inconsistent_constraint_exists(self):
        self.upgrade(96)
        constraint_name = uuid.uuid4().hex
        self._add_name_domain_id_columns_to_user()
        self._add_unique_constraint_to_user_name_domainid(
            constraint_name=constraint_name)

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('user', constraint_name))
        else:
            self.assertTrue(self.does_constraint_exist('user',
                                                       constraint_name))

        self.upgrade(97)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('user', constraint_name))
        else:
            self.assertFalse(self.does_constraint_exist('user',
                                                        constraint_name))

    def test_migration_101(self):
        self.upgrade(100)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))
        self.upgrade(101)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_migration_101_constraint_exists(self):
        self.upgrade(100)
        self._add_unique_constraint_to_role_name()

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertTrue(self.does_constraint_exist('role',
                                                       'ixu_role_name'))
        self.upgrade(101)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('role', 'ixu_role_name'))
        else:
            self.assertFalse(self.does_constraint_exist('role',
                                                        'ixu_role_name'))

    def test_drop_domain_table(self):
        self.upgrade(101)
        self.assertTableExists('domain')
        self.upgrade(102)
        self.assertTableDoesNotExist('domain')

    def test_add_nonlocal_user_table(self):
        nonlocal_user_table = 'nonlocal_user'
        self.upgrade(102)
        self.assertTableDoesNotExist(nonlocal_user_table)
        self.upgrade(103)
        self.assertTableColumns(nonlocal_user_table,
                                ['domain_id',
                                 'name',
                                 'user_id'])

    def test_migration_104(self):
        self.upgrade(103)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

        self.upgrade(104)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_104_constraint_exists(self):
        self.upgrade(103)
        self._add_name_domain_id_columns_to_user()
        self._add_unique_constraint_to_user_name_domainid(
            constraint_name='ixu_user_name_domain_id')

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertTrue(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

        self.upgrade(104)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist(
                'user',
                'ixu_user_name_domain_id'))
        else:
            self.assertFalse(self.does_constraint_exist(
                'user',
                'ixu_user_name_domain_id'))

    def test_migration_104_inconsistent_constraint_exists(self):
        self.upgrade(103)
        constraint_name = uuid.uuid4().hex
        self._add_name_domain_id_columns_to_user()
        self._add_unique_constraint_to_user_name_domainid(
            constraint_name=constraint_name)

        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist('user', constraint_name))
        else:
            self.assertTrue(self.does_constraint_exist('user',
                                                       constraint_name))

        self.upgrade(104)
        if self.engine.name == 'mysql':
            self.assertFalse(self.does_index_exist('user', constraint_name))
        else:
            self.assertFalse(self.does_constraint_exist('user',
                                                        constraint_name))

    def test_migration_105_add_password_date_columns(self):
        def add_user_model_record(session):
            # add a user
            user = {'id': uuid.uuid4().hex}
            self.insert_dict(session, 'user', user)
            # add a local user
            local_user = {
                'id': 1,
                'user_id': user['id'],
                'domain_id': 'default',
                'name': uuid.uuid4().hex
            }
            self.insert_dict(session, 'local_user', local_user)
            # add a password
            password = {
                'local_user_id': local_user['id'],
                'password': uuid.uuid4().hex
            }
            self.insert_dict(session, 'password', password)
        self.upgrade(104)
        session = self.sessionmaker()
        password_name = 'password'
        # columns before
        self.assertTableColumns(password_name,
                                ['id',
                                 'local_user_id',
                                 'password'])
        # add record and verify table count is greater than zero
        add_user_model_record(session)
        password_table = sqlalchemy.Table(password_name, self.metadata,
                                          autoload=True)
        cnt = session.query(password_table).count()
        self.assertGreater(cnt, 0)
        self.upgrade(105)
        # columns after
        self.assertTableColumns(password_name,
                                ['id',
                                 'local_user_id',
                                 'password',
                                 'created_at',
                                 'expires_at'])
        password_table = sqlalchemy.Table(password_name, self.metadata,
                                          autoload=True)
        # verify created_at is not null
        null_created_at_cnt = (
            session.query(password_table).filter_by(created_at=None).count())
        self.assertEqual(null_created_at_cnt, 0)
        # verify expires_at is null
        null_expires_at_cnt = (
            session.query(password_table).filter_by(expires_at=None).count())
        self.assertGreater(null_expires_at_cnt, 0)

    def test_migration_106_allow_password_column_to_be_nullable(self):
        password_table_name = 'password'
        self.upgrade(105)
        password_table = sqlalchemy.Table(password_table_name, self.metadata,
                                          autoload=True)
        self.assertFalse(password_table.c.password.nullable)
        self.upgrade(106)
        password_table = sqlalchemy.Table(password_table_name, self.metadata,
                                          autoload=True)
        self.assertTrue(password_table.c.password.nullable)

    def test_migration_107_add_user_date_columns(self):
        user_table = 'user'
        self.upgrade(106)
        self.assertTableColumns(user_table,
                                ['id',
                                 'extra',
                                 'enabled',
                                 'default_project_id'])
        self.upgrade(107)
        self.assertTableColumns(user_table,
                                ['id',
                                 'extra',
                                 'enabled',
                                 'default_project_id',
                                 'created_at',
                                 'last_active_at'])

    def test_migration_108_add_failed_auth_columns(self):
        self.upgrade(107)
        table_name = 'local_user'
        self.assertTableColumns(table_name,
                                ['id',
                                 'user_id',
                                 'domain_id',
                                 'name'])
        self.upgrade(108)
        self.assertTableColumns(table_name,
                                ['id',
                                 'user_id',
                                 'domain_id',
                                 'name',
                                 'failed_auth_count',
                                 'failed_auth_at'])

    def test_migration_109_add_password_self_service_column(self):
        password_table = 'password'
        self.upgrade(108)
        self.assertTableColumns(password_table,
                                ['id',
                                 'local_user_id',
                                 'password',
                                 'created_at',
                                 'expires_at'])
        self.upgrade(109)
        self.assertTableColumns(password_table,
                                ['id',
                                 'local_user_id',
                                 'password',
                                 'created_at',
                                 'expires_at',
                                 'self_service'])


class MySQLOpportunisticUpgradeTestCase(SqlLegacyRepoUpgradeTests):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticUpgradeTestCase(SqlLegacyRepoUpgradeTests):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class SqlExpandSchemaUpgradeTests(SqlMigrateBase):

    def setUp(self):
        # Make sure the main repo is fully upgraded for this release since the
        # expand phase is only run after such an upgrade
        super(SqlExpandSchemaUpgradeTests, self).setUp()
        self.upgrade()

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[EXPAND_REPO].min_version,
            self.repos[EXPAND_REPO].version)


class MySQLOpportunisticExpandSchemaUpgradeTestCase(
        SqlExpandSchemaUpgradeTests):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticExpandSchemaUpgradeTestCase(
        SqlExpandSchemaUpgradeTests):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class SqlDataMigrationUpgradeTests(SqlMigrateBase):

    def setUp(self):
        # Make sure the legacy and expand repos are fully upgraded, since the
        # data migration phase is only run after these are upgraded
        super(SqlDataMigrationUpgradeTests, self).setUp()
        self.upgrade()
        self.expand()

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[DATA_MIGRATION_REPO].min_version,
            self.repos[DATA_MIGRATION_REPO].version)


class MySQLOpportunisticDataMigrationUpgradeTestCase(
        SqlDataMigrationUpgradeTests):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticDataMigrationUpgradeTestCase(
        SqlDataMigrationUpgradeTests):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class SqlContractSchemaUpgradeTests(SqlMigrateBase, unit.TestCase):

    def setUp(self):
        # Make sure the legacy, expand and data migration repos are fully
        # upgraded, since the contract phase is only run after these are
        # upgraded.
        super(SqlContractSchemaUpgradeTests, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )
        self.upgrade()
        self.expand()
        self.migrate()

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[CONTRACT_REPO].min_version,
            self.repos[CONTRACT_REPO].version)


class MySQLOpportunisticContractSchemaUpgradeTestCase(
        SqlContractSchemaUpgradeTests):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticContractSchemaUpgradeTestCase(
        SqlContractSchemaUpgradeTests):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class VersionTests(SqlMigrateBase):
    def test_core_initial(self):
        """Get the version before migrated, it's the initial DB version."""
        self.assertEqual(
            self.repos[LEGACY_REPO].min_version,
            self.repos[LEGACY_REPO].version)

    def test_core_max(self):
        """When get the version after upgrading, it's the new version."""
        self.upgrade()
        self.assertEqual(
            self.repos[LEGACY_REPO].max_version,
            self.repos[LEGACY_REPO].version)

    def test_assert_not_schema_downgrade(self):
        self.upgrade()
        self.assertRaises(
            db_exception.DBMigrationError,
            upgrades._sync_common_repo,
            self.repos[LEGACY_REPO].max_version - 1)

    def test_these_are_not_the_migrations_you_are_looking_for(self):
        """Keystone has shifted to rolling upgrades.

        New database migrations should no longer land in the legacy migration
        repository. Instead, new database migrations should be divided into
        three discrete steps: schema expansion, data migration, and schema
        contraction. These migrations live in a new set of database migration
        repositories, called ``expand_repo``, ``data_migration_repo``, and
        ``contract_repo``.

        For more information, see "Database Migrations" here:

            https://docs.openstack.org/keystone/latest/contributor/database-migrations.html

        """
        # Note to reviewers: this version number should never change.
        self.assertEqual(109, self.repos[LEGACY_REPO].max_version)

    def test_migrate_repos_stay_in_lockstep(self):
        """Rolling upgrade repositories should always stay in lockstep.

        By maintaining a single "latest" version number in each of the three
        migration repositories (expand, data migrate, and contract), we can
        trivially prevent operators from "doing the wrong thing", such as
        running upgrades operations out of order (for example, you should not
        be able to run data migration 5 until schema expansion 5 has been run).

        For example, even if your rolling upgrade task *only* involves adding a
        new column with a reasonable default, and doesn't require any triggers,
        data migration, etc, you still need to create "empty" upgrade steps in
        the data migration and contract repositories with the same version
        number as the expansion.

        For more information, see "Database Migrations" here:

            https://docs.openstack.org/keystone/latest/contributor/database-migrations.html

        """
        # Transitive comparison: expand == data migration == contract
        self.assertEqual(
            self.repos[EXPAND_REPO].max_version,
            self.repos[DATA_MIGRATION_REPO].max_version)
        self.assertEqual(
            self.repos[DATA_MIGRATION_REPO].max_version,
            self.repos[CONTRACT_REPO].max_version)

    def test_migrate_repos_file_names_have_prefix(self):
        """Migration files should be unique to avoid caching errors.

        This test enforces migration files to include a prefix (expand,
        migrate, contract) in order to keep them unique. Here is the required
        format: [version]_[prefix]_[description]. For example:
        001_expand_add_created_column.py

        """
        versions_path = '/versions'
        # test for expand prefix, e.g. 001_expand_new_fk_constraint.py
        expand_list = os.listdir(
            self.repos[EXPAND_REPO].repo_path + versions_path)
        self.assertRepoFileNamePrefix(expand_list, 'expand')
        # test for migrate prefix, e.g. 001_migrate_new_fk_constraint.py
        migrate_list = os.listdir(
            self.repos[DATA_MIGRATION_REPO].repo_path + versions_path)
        self.assertRepoFileNamePrefix(migrate_list, 'migrate')
        # test for contract prefix, e.g. 001_contract_new_fk_constraint.py
        contract_list = os.listdir(
            self.repos[CONTRACT_REPO].repo_path + versions_path)
        self.assertRepoFileNamePrefix(contract_list, 'contract')

    def assertRepoFileNamePrefix(self, repo_list, prefix):
        if len(repo_list) > 1:
            # grab the file name for the max version
            file_name = sorted(repo_list)[-2]
            # pattern for the prefix standard, ignoring placeholder, init files
            pattern = (
                '^[0-9]{3,}_PREFIX_|^[0-9]{3,}_placeholder.py|^__init__.py')
            pattern = pattern.replace('PREFIX', prefix)
            msg = 'Missing required prefix %s in $file_name' % prefix
            self.assertRegex(file_name, pattern, msg)


class MigrationValidation(SqlMigrateBase, unit.TestCase):
    """Test validation of database between database phases."""

    def _set_db_sync_command_versions(self):
        self.expand(1)
        self.migrate(1)
        self.contract(1)
        self.assertEqual(upgrades.get_db_version('expand_repo'), 1)
        self.assertEqual(upgrades.get_db_version('data_migration_repo'), 1)
        self.assertEqual(upgrades.get_db_version('contract_repo'), 1)

    def test_running_db_sync_expand_without_up_to_date_legacy_fails(self):
        # Set Legacy version and then test that running expand fails if Legacy
        # isn't at the latest version.
        self.upgrade(67)
        latest_version = self.repos[EXPAND_REPO].max_version
        self.assertRaises(
            db_exception.DBMigrationError,
            self.expand,
            latest_version,
            "You are attempting to upgrade migrate ahead of expand")

    def test_running_db_sync_migrate_ahead_of_expand_fails(self):
        self.upgrade()
        self._set_db_sync_command_versions()
        self.assertRaises(
            db_exception.DBMigrationError,
            self.migrate,
            2,
            "You are attempting to upgrade migrate ahead of expand")

    def test_running_db_sync_contract_ahead_of_migrate_fails(self):
        self.upgrade()
        self._set_db_sync_command_versions()
        self.assertRaises(
            db_exception.DBMigrationError,
            self.contract,
            2,
            "You are attempting to upgrade contract ahead of migrate")


class FullMigration(SqlMigrateBase, unit.TestCase):
    """Test complete orchestration between all database phases."""

    def setUp(self):
        super(FullMigration, self).setUp()
        # Upgrade the legacy repository
        self.upgrade()

    def test_db_sync_check(self):
        checker = cli.DbSync()
        latest_version = self.repos[EXPAND_REPO].max_version

        # If the expand repository doesn't exist yet, then we need to make sure
        # we advertise that `--expand` must be run first.
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --expand", log_info.output)
        self.assertEqual(status, 2)

        # Assert the correct message is printed when expand is the first step
        # that needs to run
        self.expand(1)
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --expand", log_info.output)
        self.assertEqual(status, 2)

        # Assert the correct message is printed when expand is farther than
        # migrate
        self.expand(latest_version)
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --migrate", log_info.output)
        self.assertEqual(status, 3)

        # Assert the correct message is printed when migrate is farther than
        # contract
        self.migrate(latest_version)
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --contract", log_info.output)
        self.assertEqual(status, 4)

        # Assert the correct message gets printed when all commands are on
        # the same version
        self.contract(latest_version)
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("All db_sync commands are upgraded", log_info.output)
        self.assertEqual(status, 0)

    def test_out_of_sync_db_migration_fails(self):
        # We shouldn't allow for operators to accidentally run migration out of
        # order. This test ensures we fail if we attempt to upgrade the
        # contract repository ahead of the expand or migrate repositories.
        self.expand(3)
        self.migrate(3)
        self.assertRaises(db_exception.DBMigrationError, self.contract, 4)

    def test_migration_002_password_created_at_not_nullable(self):
        # upgrade each repository to 001
        self.expand(1)
        self.migrate(1)
        self.contract(1)

        password = sqlalchemy.Table('password', self.metadata, autoload=True)
        self.assertTrue(password.c.created_at.nullable)
        # upgrade each repository to 002
        self.expand(2)
        self.migrate(2)
        self.contract(2)
        password = sqlalchemy.Table('password', self.metadata, autoload=True)
        if self.engine.name != 'sqlite':
            self.assertFalse(password.c.created_at.nullable)

    def test_migration_003_migrate_unencrypted_credentials(self):
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

        session = self.sessionmaker()
        credential_table_name = 'credential'

        # upgrade each repository to 002
        self.expand(2)
        self.migrate(2)
        self.contract(2)

        # populate the credential table with some sample credentials
        credentials = list()
        for i in range(5):
            credential = {'id': uuid.uuid4().hex,
                          'blob': uuid.uuid4().hex,
                          'user_id': uuid.uuid4().hex,
                          'type': 'cert'}
            credentials.append(credential)
            self.insert_dict(session, credential_table_name, credential)

        # verify the current schema
        self.assertTableColumns(
            credential_table_name,
            ['id', 'user_id', 'project_id', 'type', 'blob', 'extra']
        )

        # upgrade expand repo to 003 to add new columns
        self.expand(3)

        # verify encrypted_blob and key_hash columns have been added and verify
        # the original blob column is still there
        self.assertTableColumns(
            credential_table_name,
            ['id', 'user_id', 'project_id', 'type', 'blob', 'extra',
             'key_hash', 'encrypted_blob']
        )

        # verify triggers by making sure we can't write to the credential table
        credential = {'id': uuid.uuid4().hex,
                      'blob': uuid.uuid4().hex,
                      'user_id': uuid.uuid4().hex,
                      'type': 'cert'}
        self.assertRaises(db_exception.DBError,
                          self.insert_dict,
                          session,
                          credential_table_name,
                          credential)

        # upgrade migrate repo to 003 to migrate existing credentials
        self.migrate(3)

        # make sure we've actually updated the credential with the
        # encrypted blob and the corresponding key hash
        credential_table = sqlalchemy.Table(
            credential_table_name,
            self.metadata,
            autoload=True
        )
        for credential in credentials:
            filter = credential_table.c.id == credential['id']
            cols = [credential_table.c.key_hash, credential_table.c.blob,
                    credential_table.c.encrypted_blob]
            q = sqlalchemy.select(cols).where(filter)
            result = session.execute(q).fetchone()

            self.assertIsNotNone(result.encrypted_blob)
            self.assertIsNotNone(result.key_hash)
            # verify the original blob column is still populated
            self.assertEqual(result.blob, credential['blob'])

        # verify we can't make any writes to the credential table
        credential = {'id': uuid.uuid4().hex,
                      'blob': uuid.uuid4().hex,
                      'user_id': uuid.uuid4().hex,
                      'key_hash': uuid.uuid4().hex,
                      'type': 'cert'}
        self.assertRaises(db_exception.DBError,
                          self.insert_dict,
                          session,
                          credential_table_name,
                          credential)

        # upgrade contract repo to 003 to remove triggers and blob column
        self.contract(3)

        # verify the new schema doesn't have a blob column anymore
        self.assertTableColumns(
            credential_table_name,
            ['id', 'user_id', 'project_id', 'type', 'extra', 'key_hash',
             'encrypted_blob']
        )

        # verify that the triggers are gone by writing to the database
        credential = {'id': uuid.uuid4().hex,
                      'encrypted_blob': uuid.uuid4().hex,
                      'key_hash': uuid.uuid4().hex,
                      'user_id': uuid.uuid4().hex,
                      'type': 'cert'}
        self.insert_dict(session, credential_table_name, credential)

    def test_migration_004_reset_password_created_at(self):
        # upgrade each repository to 003 and test
        self.expand(3)
        self.migrate(3)
        self.contract(3)
        password = sqlalchemy.Table('password', self.metadata, autoload=True)
        # postgresql returns 'TIMESTAMP WITHOUT TIME ZONE'
        self.assertTrue(
            str(password.c.created_at.type).startswith('TIMESTAMP'))
        # upgrade each repository to 004 and test
        self.expand(4)
        self.migrate(4)
        self.contract(4)
        password = sqlalchemy.Table('password', self.metadata, autoload=True)
        # type would still be TIMESTAMP with postgresql
        if self.engine.name == 'postgresql':
            self.assertTrue(
                str(password.c.created_at.type).startswith('TIMESTAMP'))
        else:
            self.assertEqual('DATETIME', str(password.c.created_at.type))
        self.assertFalse(password.c.created_at.nullable)

    def test_migration_010_add_revocation_event_indexes(self):
        self.expand(9)
        self.migrate(9)
        self.contract(9)
        self.assertFalse(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_issued_before'))
        self.assertFalse(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_project_id_issued_before'))
        self.assertFalse(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_user_id_issued_before'))
        self.assertFalse(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_audit_id_issued_before'))
        self.expand(10)
        self.migrate(10)
        self.contract(10)
        self.assertTrue(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_issued_before'))
        self.assertTrue(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_project_id_issued_before'))
        self.assertTrue(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_user_id_issued_before'))
        self.assertTrue(self.does_index_exist(
            'revocation_event',
            'ix_revocation_event_audit_id_issued_before'))

    def test_migration_011_user_id_unique_for_nonlocal_user(self):
        table_name = 'nonlocal_user'
        column = 'user_id'
        self.expand(10)
        self.migrate(10)
        self.contract(10)
        self.assertFalse(self.does_unique_constraint_exist(table_name, column))
        self.expand(11)
        self.migrate(11)
        self.contract(11)
        self.assertTrue(self.does_unique_constraint_exist(table_name, column))

    def test_migration_012_add_domain_id_to_idp(self):
        def _create_domain():
            domain_id = uuid.uuid4().hex
            domain = {
                'id': domain_id,
                'name': domain_id,
                'enabled': True,
                'description': uuid.uuid4().hex,
                'domain_id': resource_base.NULL_DOMAIN_ID,
                'is_domain': True,
                'parent_id': None,
                'extra': '{}'
            }
            self.insert_dict(session, 'project', domain)
            return domain_id

        def _get_new_idp(domain_id):
            new_idp = {'id': uuid.uuid4().hex,
                       'domain_id': domain_id,
                       'enabled': True,
                       'description': uuid.uuid4().hex}
            return new_idp

        session = self.sessionmaker()
        idp_name = 'identity_provider'
        self.expand(11)
        self.migrate(11)
        self.contract(11)
        self.assertTableColumns(idp_name,
                                ['id',
                                 'enabled',
                                 'description'])
        # add some data
        for i in range(5):
            idp = {'id': uuid.uuid4().hex,
                   'enabled': True,
                   'description': uuid.uuid4().hex}
            self.insert_dict(session, idp_name, idp)

        # upgrade
        self.expand(12)
        self.assertTableColumns(idp_name,
                                ['id',
                                 'domain_id',
                                 'enabled',
                                 'description'])

        # confirm we cannot insert an idp during expand
        domain_id = _create_domain()
        new_idp = _get_new_idp(domain_id)
        self.assertRaises(db_exception.DBError, self.insert_dict, session,
                          idp_name, new_idp)

        # confirm we cannot insert an idp during migrate
        self.migrate(12)
        self.assertRaises(db_exception.DBError, self.insert_dict, session,
                          idp_name, new_idp)

        # confirm we can insert a new idp after contract
        self.contract(12)
        self.insert_dict(session, idp_name, new_idp)

        # confirm domain_id column is not null
        idp_table = sqlalchemy.Table(idp_name, self.metadata, autoload=True)
        self.assertFalse(idp_table.c.domain_id.nullable)

    def test_migration_013_protocol_cascade_delete_for_federated_user(self):
        if self.engine.name == 'sqlite':
            self.skipTest('sqlite backend does not support foreign keys')

        self.expand(12)
        self.migrate(12)
        self.contract(12)

        # This test requires a bit of setup to properly work, first we create
        # an identity provider, mapping and a protocol. Then, we create a
        # federated user and delete the protocol. We expect the federated user
        # to be deleted as well.

        session = self.sessionmaker()

        def _create_protocol():
            domain = {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': resource_base.NULL_DOMAIN_ID,
                'is_domain': True,
                'parent_id': None
            }
            self.insert_dict(session, 'project', domain)

            idp = {'id': uuid.uuid4().hex, 'enabled': True,
                   'domain_id': domain['id']}
            self.insert_dict(session, 'identity_provider', idp)

            mapping = {'id': uuid.uuid4().hex, 'rules': json.dumps([])}
            self.insert_dict(session, 'mapping', mapping)

            protocol = {'id': uuid.uuid4().hex, 'idp_id': idp['id'],
                        'mapping_id': mapping['id']}
            protocol_table = sqlalchemy.Table(
                'federation_protocol', self.metadata, autoload=True)
            self.insert_dict(session, 'federation_protocol', protocol,
                             table=protocol_table)

            return protocol, protocol_table

        def _create_federated_user(idp_id, protocol_id):
            user = {'id': uuid.uuid4().hex}
            self.insert_dict(session, 'user', user)

            # NOTE(rodrigods): do not set the ID, the engine will do that
            # for us and we won't need it later.
            federated_user = {
                'user_id': user['id'], 'idp_id': idp_id,
                'protocol_id': protocol_id, 'unique_id': uuid.uuid4().hex}
            federated_table = sqlalchemy.Table(
                'federated_user', self.metadata, autoload=True)
            self.insert_dict(session, 'federated_user', federated_user,
                             table=federated_table)

            return federated_user, federated_table

        protocol, protocol_table = _create_protocol()
        federated_user, federated_table = _create_federated_user(
            protocol['idp_id'], protocol['id'])

        # before updating the foreign key, we won't be able to delete the
        # protocol
        self.assertRaises(db_exception.DBError,
                          session.execute,
                          protocol_table.delete().where(
                              protocol_table.c.id == protocol['id']))

        self.expand(13)
        self.migrate(13)
        self.contract(13)

        # now we are able to delete the protocol
        session.execute(
            protocol_table.delete().where(
                protocol_table.c.id == protocol['id']))

        # assert the cascade deletion worked
        federated_users = session.query(federated_table).filter_by(
            protocol_id=federated_user['protocol_id']).all()
        self.assertThat(federated_users, matchers.HasLength(0))

    def test_migration_014_add_domain_id_to_user_table(self):
        def create_domain():
            table = sqlalchemy.Table('project', self.metadata, autoload=True)
            domain_id = uuid.uuid4().hex
            domain = {
                'id': domain_id,
                'name': domain_id,
                'enabled': True,
                'description': uuid.uuid4().hex,
                'domain_id': resource_base.NULL_DOMAIN_ID,
                'is_domain': True,
                'parent_id': None,
                'extra': '{}'
            }
            table.insert().values(domain).execute()
            return domain_id

        def create_user(table):
            user_id = uuid.uuid4().hex
            user = {'id': user_id, 'enabled': True}
            table.insert().values(user).execute()
            return user_id

        # insert local_user or nonlocal_user
        def create_child_user(table, user_id, domain_id):
            child_user = {
                'user_id': user_id,
                'domain_id': domain_id,
                'name': uuid.uuid4().hex
            }
            table.insert().values(child_user).execute()

        # update local_user or nonlocal_user
        def update_child_user(table, user_id, new_domain_id):
            table.update().where(table.c.user_id == user_id).values(
                domain_id=new_domain_id).execute()

        def assertUserDomain(user_id, domain_id):
            user = sqlalchemy.Table('user', self.metadata, autoload=True)
            cols = [user.c.domain_id]
            filter = user.c.id == user_id
            sel = sqlalchemy.select(cols).where(filter)
            domains = sel.execute().fetchone()
            self.assertEqual(domain_id, domains[0])

        user_table_name = 'user'
        self.expand(13)
        self.migrate(13)
        self.contract(13)
        self.assertTableColumns(
            user_table_name, ['id', 'extra', 'enabled', 'default_project_id',
                              'created_at', 'last_active_at'])
        self.expand(14)
        self.assertTableColumns(
            user_table_name, ['id', 'extra', 'enabled', 'default_project_id',
                              'created_at', 'last_active_at', 'domain_id'])
        user_table = sqlalchemy.Table(user_table_name, self.metadata,
                                      autoload=True)
        local_user_table = sqlalchemy.Table('local_user', self.metadata,
                                            autoload=True)
        nonlocal_user_table = sqlalchemy.Table('nonlocal_user', self.metadata,
                                               autoload=True)

        # add users before migrate to test that the user.domain_id gets updated
        # after migrate
        user_ids = []
        expected_domain_id = create_domain()
        user_id = create_user(user_table)
        create_child_user(local_user_table, user_id, expected_domain_id)
        user_ids.append(user_id)
        user_id = create_user(user_table)
        create_child_user(nonlocal_user_table, user_id, expected_domain_id)
        user_ids.append(user_id)

        self.migrate(14)
        # test local_user insert trigger updates user.domain_id
        user_id = create_user(user_table)
        domain_id = create_domain()
        create_child_user(local_user_table, user_id, domain_id)
        assertUserDomain(user_id, domain_id)

        # test local_user update trigger updates user.domain_id
        new_domain_id = create_domain()
        update_child_user(local_user_table, user_id, new_domain_id)
        assertUserDomain(user_id, new_domain_id)

        # test nonlocal_user insert trigger updates user.domain_id
        user_id = create_user(user_table)
        create_child_user(nonlocal_user_table, user_id, domain_id)
        assertUserDomain(user_id, domain_id)

        # test nonlocal_user update trigger updates user.domain_id
        update_child_user(nonlocal_user_table, user_id, new_domain_id)
        assertUserDomain(user_id, new_domain_id)

        self.contract(14)
        # test migrate updated the user.domain_id
        for user_id in user_ids:
            assertUserDomain(user_id, expected_domain_id)

        # test unique and fk constraints
        if self.engine.name == 'mysql':
            self.assertTrue(
                self.does_index_exist('user', 'ixu_user_id_domain_id'))
        else:
            self.assertTrue(
                self.does_constraint_exist('user', 'ixu_user_id_domain_id'))
        self.assertTrue(self.does_fk_exist('local_user', 'user_id'))
        self.assertTrue(self.does_fk_exist('local_user', 'domain_id'))
        self.assertTrue(self.does_fk_exist('nonlocal_user', 'user_id'))
        self.assertTrue(self.does_fk_exist('nonlocal_user', 'domain_id'))

    def test_migration_015_update_federated_user_domain(self):
        def create_domain():
            table = sqlalchemy.Table('project', self.metadata, autoload=True)
            domain_id = uuid.uuid4().hex
            domain = {
                'id': domain_id,
                'name': domain_id,
                'enabled': True,
                'description': uuid.uuid4().hex,
                'domain_id': resource_base.NULL_DOMAIN_ID,
                'is_domain': True,
                'parent_id': None,
                'extra': '{}'
            }
            table.insert().values(domain).execute()
            return domain_id

        def create_idp(domain_id):
            table = sqlalchemy.Table('identity_provider', self.metadata,
                                     autoload=True)
            idp_id = uuid.uuid4().hex
            idp = {
                'id': idp_id,
                'domain_id': domain_id,
                'enabled': True,
                'description': uuid.uuid4().hex
            }
            table.insert().values(idp).execute()
            return idp_id

        def create_protocol(idp_id):
            table = sqlalchemy.Table('federation_protocol', self.metadata,
                                     autoload=True)
            protocol_id = uuid.uuid4().hex
            protocol = {
                'id': protocol_id,
                'idp_id': idp_id,
                'mapping_id': uuid.uuid4().hex
            }
            table.insert().values(protocol).execute()
            return protocol_id

        def create_user():
            table = sqlalchemy.Table('user', self.metadata, autoload=True)
            user_id = uuid.uuid4().hex
            user = {'id': user_id, 'enabled': True}
            table.insert().values(user).execute()
            return user_id

        def create_federated_user(user_id, idp_id, protocol_id):
            table = sqlalchemy.Table('federated_user', self.metadata,
                                     autoload=True)
            federated_user = {
                'user_id': user_id,
                'idp_id': idp_id,
                'protocol_id': protocol_id,
                'unique_id': uuid.uuid4().hex,
                'display_name': uuid.uuid4().hex
            }
            table.insert().values(federated_user).execute()

        def assertUserDomain(user_id, domain_id):
            table = sqlalchemy.Table('user', self.metadata, autoload=True)
            where = table.c.id == user_id
            stmt = sqlalchemy.select([table.c.domain_id]).where(where)
            domains = stmt.execute().fetchone()
            self.assertEqual(domain_id, domains[0])

        def assertUserDomainIsNone(user_id):
            table = sqlalchemy.Table('user', self.metadata, autoload=True)
            where = table.c.id == user_id
            stmt = sqlalchemy.select([table.c.domain_id]).where(where)
            domains = stmt.execute().fetchone()
            self.assertIsNone(domains[0])

        self.expand(14)
        self.migrate(14)
        self.contract(14)

        domain_id = create_domain()
        idp_id = create_idp(domain_id)
        protocol_id = create_protocol(idp_id)

        # create user before expand to test data migration
        user_id_before_expand = create_user()
        create_federated_user(user_id_before_expand, idp_id, protocol_id)
        assertUserDomainIsNone(user_id_before_expand)

        self.expand(15)
        # create user before migrate to test insert trigger
        user_id_before_migrate = create_user()
        create_federated_user(user_id_before_migrate, idp_id, protocol_id)
        assertUserDomain(user_id_before_migrate, domain_id)

        self.migrate(15)
        # test insert trigger after migrate
        user_id = create_user()
        create_federated_user(user_id, idp_id, protocol_id)
        assertUserDomain(user_id, domain_id)

        self.contract(15)
        # test migrate updated the user.domain_id
        assertUserDomain(user_id_before_expand, domain_id)

        # verify that the user.domain_id is now not nullable
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        self.assertFalse(user_table.c.domain_id.nullable)

    def test_migration_016_add_user_options(self):
        self.expand(15)
        self.migrate(15)
        self.contract(15)

        user_option = 'user_option'
        self.assertTableDoesNotExist(user_option)
        self.expand(16)
        self.migrate(16)
        self.contract(16)
        self.assertTableColumns(user_option,
                                ['user_id', 'option_id', 'option_value'])

    def test_migration_024_add_created_expires_at_int_columns_password(self):

        self.expand(23)
        self.migrate(23)
        self.contract(23)

        password_table_name = 'password'

        self.assertTableColumns(
            password_table_name,
            ['id', 'local_user_id', 'password', 'password_hash', 'created_at',
             'expires_at', 'self_service']
        )

        self.expand(24)

        self.assertTableColumns(
            password_table_name,
            ['id', 'local_user_id', 'password', 'password_hash', 'created_at',
             'expires_at', 'created_at_int', 'expires_at_int', 'self_service']
        )

        # Create User and Local User
        project_table = sqlalchemy.Table('project', self.metadata,
                                         autoload=True)
        domain_data = {'id': '_domain', 'domain_id': '_domain',
                       'enabled': True, 'name': '_domain', 'is_domain': True}
        project_table.insert().values(domain_data).execute()
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        user_id = uuid.uuid4().hex
        user = {'id': user_id, 'enabled': True, 'domain_id': domain_data['id']}
        user_table.insert().values(user).execute()
        local_user_table = sqlalchemy.Table('local_user', self.metadata,
                                            autoload=True)
        local_user = {
            'id': 1, 'user_id': user_id, 'domain_id': user['domain_id'],
            'name': 'name'}

        local_user_table.insert().values(local_user).execute()

        password_table = sqlalchemy.Table('password',
                                          self.metadata, autoload=True)
        password_data = {
            'local_user_id': local_user['id'],
            'created_at': datetime.datetime.utcnow(),
            'expires_at': datetime.datetime.utcnow()}
        password_table.insert().values(password_data).execute()

        self.migrate(24)
        self.contract(24)
        passwords = list(password_table.select().execute())

        epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)

        for p in passwords:
            c = (p.created_at.replace(tzinfo=pytz.UTC) - epoch).total_seconds()
            e = (p.expires_at.replace(tzinfo=pytz.UTC) - epoch).total_seconds()
            self.assertEqual(p.created_at_int, int(c * 1000000))
            self.assertEqual(p.expires_at_int, int(e * 1000000))

        # Test contract phase and ensure data can not be null
        self.contract(24)
        meta = sqlalchemy.MetaData(self.engine)
        pw_table = sqlalchemy.Table('password', meta, autoload=True)
        self.assertFalse(pw_table.c.created_at_int.nullable)

    def test_migration_30_expand_add_project_tags_table(self):
        self.expand(29)
        self.migrate(29)
        self.contract(29)

        table_name = 'project_tag'
        self.assertTableDoesNotExist(table_name)

        self.expand(30)
        self.migrate(30)
        self.contract(30)

        self.assertTableExists(table_name)
        self.assertTableColumns(
            table_name,
            ['project_id', 'name'])

    def test_migration_030_project_tags_works_correctly_after_migration(self):
        if self.engine.name == 'sqlite':
            self.skipTest('sqlite backend does not support foreign keys')

        self.expand(30)
        self.migrate(30)
        self.contract(30)

        project_table = sqlalchemy.Table(
            'project', self.metadata, autoload=True)
        tag_table = sqlalchemy.Table(
            'project_tag', self.metadata, autoload=True)

        session = self.sessionmaker()
        project_id = uuid.uuid4().hex

        project = {
            'id': project_id,
            'name': uuid.uuid4().hex,
            'enabled': True,
            'domain_id': resource_base.NULL_DOMAIN_ID,
            'is_domain': False
        }

        tag = {
            'project_id': project_id,
            'name': uuid.uuid4().hex
        }

        self.insert_dict(session, 'project', project)
        self.insert_dict(session, 'project_tag', tag)

        tags_query = session.query(tag_table).filter_by(
            project_id=project_id).all()
        self.assertThat(tags_query, matchers.HasLength(1))

        # Adding duplicate tags should cause error.
        self.assertRaises(db_exception.DBDuplicateEntry,
                          self.insert_dict,
                          session, 'project_tag', tag)

        session.execute(
            project_table.delete().where(project_table.c.id == project_id)
        )

        tags_query = session.query(tag_table).filter_by(
            project_id=project_id).all()
        self.assertThat(tags_query, matchers.HasLength(0))

        session.close()

    def test_migration_031_adds_system_assignment_table(self):
        self.expand(30)
        self.migrate(30)
        self.contract(30)

        system_assignment_table_name = 'system_assignment'
        self.assertTableDoesNotExist(system_assignment_table_name)

        self.expand(31)
        self.migrate(31)
        self.contract(31)

        self.assertTableExists(system_assignment_table_name)
        self.assertTableColumns(
            system_assignment_table_name,
            ['type', 'actor_id', 'target_id', 'role_id', 'inherited']
        )

        system_assignment_table = sqlalchemy.Table(
            system_assignment_table_name, self.metadata, autoload=True
        )

        system_user = {
            'type': 'UserSystem',
            'target_id': uuid.uuid4().hex,
            'actor_id': uuid.uuid4().hex,
            'role_id': uuid.uuid4().hex,
            'inherited': False
        }
        system_assignment_table.insert().values(system_user).execute()

        system_group = {
            'type': 'GroupSystem',
            'target_id': uuid.uuid4().hex,
            'actor_id': uuid.uuid4().hex,
            'role_id': uuid.uuid4().hex,
            'inherited': False
        }
        system_assignment_table.insert().values(system_group).execute()

    def test_migration_032_add_expires_at_int_column_trust(self):

        self.expand(31)
        self.migrate(31)
        self.contract(31)

        trust_table_name = 'trust'

        self.assertTableColumns(
            trust_table_name,
            ['id', 'trustor_user_id', 'trustee_user_id', 'project_id',
             'impersonation', 'deleted_at', 'expires_at', 'remaining_uses',
             'extra'],
        )

        self.expand(32)

        self.assertTableColumns(
            trust_table_name,
            ['id', 'trustor_user_id', 'trustee_user_id', 'project_id',
             'impersonation', 'deleted_at', 'expires_at', 'expires_at_int',
             'remaining_uses', 'extra'],
        )

        # Create Trust
        trust_table = sqlalchemy.Table('trust', self.metadata,
                                       autoload=True)
        trust_1_data = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': False,
            'expires_at': datetime.datetime.utcnow()
        }
        trust_2_data = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': False,
            'expires_at': None
        }
        trust_table.insert().values(trust_1_data).execute()
        trust_table.insert().values(trust_2_data).execute()

        self.migrate(32)
        self.contract(32)
        trusts = list(trust_table.select().execute())

        epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)

        for t in trusts:
            if t.expires_at:
                e = t.expires_at.replace(tzinfo=pytz.UTC) - epoch
                e = e.total_seconds()
                self.assertEqual(t.expires_at_int, int(e * 1000000))

    def test_migration_033_adds_limits_table(self):
        self.expand(32)
        self.migrate(32)
        self.contract(32)

        registered_limit_table_name = 'registered_limit'
        limit_table_name = 'limit'
        self.assertTableDoesNotExist(registered_limit_table_name)
        self.assertTableDoesNotExist(limit_table_name)

        self.expand(33)
        self.migrate(33)
        self.contract(33)

        self.assertTableExists(registered_limit_table_name)
        self.assertTableColumns(
            registered_limit_table_name,
            ['id', 'service_id', 'resource_name', 'region_id', 'default_limit']
        )
        self.assertTableExists(limit_table_name)
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'resource_name', 'region_id',
             'resource_limit']
        )

        session = self.sessionmaker()
        service_id = uuid.uuid4().hex
        service = {
            'id': service_id,
            'type': 'compute',
            'enabled': True
        }
        region = {
            'id': 'RegionOne',
            'description': 'test'
        }
        project_id = uuid.uuid4().hex
        project = {
            'id': project_id,
            'name': 'nova',
            'enabled': True,
            'domain_id': resource_base.NULL_DOMAIN_ID,
            'is_domain': False
        }
        self.insert_dict(session, 'service', service)
        self.insert_dict(session, 'region', region)
        self.insert_dict(session, 'project', project)

        # Insert one registered limit
        registered_limit_table = sqlalchemy.Table(
            registered_limit_table_name, self.metadata, autoload=True)
        registered_limit = {
            'id': uuid.uuid4().hex,
            'service_id': service_id,
            'region_id': 'RegionOne',
            'resource_name': 'cores',
            'default_limit': 10
        }
        registered_limit_table.insert().values(registered_limit).execute()

        # It will raise error if insert another one with same service_id,
        # region_id and resource name.
        registered_limit['id'] = uuid.uuid4().hex
        registered_limit['default_limit'] = 20
        self.assertRaises(db_exception.DBDuplicateEntry,
                          registered_limit_table.insert().values(
                              registered_limit).execute)

        # Insert one without region_id
        registered_limit_without_region = {
            'id': uuid.uuid4().hex,
            'service_id': service_id,
            'resource_name': 'cores',
            'default_limit': 10
        }
        registered_limit_table.insert().values(
            registered_limit_without_region).execute()

        # It will not raise error if insert another one with same service_id
        # and resource_name but the region_id is None. Because that
        # UniqueConstraint doesn't work if one of the columns is None. This
        # should be controlled at the Manager layer to forbid this behavior.
        registered_limit_without_region['id'] = uuid.uuid4().hex
        registered_limit_table.insert().values(
            registered_limit_without_region).execute()

        # Insert one limit
        limit_table = sqlalchemy.Table(
            limit_table_name, self.metadata, autoload=True)
        limit = {
            'id': uuid.uuid4().hex,
            'project_id': project_id,
            'service_id': service_id,
            'region_id': 'RegionOne',
            'resource_name': 'cores',
            'resource_limit': 5
        }
        limit_table.insert().values(limit).execute()

        # Insert another one with the same project_id, service_id, region_id
        # and resource_name, then raise error.
        limit['id'] = uuid.uuid4().hex
        limit['resource_limit'] = 10
        self.assertRaises(db_exception.DBDuplicateEntry,
                          limit_table.insert().values(limit).execute)

        # Insert one without region_id
        limit_without_region = {
            'id': uuid.uuid4().hex,
            'project_id': project_id,
            'service_id': service_id,
            'resource_name': 'cores',
            'resource_limit': 5
        }
        limit_table.insert().values(limit_without_region).execute()

    def test_migration_034_adds_application_credential_table(self):
        self.expand(33)
        self.migrate(33)
        self.contract(33)

        application_credential_table_name = 'application_credential'
        self.assertTableDoesNotExist(application_credential_table_name)
        application_credential_role_table_name = 'application_credential_role'
        self.assertTableDoesNotExist(application_credential_role_table_name)

        self.expand(34)
        self.migrate(34)
        self.contract(34)

        self.assertTableExists(application_credential_table_name)
        self.assertTableColumns(
            application_credential_table_name,
            ['internal_id', 'id', 'name', 'secret_hash',
             'description', 'user_id', 'project_id', 'expires_at',
             'allow_application_credential_creation']
        )
        if self.engine.name == 'mysql':
            self.assertTrue(self.does_index_exist(
                'application_credential', 'duplicate_app_cred_constraint'))
        else:
            self.assertTrue(self.does_constraint_exist(
                'application_credential', 'duplicate_app_cred_constraint'))
        self.assertTableExists(application_credential_role_table_name)
        self.assertTableColumns(
            application_credential_role_table_name,
            ['application_credential_id', 'role_id']
        )

        app_cred_table = sqlalchemy.Table(
            application_credential_table_name, self.metadata, autoload=True
        )
        app_cred_role_table = sqlalchemy.Table(
            application_credential_role_table_name,
            self.metadata, autoload=True
        )
        self.assertTrue(self.does_fk_exist('application_credential_role',
                                           'application_credential_id'))

        expires_at = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)
        expires_at_int = (expires_at - epoch).total_seconds()
        app_cred = {
            'internal_id': 1,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'expires_at': expires_at_int,
            'allow_application_credential_creation': False
        }
        app_cred_table.insert().values(app_cred).execute()

        # Exercise unique constraint
        dup_app_cred = {
            'internal_id': 2,
            'id': uuid.uuid4().hex,
            'name': app_cred['name'],
            'secret_hash': uuid.uuid4().hex,
            'user_id': app_cred['user_id'],
            'project_id': uuid.uuid4().hex
        }
        insert = app_cred_table.insert().values(dup_app_cred)
        self.assertRaises(db_exception.DBDuplicateEntry,
                          insert.execute)

        role_rel = {
            'application_credential_id': app_cred['internal_id'],
            'role_id': uuid.uuid4().hex
        }
        app_cred_role_table.insert().values(role_rel).execute()

        # Exercise role table primary keys
        insert = app_cred_role_table.insert().values(role_rel)
        self.assertRaises(db_exception.DBDuplicateEntry, insert.execute)

    def test_migration_035_add_system_column_to_credential_table(self):
        self.expand(34)
        self.migrate(34)
        self.contract(34)

        application_credential_table_name = 'application_credential'
        self.assertTableExists(application_credential_table_name)
        self.assertTableColumns(
            application_credential_table_name,
            ['internal_id', 'id', 'name', 'secret_hash',
             'description', 'user_id', 'project_id', 'expires_at',
             'allow_application_credential_creation']
        )

        self.expand(35)
        self.migrate(35)
        self.contract(35)

        self.assertTableColumns(
            application_credential_table_name,
            ['internal_id', 'id', 'name', 'secret_hash',
             'description', 'user_id', 'project_id', 'system', 'expires_at',
             'allow_application_credential_creation']
        )

        application_credential_table = sqlalchemy.Table(
            application_credential_table_name, self.metadata, autoload=True
        )

        # Test that we can insert an application credential without project_id
        # defined.
        expires_at = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)
        expires_at_int = (expires_at - epoch).total_seconds()
        app_cred = {
            'internal_id': 1,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'system': uuid.uuid4().hex,
            'expires_at': expires_at_int,
            'allow_application_credential_creation': False
        }
        application_credential_table.insert().values(app_cred).execute()

        # Test that we can insert an application credential with a project_id
        # and without system defined.
        app_cred = {
            'internal_id': 2,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'expires_at': expires_at_int,
            'allow_application_credential_creation': False
        }
        application_credential_table.insert().values(app_cred).execute()

        # Test that we can create an application credential without a project
        # or a system defined. Technically, project_id and system should be
        # mutually exclusive, which will be handled by the application and not
        # the data layer.
        app_cred = {
            'internal_id': 3,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'expires_at': expires_at_int,
            'allow_application_credential_creation': False
        }
        application_credential_table.insert().values(app_cred).execute()

    def test_migration_036_rename_application_credentials_column(self):
        self.expand(35)
        self.migrate(35)
        self.contract(35)

        application_credential_table_name = 'application_credential'
        application_credential_role_table_name = 'application_credential_role'

        self.expand(36)
        self.migrate(36)
        self.contract(36)

        self.assertTableColumns(
            application_credential_table_name,
            ['internal_id', 'id', 'name', 'secret_hash',
             'description', 'user_id', 'project_id', 'system', 'expires_at',
             'unrestricted']
        )

        application_credential_table = sqlalchemy.Table(
            application_credential_table_name, self.metadata, autoload=True
        )
        app_cred_role_table = sqlalchemy.Table(
            application_credential_role_table_name,
            self.metadata, autoload=True
        )

        # Test that the new column works
        app_cred = {
            'internal_id': 1,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'system': uuid.uuid4().hex,
            'expires_at': None,
            'unrestricted': False
        }
        application_credential_table.insert().values(app_cred).execute()
        role_rel = {
            'application_credential_id': app_cred['internal_id'],
            'role_id': uuid.uuid4().hex
        }
        app_cred_role_table.insert().values(role_rel).execute()

    def test_migration_037_remove_service_and_region_fk_for_registered_limit(
            self):
        self.expand(37)
        self.migrate(37)
        self.contract(37)

        registered_limit_table_name = 'registered_limit'
        registered_limit_table = sqlalchemy.Table(registered_limit_table_name,
                                                  self.metadata, autoload=True)
        self.assertEqual(set([]), registered_limit_table.foreign_keys)

    def test_migration_045_add_description_to_limit(self):

        self.expand(44)
        self.migrate(44)
        self.contract(44)

        registered_limit_table_name = 'registered_limit'
        limit_table_name = 'limit'

        self.assertTableExists(registered_limit_table_name)
        self.assertTableExists(limit_table_name)
        self.assertTableColumns(
            registered_limit_table_name,
            ['id', 'service_id', 'region_id', 'resource_name', 'default_limit']
        )
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit']
        )

        self.expand(45)
        self.migrate(45)
        self.contract(45)

        registered_limit_table = sqlalchemy.Table(registered_limit_table_name,
                                                  self.metadata, autoload=True)
        limit_table = sqlalchemy.Table(limit_table_name,
                                       self.metadata, autoload=True)
        self.assertTableColumns(
            registered_limit_table_name,
            ['id', 'service_id', 'region_id', 'resource_name', 'default_limit',
             'description']
        )
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description']
        )

        session = self.sessionmaker()
        service_id = uuid.uuid4().hex
        service = {
            'id': service_id,
            'type': 'compute',
            'enabled': True
        }
        region = {
            'id': 'RegionOne',
            'description': 'test'
        }
        project_id = uuid.uuid4().hex
        project = {
            'id': project_id,
            'name': 'nova',
            'enabled': True,
            'domain_id': resource_base.NULL_DOMAIN_ID,
            'is_domain': False
        }
        self.insert_dict(session, 'service', service)
        self.insert_dict(session, 'region', region)
        self.insert_dict(session, 'project', project)

        # with description
        registered_limit = {
            'id': uuid.uuid4().hex,
            'service_id': service_id,
            'region_id': 'RegionOne',
            'resource_name': 'cores',
            'default_limit': 10,
            'description': 'this is a description'
        }
        registered_limit_table.insert().values(registered_limit).execute()

        # without description
        limit = {
            'id': uuid.uuid4().hex,
            'project_id': project_id,
            'service_id': service_id,
            'region_id': 'RegionOne',
            'resource_name': 'cores',
            'resource_limit': 5
        }
        limit_table.insert().values(limit).execute()

    def test_migration_046_copies_data_from_password_to_password_hash(self):
        self.expand(46)
        self.migrate(45)
        self.contract(45)
        # Create User and Local User
        project_table = sqlalchemy.Table('project', self.metadata,
                                         autoload=True)
        domain_data = {'id': '_domain', 'domain_id': '_domain',
                       'enabled': True, 'name': '_domain', 'is_domain': True}
        project_table.insert().values(domain_data).execute()
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        user_id = uuid.uuid4().hex
        user = {'id': user_id, 'enabled': True, 'domain_id': domain_data['id']}
        user_table.insert().values(user).execute()
        local_user_table = sqlalchemy.Table('local_user', self.metadata,
                                            autoload=True)
        local_user = {
            'id': 1, 'user_id': user_id, 'domain_id': user['domain_id'],
            'name': 'name'}

        local_user_table.insert().values(local_user).execute()

        password_table = sqlalchemy.Table('password',
                                          self.metadata, autoload=True)
        password_data = {
            'local_user_id': local_user['id'],
            'created_at': datetime.datetime.utcnow(),
            'expires_at': datetime.datetime.utcnow(),
            'password': uuid.uuid4().hex}
        password_data1 = {
            'local_user_id': local_user['id'],
            'created_at': datetime.datetime.utcnow(),
            'expires_at': datetime.datetime.utcnow(),
            'password_hash': uuid.uuid4().hex}
        password_data2 = {
            'local_user_id': local_user['id'],
            'created_at': datetime.datetime.utcnow(),
            'expires_at': datetime.datetime.utcnow(),
            'password': uuid.uuid4().hex,
            'password_hash': uuid.uuid4().hex}
        password_table.insert().values(password_data).execute()
        password_table.insert().values(password_data1).execute()
        password_table.insert().values(password_data2).execute()
        self.migrate(46)
        passwords = list(password_table.select().execute())
        for p in passwords:
            if p.password == password_data['password']:
                self.assertEqual(p.password_hash, p.password)
                self.assertIsNotNone(p.password)
                self.assertIsNotNone(p.password_hash)
            elif p.password_hash == password_data1['password_hash']:
                self.assertIsNone(p.password)
                self.assertIsNotNone(p.password_hash)
            elif p.password_hash == password_data2['password_hash']:
                self.assertIsNotNone(p.password)
                self.assertIsNotNone(p.password_hash)
                self.assertNotEqual(p.password, p.password_hash)
            else:
                raise ValueError('Too Many Passwords Found')

    def test_migration_047_add_auto_increment_pk_column_to_unified_limit(self):
        self.expand(46)
        self.migrate(46)
        self.contract(46)
        registered_limit_table_name = 'registered_limit'
        limit_table_name = 'limit'
        self.assertTableColumns(
            registered_limit_table_name,
            ['id', 'service_id', 'region_id', 'resource_name', 'default_limit',
             'description']
        )
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description']
        )
        self.assertTrue(self.does_pk_exist('registered_limit', 'id'))
        self.assertTrue(self.does_pk_exist('limit', 'id'))
        self.assertTrue(self.does_fk_exist('limit', 'project_id'))

        self.expand(47)
        self.migrate(47)
        self.contract(47)
        self.assertTableColumns(
            registered_limit_table_name,
            ['id', 'service_id', 'region_id', 'resource_name', 'default_limit',
             'description', 'internal_id']
        )
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description', 'internal_id']
        )
        self.assertFalse(self.does_pk_exist('registered_limit', 'id'))
        self.assertTrue(self.does_pk_exist('registered_limit', 'internal_id'))
        self.assertFalse(self.does_pk_exist('limit', 'id'))
        self.assertTrue(self.does_pk_exist('limit', 'internal_id'))
        limit_table = sqlalchemy.Table(limit_table_name,
                                       self.metadata, autoload=True)
        self.assertEqual(set([]), limit_table.foreign_keys)

    def test_migration_048_add_registered_limit_id_column_for_limit(self):
        self.expand(47)
        self.migrate(47)
        self.contract(47)

        limit_table_name = 'limit'
        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description', 'internal_id']
        )

        self.expand(48)
        self.migrate(48)
        self.contract(48)

        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description', 'internal_id',
             'registered_limit_id']
        )
        self.assertTrue(self.does_fk_exist('limit', 'registered_limit_id'))


class MySQLOpportunisticFullMigration(FullMigration):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticFullMigration(FullMigration):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture
