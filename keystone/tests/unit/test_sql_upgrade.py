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

    tox -e py39 -- keystone.tests.unit.test_sql_upgrade

For further information, see `oslo.db documentation
<https://docs.openstack.org/oslo.db/latest/contributor/index.html#how-to-run-unit-tests>`_.

.. warning::

    Your database will be wiped.

    Do not do this against a database with valuable data as
    all data will be lost.
"""

import datetime
import glob
import json
import os
import uuid

import fixtures
from migrate.versioning import script
from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
from oslo_log import fixture as log_fixture
from oslo_log import log
from oslo_serialization import jsonutils
from oslotest import base as test_base
import pytz
import sqlalchemy.exc
from sqlalchemy import inspect
from testtools import matchers

from keystone.cmd import cli
from keystone.common import sql
from keystone.common.sql import upgrades
from keystone.credential.providers import fernet as credential_fernet
from keystone.resource.backends import base as resource_base
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database


# NOTE(morganfainberg): This should be updated when each DB migration collapse
# is done to mirror the expected structure of the DB in the format of
# { <DB_TABLE_NAME>: [<COLUMN>, <COLUMN>, ...], ... }
INITIAL_TABLE_STRUCTURE = {
    'config_register': [
        'type', 'domain_id',
    ],
    'credential': [
        'id', 'user_id', 'project_id', 'type', 'extra', 'key_hash',
        'encrypted_blob',
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
        'parent_id', 'is_domain',
    ],
    'role': [
        'id', 'name', 'extra', 'domain_id',
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
        'id', 'extra', 'enabled', 'default_project_id', 'created_at',
        'last_active_at',
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
    'policy_association': [
        'id', 'policy_id', 'endpoint_id', 'service_id', 'region_id',
    ],
    'identity_provider': [
        'id', 'enabled', 'description',
    ],
    'federation_protocol': [
        'id', 'idp_id', 'mapping_id',
    ],
    'mapping': [
        'id', 'rules',
    ],
    'service_provider': [
        'auth_url', 'id', 'enabled', 'description', 'sp_url',
        'relay_state_prefix',
    ],
    'idp_remote_ids': [
        'idp_id', 'remote_id',
    ],
    'consumer': [
        'id', 'description', 'secret', 'extra',
    ],
    'request_token': [
        'id', 'request_secret', 'verifier', 'authorizing_user_id',
        'requested_project_id', 'role_ids', 'consumer_id', 'expires_at',
    ],
    'access_token': [
        'id', 'access_secret', 'authorizing_user_id', 'project_id', 'role_ids',
        'consumer_id', 'expires_at',
    ],
    'revocation_event': [
        'id', 'domain_id', 'project_id', 'user_id', 'role_id', 'trust_id',
        'consumer_id', 'access_token_id', 'issued_before', 'expires_at',
        'revoked_at', 'audit_id', 'audit_chain_id',
    ],
    'project_endpoint': [
        'endpoint_id', 'project_id'
    ],
    'endpoint_group': [
        'id', 'name', 'description', 'filters',
    ],
    'project_endpoint_group': [
        'endpoint_group_id', 'project_id',
    ],
    'implied_role': [
        'prior_role_id', 'implied_role_id',
    ],
    'local_user': [
        'id', 'user_id', 'domain_id', 'name', 'failed_auth_count',
        'failed_auth_at',
    ],
    'password': [
        'id', 'local_user_id', 'password', 'created_at', 'expires_at',
        'self_service',
    ],
    'federated_user': [
        'id', 'user_id', 'idp_id', 'protocol_id', 'unique_id', 'display_name',
    ],
    'nonlocal_user': [
        'domain_id', 'name', 'user_id',
    ],
}


class MigrateBase(
    db_fixtures.OpportunisticDBTestMixin,
    test_base.BaseTestCase,
):
    def setUp(self):
        super().setUp()

        self.useFixture(log_fixture.get_logging_handle_error_fixture())
        self.stdlog = self.useFixture(ksfixtures.StandardLogging())
        self.useFixture(ksfixtures.WarningsFixture())

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
            upgrades.EXPAND_REPO: upgrades.Repository(
                self.engine, upgrades.EXPAND_REPO,
            ),
            upgrades.DATA_MIGRATION_REPO: upgrades.Repository(
                self.engine, upgrades.DATA_MIGRATION_REPO,
            ),
            upgrades.CONTRACT_REPO: upgrades.Repository(
                self.engine, upgrades.CONTRACT_REPO,
            ),
        }

    def expand(self, *args, **kwargs):
        """Expand database schema."""
        self.repos[upgrades.EXPAND_REPO].upgrade(*args, **kwargs)

    def migrate(self, *args, **kwargs):
        """Migrate data."""
        self.repos[upgrades.DATA_MIGRATION_REPO].upgrade(*args, **kwargs)

    def contract(self, *args, **kwargs):
        """Contract database schema."""
        self.repos[upgrades.CONTRACT_REPO].upgrade(*args, **kwargs)

    @property
    def metadata(self):
        """A collection of tables and their associated schemas."""
        return sqlalchemy.MetaData(self.engine)

    def load_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        return table

    def assertTableExists(self, table_name):
        try:
            self.load_table(table_name)
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
        table = self.load_table(table_name)
        actual_cols = [col.name for col in table.columns]
        # Check if the columns are equal, but allow for a different order,
        # which might occur after an upgrade followed by a downgrade
        self.assertCountEqual(expected_cols, actual_cols,
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
        inspector = inspect(self.engine)
        pk_columns = inspector.get_pk_constraint(table)['constrained_columns']

        return pk_column in pk_columns

    def does_fk_exist(self, table, fk_column):
        inspector = inspect(self.engine)
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

    def does_unique_constraint_exist(self, table_name, column_names):
        inspector = inspect(self.engine)
        constraints = inspector.get_unique_constraints(table_name)
        for c in constraints:
            if (len(c['column_names']) == 1 and
                    column_names in c['column_names']):
                return True
            if (len(c['column_names'])) > 1 and isinstance(column_names, list):
                return set(c['column_names']) == set(column_names)
        return False


class ExpandSchemaUpgradeTests(MigrateBase):

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[upgrades.EXPAND_REPO].min_version,
            self.repos[upgrades.EXPAND_REPO].version)

    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_upgrade_add_initial_tables(self):
        self.expand(upgrades.INITIAL_VERSION + 1)
        self.check_initial_table_structure()

    def check_initial_table_structure(self):
        for table in INITIAL_TABLE_STRUCTURE:
            self.assertTableColumns(table, INITIAL_TABLE_STRUCTURE[table])


class MySQLOpportunisticExpandSchemaUpgradeTestCase(
    ExpandSchemaUpgradeTests,
):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticExpandSchemaUpgradeTestCase(
    ExpandSchemaUpgradeTests,
):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class DataMigrationUpgradeTests(MigrateBase):

    def setUp(self):
        # Make sure the expand repo is fully upgraded, since the data migration
        # phase is only run after this is upgraded
        super().setUp()
        self.expand()

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[upgrades.DATA_MIGRATION_REPO].min_version,
            self.repos[upgrades.DATA_MIGRATION_REPO].version,
        )


class MySQLOpportunisticDataMigrationUpgradeTestCase(
    DataMigrationUpgradeTests,
):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticDataMigrationUpgradeTestCase(
    DataMigrationUpgradeTests,
):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class ContractSchemaUpgradeTests(MigrateBase, unit.TestCase):

    def setUp(self):
        # Make sure the expand and data migration repos are fully
        # upgraded, since the contract phase is only run after these are
        # upgraded.
        super().setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )
        self.expand()
        self.migrate()

    def test_start_version_db_init_version(self):
        self.assertEqual(
            self.repos[upgrades.CONTRACT_REPO].min_version,
            self.repos[upgrades.CONTRACT_REPO].version,
        )


class MySQLOpportunisticContractSchemaUpgradeTestCase(
    ContractSchemaUpgradeTests,
):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticContractSchemaUpgradeTestCase(
    ContractSchemaUpgradeTests,
):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class VersionTests(MigrateBase):

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
            self.repos[upgrades.EXPAND_REPO].max_version,
            self.repos[upgrades.DATA_MIGRATION_REPO].max_version,
        )
        self.assertEqual(
            self.repos[upgrades.DATA_MIGRATION_REPO].max_version,
            self.repos[upgrades.CONTRACT_REPO].max_version,
        )

    def test_migrate_repos_file_names_have_prefix(self):
        """Migration files should be unique to avoid caching errors.

        This test enforces migration files to include a prefix (expand,
        migrate, contract) in order to keep them unique. Here is the required
        format: [version]_[prefix]_[description]. For example:
        001_expand_add_created_column.py

        """
        versions_path = '/versions'

        # test for expand prefix, e.g. 001_expand_new_fk_constraint.py
        repo_path = self.repos[upgrades.EXPAND_REPO].repo_path
        expand_list = glob.glob(repo_path + versions_path + '/*.py')
        self.assertRepoFileNamePrefix(expand_list, 'expand')

        # test for migrate prefix, e.g. 001_migrate_new_fk_constraint.py
        repo_path = self.repos[upgrades.DATA_MIGRATION_REPO].repo_path
        migrate_list = glob.glob(repo_path + versions_path + '/*.py')
        self.assertRepoFileNamePrefix(migrate_list, 'migrate')

        # test for contract prefix, e.g. 001_contract_new_fk_constraint.py
        repo_path = self.repos[upgrades.CONTRACT_REPO].repo_path
        contract_list = glob.glob(repo_path + versions_path + '/*.py')
        self.assertRepoFileNamePrefix(contract_list, 'contract')

    def assertRepoFileNamePrefix(self, repo_list, prefix):
        if len(repo_list) > 1:
            # grab the file name for the max version
            file_name = os.path.basename(sorted(repo_list)[-2])
            # pattern for the prefix standard, ignoring placeholder, init files
            pattern = (
                '^[0-9]{3,}_PREFIX_|^[0-9]{3,}_placeholder.py|^__init__.py')
            pattern = pattern.replace('PREFIX', prefix)
            msg = 'Missing required prefix %s in $file_name' % prefix
            self.assertRegex(file_name, pattern, msg)


class MigrationValidation(MigrateBase, unit.TestCase):
    """Test validation of database between database phases."""

    def _set_db_sync_command_versions(self):
        self.expand(upgrades.INITIAL_VERSION + 1)
        self.migrate(upgrades.INITIAL_VERSION + 1)
        self.contract(upgrades.INITIAL_VERSION + 1)
        for version in (
            upgrades.get_db_version('expand_repo'),
            upgrades.get_db_version('data_migration_repo'),
            upgrades.get_db_version('contract_repo'),
        ):
            self.assertEqual(upgrades.INITIAL_VERSION + 1, version)

    def test_running_db_sync_migrate_ahead_of_expand_fails(self):
        self._set_db_sync_command_versions()
        self.assertRaises(
            db_exception.DBMigrationError,
            self.migrate,
            upgrades.INITIAL_VERSION + 2,
            "You are attempting to upgrade migrate ahead of expand",
        )

    def test_running_db_sync_contract_ahead_of_migrate_fails(self):
        self._set_db_sync_command_versions()
        self.assertRaises(
            db_exception.DBMigrationError,
            self.contract,
            upgrades.INITIAL_VERSION + 2,
            "You are attempting to upgrade contract ahead of migrate",
        )


class FullMigration(MigrateBase, unit.TestCase):
    """Test complete orchestration between all database phases."""

    def test_db_sync_check(self):
        checker = cli.DbSync()
        latest_version = self.repos[upgrades.EXPAND_REPO].max_version

        # If the expand repository doesn't exist yet, then we need to make sure
        # we advertise that `--expand` must be run first.
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --expand", log_info.output)
        self.assertEqual(status, 2)

        # Assert the correct message is printed when expand is the first step
        # that needs to run
        self.expand(upgrades.INITIAL_VERSION + 1)
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
        self.expand(upgrades.INITIAL_VERSION + 1)
        self.migrate(upgrades.INITIAL_VERSION + 1)
        self.assertRaises(
            db_exception.DBMigrationError,
            self.contract,
            upgrades.INITIAL_VERSION + 2,
        )

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

    def test_migration_030_expand_add_project_tags_table(self):
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

    def test_migration_053_adds_description_to_role(self):
        self.expand(52)
        self.migrate(52)
        self.contract(52)

        role_table_name = 'role'
        self.assertTableColumns(
            role_table_name,
            ['id', 'name', 'domain_id', 'extra']
        )

        self.expand(53)
        self.migrate(53)
        self.contract(53)

        self.assertTableColumns(
            role_table_name,
            ['id', 'name', 'domain_id', 'extra', 'description']
        )

        role_table = sqlalchemy.Table(
            role_table_name, self.metadata, autoload=True
        )

        role = {
            'id': uuid.uuid4().hex,
            'name': "test",
            'domain_id': resource_base.NULL_DOMAIN_ID,
            'description': "This is a string"
        }
        role_table.insert().values(role).execute()

        role_without_description = {
            'id': uuid.uuid4().hex,
            'name': "test1",
            'domain_id': resource_base.NULL_DOMAIN_ID
        }
        role_table.insert().values(role_without_description).execute()

    def test_migration_054_drop_old_password_column(self):
        self.expand(53)
        self.migrate(53)
        self.contract(53)

        password_table = 'password'
        self.assertTableColumns(
            password_table,
            ['id', 'local_user_id', 'password', 'password_hash',
             'self_service', 'created_at_int', 'created_at', 'expires_at_int',
             'expires_at']
        )

        self.expand(54)
        self.migrate(54)
        self.contract(54)

        self.assertTableColumns(
            password_table,
            ['id', 'local_user_id', 'password_hash', 'self_service',
             'created_at_int', 'created_at', 'expires_at_int', 'expires_at']
        )

    def test_migration_055_add_domain_to_limit(self):
        self.expand(54)
        self.migrate(54)
        self.contract(54)

        limit_table_name = 'limit'
        limit_table = sqlalchemy.Table(limit_table_name, self.metadata,
                                       autoload=True)
        self.assertFalse(hasattr(limit_table.c, 'domain_id'))

        self.expand(55)
        self.migrate(55)
        self.contract(55)

        self.assertTableColumns(
            limit_table_name,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description', 'internal_id',
             'registered_limit_id', 'domain_id'])
        self.assertTrue(limit_table.c.project_id.nullable)

    def test_migration_056_add_application_credential_access_rules(self):
        self.expand(55)
        self.migrate(55)
        self.contract(55)

        self.assertTableDoesNotExist('access_rule')
        self.assertTableDoesNotExist('application_credential_access_rule')

        self.expand(56)
        self.migrate(56)
        self.contract(56)

        self.assertTableExists('access_rule')
        self.assertTableExists('application_credential_access_rule')
        self.assertTableColumns(
            'access_rule',
            ['id', 'service', 'path', 'method']
        )
        self.assertTableColumns(
            'application_credential_access_rule',
            ['application_credential_id', 'access_rule_id']
        )
        self.assertTrue(self.does_fk_exist(
            'application_credential_access_rule', 'application_credential_id'))
        self.assertTrue(self.does_fk_exist(
            'application_credential_access_rule', 'access_rule_id'))

        app_cred_table = sqlalchemy.Table(
            'application_credential', self.metadata, autoload=True
        )
        access_rule_table = sqlalchemy.Table(
            'access_rule', self.metadata, autoload=True
        )
        app_cred_access_rule_table = sqlalchemy.Table(
            'application_credential_access_rule',
            self.metadata, autoload=True
        )
        app_cred = {
            'internal_id': 1,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'secret_hash': uuid.uuid4().hex,
            'user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex
        }
        app_cred_table.insert().values(app_cred).execute()
        access_rule = {
            'id': 1,
            'service': uuid.uuid4().hex,
            'path': '/v2.1/servers',
            'method': 'GET'
        }
        access_rule_table.insert().values(access_rule).execute()
        app_cred_access_rule_rel = {
            'application_credential_id': app_cred['internal_id'],
            'access_rule_id': access_rule['id']
        }
        app_cred_access_rule_table.insert().values(
            app_cred_access_rule_rel).execute()

    def test_migration_062_add_trust_redelegation(self):
        # ensure initial schema
        self.expand(61)
        self.migrate(61)
        self.contract(61)
        self.assertTableColumns('trust', ['id',
                                          'trustor_user_id',
                                          'trustee_user_id',
                                          'project_id',
                                          'impersonation',
                                          'expires_at',
                                          'expires_at_int',
                                          'remaining_uses',
                                          'deleted_at',
                                          'extra'])

        # fixture
        trust = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': True,
            'expires_at': datetime.datetime.now(),
            'remaining_uses': 10,
            'deleted_at': datetime.datetime.now(),
            'redelegated_trust_id': uuid.uuid4().hex,
            'redelegation_count': 3,
            'other': uuid.uuid4().hex
        }
        old_trust = trust.copy()
        old_extra = {
            'redelegated_trust_id': old_trust.pop('redelegated_trust_id'),
            'redelegation_count': old_trust.pop('redelegation_count'),
            'other': old_trust.pop('other')
        }
        old_trust['extra'] = jsonutils.dumps(old_extra)
        # load fixture
        session = self.sessionmaker()
        self.insert_dict(session, 'trust', old_trust)

        # ensure redelegation data is in extra
        stored_trust = list(
            session.execute(self.load_table('trust').select())
        )[0]
        self.assertDictEqual({
            'redelegated_trust_id': trust['redelegated_trust_id'],
            'redelegation_count': trust['redelegation_count'],
            'other': trust['other']},
            jsonutils.loads(stored_trust.extra))

        # upgrade and ensure expected schema
        self.expand(62)
        self.migrate(62)
        self.contract(62)
        self.assertTableColumns('trust', ['id',
                                          'trustor_user_id',
                                          'trustee_user_id',
                                          'project_id',
                                          'impersonation',
                                          'expires_at',
                                          'expires_at_int',
                                          'remaining_uses',
                                          'deleted_at',
                                          'redelegated_trust_id',
                                          'redelegation_count',
                                          'extra'])

        trust_table = sqlalchemy.Table('trust', self.metadata, autoload=True)
        self.assertTrue(trust_table.c.redelegated_trust_id.nullable)
        self.assertTrue(trust_table.c.redelegation_count.nullable)

        # test target data layout
        upgraded_trust = list(
            session.execute(self.load_table('trust').select())
        )[0]
        self.assertDictEqual({'other': trust['other']},
                             jsonutils.loads(upgraded_trust.extra))
        self.assertEqual(trust['redelegated_trust_id'],
                         upgraded_trust.redelegated_trust_id)
        self.assertEqual(trust['redelegation_count'],
                         upgraded_trust.redelegation_count)

    def test_migration_063_drop_limit_columns(self):
        self.expand(62)
        self.migrate(62)
        self.contract(62)

        limit_table = 'limit'
        self.assertTableColumns(
            limit_table,
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description', 'internal_id',
             'registered_limit_id', 'domain_id'])

        self.expand(63)
        self.migrate(63)
        self.contract(63)

        self.assertTableColumns(
            limit_table,
            ['id', 'project_id', 'resource_limit', 'description',
             'internal_id', 'registered_limit_id', 'domain_id'])

    def test_migration_064_add_remote_id_attribute_federation_protocol(self):
        self.expand(63)
        self.migrate(63)
        self.contract(63)

        federation_protocol_table_name = 'federation_protocol'
        self.assertTableColumns(
            federation_protocol_table_name,
            ['id', 'idp_id', 'mapping_id']
        )

        self.expand(64)
        self.migrate(64)
        self.contract(64)

        self.assertTableColumns(
            federation_protocol_table_name,
            ['id', 'idp_id', 'mapping_id', 'remote_id_attribute']
        )

    def test_migration_065_add_user_external_id_to_access_rule(self):
        self.expand(64)
        self.migrate(64)
        self.contract(64)

        self.assertTableColumns(
            'access_rule',
            ['id', 'service', 'path', 'method']
        )

        self.expand(65)
        self.migrate(65)
        self.contract(65)

        self.assertTableColumns(
            'access_rule',
            ['id', 'external_id', 'user_id', 'service', 'path', 'method']
        )
        self.assertTrue(self.does_index_exist('access_rule', 'external_id'))
        self.assertTrue(self.does_index_exist('access_rule', 'user_id'))
        self.assertTrue(self.does_unique_constraint_exist(
            'access_rule', 'external_id'))
        self.assertTrue(self.does_unique_constraint_exist(
            'access_rule', ['user_id', 'service', 'path', 'method']))

    def test_migration_066_add_role_and_project_options_tables(self):
        self.expand(65)
        self.migrate(65)
        self.contract(65)

        role_option = 'role_option'
        project_option = 'project_option'
        self.assertTableDoesNotExist(role_option)
        self.assertTableDoesNotExist(project_option)

        self.expand(66)
        self.migrate(66)
        self.contract(66)

        self.assertTableColumns(
            project_option,
            ['project_id', 'option_id', 'option_value'])

        self.assertTableColumns(
            role_option,
            ['role_id', 'option_id', 'option_value'])

    def test_migration_072_drop_domain_id_fk(self):
        self.expand(71)
        self.migrate(71)
        self.contract(71)

        self.assertTrue(self.does_fk_exist('user', 'domain_id'))
        self.assertTrue(self.does_fk_exist('identity_provider', 'domain_id'))

        self.expand(72)
        self.migrate(72)
        self.contract(72)

        self.assertFalse(self.does_fk_exist('user', 'domain_id'))
        self.assertFalse(self.does_fk_exist('identity_provider', 'domain_id'))

    def test_migration_073_contract_expiring_group_membership(self):
        self.expand(72)
        self.migrate(72)
        self.contract(72)

        membership_table = 'expiring_user_group_membership'
        self.assertTableDoesNotExist(membership_table)

        idp_table = 'identity_provider'
        self.assertTableColumns(
            idp_table,
            ['id', 'domain_id', 'enabled', 'description'])

        self.expand(73)
        self.migrate(73)
        self.contract(73)

        self.assertTableColumns(
            membership_table,
            ['user_id', 'group_id', 'idp_id', 'last_verified'])
        self.assertTableColumns(
            idp_table,
            ['id', 'domain_id', 'enabled', 'description',
             'authorization_ttl'])

    def test_migration_079_expand_update_local_id_limit(self):
        self.expand(78)
        self.migrate(78)
        self.contract(78)

        id_mapping_table = sqlalchemy.Table('id_mapping',
                                            self.metadata, autoload=True)
        # assert local_id column is a string of 64 characters (before)
        self.assertEqual('VARCHAR(64)', str(id_mapping_table.c.local_id.type))

        self.expand(79)
        self.migrate(79)
        self.contract(79)

        id_mapping_table = sqlalchemy.Table('id_mapping',
                                            self.metadata, autoload=True)
        # assert local_id column is a string of 255 characters (after)
        self.assertEqual('VARCHAR(255)', str(id_mapping_table.c.local_id.type))


class MySQLOpportunisticFullMigration(FullMigration):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture

    def test_migration_012_add_domain_id_to_idp(self):
        self.skip_test_overrides('skipped to update u-c for PyMySql version'
                                 'to 0.10.0')


class PostgreSQLOpportunisticFullMigration(FullMigration):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture
