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
import sqlalchemy.exc
from sqlalchemy import inspect

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
    'project_tag': [
        'project_id', 'name',
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
        'expires_at_int',
    ],
    'trust_role': [
        'trust_id', 'role_id',
    ],
    'user': [
        'id', 'extra', 'enabled', 'default_project_id', 'created_at',
        'last_active_at', 'domain_id',
    ],
    'user_option': [
        'user_id', 'option_id', 'option_value',
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
        'id', 'enabled', 'description', 'domain_id',
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
        'self_service', 'password_hash', 'created_at_int', 'expires_at_int',
    ],
    'federated_user': [
        'id', 'user_id', 'idp_id', 'protocol_id', 'unique_id', 'display_name',
    ],
    'nonlocal_user': [
        'domain_id', 'name', 'user_id',
    ],
    'system_assignment': [
        'type', 'actor_id', 'target_id', 'role_id', 'inherited',
    ],
    'registered_limit': [
        'internal_id', 'id', 'service_id', 'region_id', 'resource_name',
        'default_limit', 'description',
    ],
    'limit': [
        'internal_id', 'id', 'project_id', 'service_id', 'region_id',
        'resource_name', 'resource_limit', 'description',
        'registered_limit_id',
    ],
    'application_credential': [
        'internal_id', 'id', 'name', 'secret_hash', 'description', 'user_id',
        'project_id', 'expires_at', 'system', 'unrestricted',
    ],
    'application_credential_role': [
        'application_credential_id', 'role_id',
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


class PostgreSQLOpportunisticFullMigration(FullMigration):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture
