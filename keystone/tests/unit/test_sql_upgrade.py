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

import fixtures
from migrate.versioning import script
from oslo_db import options as db_options
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
from oslo_log import fixture as log_fixture
from oslo_log import log
import sqlalchemy.exc

from keystone.cmd import cli
from keystone.common import sql
from keystone.common.sql import upgrades
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF

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
    'project_option': [
        'project_id', 'option_id', 'option_value',
    ],
    'project_tag': [
        'project_id', 'name',
    ],
    'role': [
        'id', 'name', 'extra', 'domain_id', 'description',
    ],
    'role_option': [
        'role_id', 'option_id', 'option_value',
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
        'expires_at_int', 'redelegated_trust_id', 'redelegation_count',
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
        'id', 'enabled', 'description', 'domain_id', 'authorization_ttl',
    ],
    'federation_protocol': [
        'id', 'idp_id', 'mapping_id', 'remote_id_attribute',
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
        'id', 'local_user_id', 'created_at', 'expires_at',
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
        'internal_id', 'id', 'project_id', 'resource_limit', 'description',
        'registered_limit_id', 'domain_id',
    ],
    'application_credential': [
        'internal_id', 'id', 'name', 'secret_hash', 'description', 'user_id',
        'project_id', 'expires_at', 'system', 'unrestricted',
    ],
    'application_credential_role': [
        'application_credential_id', 'role_id',
    ],
    'access_rule': [
        'id', 'service', 'path', 'method', 'external_id', 'user_id',
    ],
    'application_credential_access_rule': [
        'application_credential_id', 'access_rule_id',
    ],
    'expiring_user_group_membership': [
        'user_id', 'group_id', 'idp_id', 'last_verified',
    ],
}


class MigrateBase(
    db_fixtures.OpportunisticDBTestMixin,
):
    """Test complete orchestration between all database phases."""
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

        db_options.set_defaults(CONF, connection=self.engine.url)

        # Override keystone's context manager to be oslo.db's global context
        # manager.
        sql.core._TESTING_USE_GLOBAL_CONTEXT_MANAGER = True
        self.addCleanup(setattr,
                        sql.core, '_TESTING_USE_GLOBAL_CONTEXT_MANAGER', False)
        self.addCleanup(sql.cleanup)

    def expand(self):
        """Expand database schema."""
        upgrades.expand_schema(engine=self.engine)

    def contract(self):
        """Contract database schema."""
        upgrades.contract_schema(engine=self.engine)

    @property
    def metadata(self):
        """A collection of tables and their associated schemas."""
        return sqlalchemy.MetaData(self.engine)

    def load_table(self, name):
        table = sqlalchemy.Table(
            name, self.metadata, autoload_with=self.engine,
        )
        return table

    def assertTableDoesNotExist(self, table_name):
        """Assert that a given table exists cannot be selected by name."""
        # Switch to a different metadata otherwise you might still
        # detect renamed or dropped tables
        try:
            sqlalchemy.Table(
                table_name, self.metadata, autoload_with=self.engine,
            )
        except sqlalchemy.exc.NoSuchTableError:
            pass
        else:
            raise AssertionError('Table "%s" already exists' % table_name)

    def assertTableColumns(self, table_name, expected_cols):
        """Assert that the table contains the expected set of columns."""
        table = self.load_table(table_name)
        actual_cols = [col.name for col in table.columns]
        # Check if the columns are equal, but allow for a different order,
        # which might occur after an upgrade followed by a downgrade
        self.assertCountEqual(expected_cols, actual_cols,
                              '%s table' % table_name)

    def test_db_sync_check(self):
        checker = cli.DbSync()

        # If the expand repository doesn't exist yet, then we need to make sure
        # we advertise that `--expand` must be run first.
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --expand", log_info.output)
        self.assertEqual(status, 2)

        # Assert the correct message is printed when migrate is ahead of
        # contract
        self.expand()
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("keystone-manage db_sync --contract", log_info.output)
        self.assertEqual(status, 4)

        # Assert the correct message gets printed when all commands are on
        # the same version
        self.contract()
        log_info = self.useFixture(fixtures.FakeLogger(level=log.INFO))
        status = checker.check_db_sync_status()
        self.assertIn("All db_sync commands are upgraded", log_info.output)
        self.assertEqual(status, 0)

    def test_upgrade_add_initial_tables(self):
        self.expand()
        for table in INITIAL_TABLE_STRUCTURE:
            self.assertTableColumns(table, INITIAL_TABLE_STRUCTURE[table])


class FullMigrationSQLite(MigrateBase, unit.TestCase):
    pass


class FullMigrationMySQL(MigrateBase, unit.TestCase):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class FullMigrationPostgreSQL(MigrateBase, unit.TestCase):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture
