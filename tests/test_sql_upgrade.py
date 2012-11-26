# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import copy
import json

from migrate.versioning import api as versioning_api
import sqlalchemy
from sqlalchemy.orm import sessionmaker

from keystone.common import sql
from keystone import config
from keystone import test
from keystone.common.sql import migration
import default_fixtures

CONF = config.CONF


class SqlUpgradeTests(test.TestCase):
    def setUp(self):
        super(SqlUpgradeTests, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])

        # create and share a single sqlalchemy engine for testing
        self.engine = sql.Base().get_engine(allow_global_engine=False)
        self.metadata = sqlalchemy.MetaData()

        # populate the engine with tables & fixtures
        self.metadata.bind = self.engine
        self.repo_path = migration._find_migrate_repo()
        self.schema = versioning_api.ControlledSchema.create(self.engine,
                                                             self.repo_path, 0)

    def tearDown(self):
        super(SqlUpgradeTests, self).tearDown()

    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_start_version_0(self):
        version = migration.db_version()
        self.assertEqual(version, 0, "DB is at version 0")

    def assertTableColumns(self, table_name, expected_cols):
        """Asserts that the table contains the expected set of columns."""
        table = self.select_table(table_name)
        actual_cols = [col.name for col in table.columns]
        self.assertEqual(expected_cols, actual_cols, '%s table' % table_name)

    def test_upgrade_0_to_1(self):
        self.assertEqual(self.schema.version, 0, "DB is at version 0")
        self._migrate(self.repo_path, 1)
        self.assertEqual(self.schema.version, 1, "DB is at version 1")
        self.assertTableColumns("user", ["id", "name", "extra"])
        self.assertTableColumns("tenant", ["id", "name", "extra"])
        self.assertTableColumns("role", ["id", "name"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])
        self.populate_user_table()

    def test_upgrade_5_to_6(self):
        self._migrate(self.repo_path, 5)
        self.assertEqual(self.schema.version, 5)
        self.assertTableDoesNotExist('policy')

        self._migrate(self.repo_path, 6)
        self.assertEqual(self.schema.version, 6)
        self.assertTableExists('policy')
        self.assertTableColumns('policy', ['id', 'type', 'blob', 'extra'])

    def test_upgrade_7_to_9(self):

        self.assertEqual(self.schema.version, 0)
        self._migrate(self.repo_path, 7)
        self.populate_user_table()
        self.populate_tenant_table()
        self._migrate(self.repo_path, 9)
        self.assertEqual(self.schema.version, 9)
        self.assertTableColumns("user",
                                ["id", "name", "extra", "password",
                                 "enabled"])
        self.assertTableColumns("tenant",
                                ["id", "name", "extra", "description",
                                 "enabled"])
        self.assertTableColumns("role", ["id", "name", "extra"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])
        maker = sessionmaker(bind=self.engine)
        session = maker()
        user_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        a_user = session.query(user_table).filter("id='foo'").one()
        self.assertTrue(a_user.enabled)
        a_user = session.query(user_table).filter("id='badguy'").one()
        self.assertFalse(a_user.enabled)
        tenant_table = sqlalchemy.Table("tenant",
                                        self.metadata,
                                        autoload=True)
        a_tenant = session.query(tenant_table).filter("id='baz'").one()
        self.assertEqual(a_tenant.description, 'description')
        session.commit()

    def test_downgrade_9_to_7(self):
        self.assertEqual(self.schema.version, 0)
        self._migrate(self.repo_path, 9)
        self._migrate(self.repo_path, 7, False)

    def test_downgrade_to_0(self):
        self._migrate(self.repo_path, 9)
        self._migrate(self.repo_path, 0, False)
        for table_name in ["user", "token", "role", "user_tenant_membership",
                           "metadata"]:
            self.assertTableDoesNotExist(table_name)

    def test_upgrade_6_to_7(self):
        self._migrate(self.repo_path, 6)
        self.assertEqual(self.schema.version, 6, "DB is at version 6")
        self.assertTableDoesNotExist('credential')
        self.assertTableDoesNotExist('domain')
        self.assertTableDoesNotExist('user_domain_metadata')
        self._migrate(self.repo_path, 7)
        self.assertEqual(self.schema.version, 7, "DB is at version 7")
        self.assertTableExists('credential')
        self.assertTableColumns('credential', ['id', 'user_id', 'project_id',
                                               'blob', 'type', 'extra'])
        self.assertTableExists('domain')
        self.assertTableColumns('domain', ['id', 'name', 'extra'])
        self.assertTableExists('user_domain_metadata')
        self.assertTableColumns('user_domain_metadata',
                                ['user_id', 'domain_id', 'data'])

    def populate_user_table(self):
        for user in default_fixtures.USERS:
            extra = copy.deepcopy(user)
            extra.pop('id')
            extra.pop('name')
            self.engine.execute("insert into user values ('%s', '%s', '%s')"
                                % (user['id'],
                                   user['name'],
                                   json.dumps(extra)))

    def populate_tenant_table(self):
        for tenant in default_fixtures.TENANTS:
            extra = copy.deepcopy(tenant)
            extra.pop('id')
            extra.pop('name')
            self.engine.execute("insert into tenant values ('%s', '%s', '%s')"
                                % (tenant['id'],
                                   tenant['name'],
                                   json.dumps(extra)))

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertTableExists(self, table_name):
        """Asserts that a given table exists can be selected by name."""
        try:
            self.select_table(table_name)
        except sqlalchemy.exc.NoSuchTableError:
            raise AssertionError('Table "%s" does not exist' % table_name)

    def assertTableDoesNotExist(self, table_name):
        """Asserts that a given table exists cannot be selected by name."""
        try:
            self.assertTableExists(table_name)
        except AssertionError:
            pass
        else:
            raise AssertionError('Table "%s" already exists' % table_name)

    def _migrate(self, repository, version, upgrade=True):
        err = ""
        version = versioning_api._migrate_version(self.schema,
                                                  version,
                                                  upgrade,
                                                  err)
        changeset = self.schema.changeset(version)
        for ver, change in changeset:
            self.schema.runchange(ver, change, changeset.step)
