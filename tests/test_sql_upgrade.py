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

from migrate.versioning import api as versioning_api
import sqlalchemy

from keystone.common import sql
from keystone import config
from keystone import test
from keystone.common.sql import migration


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
        self.assertFalse(self.is_user_table_created(),
                         "User should not be defined yet")

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
        self.assertEqual(self.schema.version, 1, "DB is at version 0")
        self.assertTableColumns("user", ["id", "name", "extra"])
        self.assertTableColumns("tenant", ["id", "name", "extra"])
        self.assertTableColumns("role", ["id", "name"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def is_user_table_created(self):
        try:
            self.select_table("user")
            return True
        except sqlalchemy.exc.NoSuchTableError:
            return False

    def _migrate(self, repository, version):
        upgrade = True
        err = ""
        version = versioning_api._migrate_version(self.schema,
                                                  version,
                                                  upgrade,
                                                  err)
        changeset = self.schema.changeset(version)
        for ver, change in changeset:
            self.schema.runchange(ver, change, changeset.step)
