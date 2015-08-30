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

import sqlalchemy

from keystone.common import sql
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


class BaseBackendSqlTests(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        super(BaseBackendSqlTests, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        # defaulted by the data load
        self.user_foo['enabled'] = True

    def config_files(self):
        config_files = super(BaseBackendSqlTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files


class BaseBackendSqlModels(BaseBackendSqlTests):

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 sql.ModelBase.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertExpectedSchema(self, table, cols):
        table = self.select_table(table)
        for col, type_, length in cols:
            self.assertIsInstance(table.c[col].type, type_)
            if length:
                self.assertEqual(length, table.c[col].type.length)
