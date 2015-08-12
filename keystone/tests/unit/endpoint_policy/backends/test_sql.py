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

from keystone.common import sql
from keystone.endpoint_policy.backends import sql as sql_driver
from keystone.tests import unit
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.endpoint_policy.backends import test_base
from keystone.tests.unit.ksfixtures import database


class SQLModelTestCase(core_sql.BaseBackendSqlModels):
    """Test cases to validate the table structure."""

    def test_policy_association_model(self):
        cols = (('id', sql.String, 64),
                ('policy_id', sql.String, 64),
                ('endpoint_id', sql.String, 64),
                ('service_id', sql.String, 64),
                ('region_id', sql.String, 64))

        self.assertExpectedSchema('policy_association', cols)


class SQLDriverTestCase(test_base.DriverTestCase, unit.TestCase):

    def setUp(self):
        super(SQLDriverTestCase, self).setUp()
        self.useFixture(database.Database())
        self._driver = sql_driver.EndpointPolicy()

    @property
    def driver(self):
        return self._driver
