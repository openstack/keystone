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
from keystone.policy.backends import sql as sql_driver
from keystone.tests import unit
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.policy.backends import test_base


class SQLModelTestCase(core_sql.BaseBackendSqlModels):
    """Test cases to validate the table structure."""

    def test_policy_model(self):
        cols = (('id', sql.String, 64),
                ('blob', sql.JsonBlob, None),
                ('type', sql.String, 255),
                ('extra', sql.JsonBlob, None))

        self.assertExpectedSchema('policy', cols)


class SQLDriverTestCase(test_base.DriverTestCase, unit.TestCase):

    def setUp(self):
        # Load database first since parent's setUp will use it
        self.useFixture(database.Database())
        super(SQLDriverTestCase, self).setUp()

    @property
    def driver(self):
        if not hasattr(self, '_driver'):
            self._driver = sql_driver.Policy()
        return self._driver
