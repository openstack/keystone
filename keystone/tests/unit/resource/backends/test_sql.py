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

from keystone.resource.backends import sql
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.resource import test_backends


class TestSqlResourceDriver(unit.BaseTestCase,
                            test_backends.ResourceDriverTests):
    def setUp(self):
        super(TestSqlResourceDriver, self).setUp()
        self.useFixture(database.Database())
        self.driver = sql.Resource()
        root_domain = default_fixtures.ROOT_DOMAIN
        root_domain['domain_id'] = root_domain['id']
        root_domain['is_domain'] = True
        self.driver.create_project(root_domain['id'],
                                   root_domain)
