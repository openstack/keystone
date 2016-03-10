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
from keystone.resource.config_backends import sql as config_sql
from keystone.tests import unit
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.resource import test_core


class SqlDomainConfigModels(core_sql.BaseBackendSqlModels):

    def test_whitelisted_model(self):
        cols = (('domain_id', sql.String, 64),
                ('group', sql.String, 255),
                ('option', sql.String, 255),
                ('value', sql.JsonBlob, None))
        self.assertExpectedSchema('whitelisted_config', cols)

    def test_sensitive_model(self):
        cols = (('domain_id', sql.String, 64),
                ('group', sql.String, 255),
                ('option', sql.String, 255),
                ('value', sql.JsonBlob, None))
        self.assertExpectedSchema('sensitive_config', cols)


class SqlDomainConfigDriver(unit.BaseTestCase,
                            test_core.DomainConfigDriverTests):
    def setUp(self):
        super(SqlDomainConfigDriver, self).setUp()
        self.useFixture(database.Database())
        self.driver = config_sql.DomainConfig()


class SqlDomainConfig(core_sql.BaseBackendSqlTests,
                      test_core.DomainConfigTests):
    def setUp(self):
        super(SqlDomainConfig, self).setUp()
        # test_core.DomainConfigTests is effectively a mixin class, so make
        # sure we call its setup
        test_core.DomainConfigTests.setUp(self)
