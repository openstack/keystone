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

from keystone.application_credential.backends import sql as sql_driver
from keystone.common import provider_api
from keystone.common import sql
from keystone.tests.unit.application_credential import test_backends
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.ksfixtures import database


PROVIDERS = provider_api.ProviderAPIs


class SQLModelTestCase(core_sql.BaseBackendSqlModels):
    def test_application_credential_model(self):
        cols = (('internal_id', sql.Integer, None),
                ('id', sql.String, 64),
                ('name', sql.String, 255),
                ('secret_hash', sql.String, 255),
                ('description', sql.Text, None),
                ('user_id', sql.String, 64),
                ('project_id', sql.String, 64),
                ('system', sql.String, 64),
                ('expires_at', sql.DateTimeInt, None))
        self.assertExpectedSchema('application_credential', cols)

    def test_application_credential_role_model(self):
        cols = (('application_credential_id', sql.Integer, None),
                ('role_id', sql.String, 64))
        self.assertExpectedSchema('application_credential_role', cols)

    def test_access_rule_model(self):
        cols = (('id', sql.Integer, None),
                ('external_id', sql.String, 64),
                ('user_id', sql.String, 64),
                ('service', sql.String, 64),
                ('path', sql.String, 128),
                ('method', sql.String, 16))
        self.assertExpectedSchema('access_rule', cols)

    def test_application_credential_access_rule_model(self):
        cols = (('application_credential_id', sql.Integer, None),
                ('access_rule_id', sql.Integer, None))
        self.assertExpectedSchema('application_credential_access_rule', cols)


class SQLDriverTestCase(core_sql.BaseBackendSqlTests,
                        test_backends.ApplicationCredentialTests):
    def setUp(self):
        self.useFixture(database.Database())
        self.driver = sql_driver.ApplicationCredential()
        super(SQLDriverTestCase, self).setUp()

        self.app_cred_api = PROVIDERS.application_credential_api
