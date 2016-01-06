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

from keystone.tests.unit import test_backend_sql


class SqlIdentityV8(test_backend_sql.SqlIdentity):
    """Test that a V8 driver still passes the same tests.

    We use the SQL driver as an example of a V8 legacy driver.

    """

    def config_overrides(self):
        super(SqlIdentityV8, self).config_overrides()
        # V8 SQL specific driver overrides
        self.config_fixture.config(
            group='resource',
            driver='keystone.resource.V8_backends.sql.Resource')
        self.use_specific_sql_driver_version(
            'keystone.resource', 'backends', 'V8_')

    def test_delete_projects_from_ids(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')

    def test_delete_projects_from_ids_with_no_existing_project_id(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')

    def test_delete_project_cascade(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')

    def test_delete_large_project_cascade(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')

    def test_hidden_project_domain_root_is_really_hidden(self):
        self.skipTest('Operation not supported in v8 and earlier drivers')
