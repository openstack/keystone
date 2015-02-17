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

import uuid

from keystone.common import sql
from keystone import exception
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.backend.role import core


class SqlRoleModels(core_sql.BaseBackendSqlModels):

    def test_role_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 255))
        self.assertExpectedSchema('role', cols)


class SqlRole(core_sql.BaseBackendSqlTests, core.RoleTests):

    def test_create_null_role_name(self):
        role = {'id': uuid.uuid4().hex,
                'name': None}
        self.assertRaises(exception.UnexpectedError,
                          self.role_api.create_role,
                          role['id'],
                          role)
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role['id'])
