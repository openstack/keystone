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

from keystone.common import provider_api
from keystone.common import sql
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.assignment import test_core
from keystone.tests.unit.backend import core_sql

PROVIDERS = provider_api.ProviderAPIs


class SqlRoleModels(core_sql.BaseBackendSqlModels):

    def test_role_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 255),
                ('domain_id', sql.String, 64))
        self.assertExpectedSchema('role', cols)


class SqlRole(core_sql.BaseBackendSqlTests, test_core.RoleTests):

    def test_create_null_role_name(self):
        role = unit.new_role_ref(name=None)
        self.assertRaises(exception.UnexpectedError,
                          PROVIDERS.role_api.create_role,
                          role['id'],
                          role)
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          role['id'])

    def test_create_duplicate_role_domain_specific_name_fails(self):
        domain = unit.new_domain_ref()
        role1 = unit.new_role_ref(domain_id=domain['id'])
        PROVIDERS.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref(name=role1['name'],
                                  domain_id=domain['id'])
        self.assertRaises(exception.Conflict,
                          PROVIDERS.role_api.create_role,
                          role2['id'],
                          role2)

    def test_update_domain_id_of_role_fails(self):
        # Create a global role
        role1 = unit.new_role_ref()
        role1 = PROVIDERS.role_api.create_role(role1['id'], role1)
        # Try and update it to be domain specific
        domainA = unit.new_domain_ref()
        role1['domain_id'] = domainA['id']
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.role_api.update_role,
                          role1['id'],
                          role1)

        # Create a domain specific role from scratch
        role2 = unit.new_role_ref(domain_id=domainA['id'])
        PROVIDERS.role_api.create_role(role2['id'], role2)
        # Try to "move" it to another domain
        domainB = unit.new_domain_ref()
        role2['domain_id'] = domainB['id']
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.role_api.update_role,
                          role2['id'],
                          role2)
        # Now try to make it global
        role2['domain_id'] = None
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.role_api.update_role,
                          role2['id'],
                          role2)

    def test_domain_specific_separation(self):
        domain1 = unit.new_domain_ref()
        role1 = unit.new_role_ref(domain_id=domain1['id'])
        role_ref1 = PROVIDERS.role_api.create_role(role1['id'], role1.copy())
        self.assertDictEqual(role1, role_ref1)
        # Check we can have the same named role in a different domain
        domain2 = unit.new_domain_ref()
        role2 = unit.new_role_ref(name=role1['name'], domain_id=domain2['id'])
        role_ref2 = PROVIDERS.role_api.create_role(role2['id'], role2)
        self.assertDictEqual(role2, role_ref2)
        # ...and in fact that you can have the same named role as a global role
        role3 = unit.new_role_ref(name=role1['name'])
        role_ref3 = PROVIDERS.role_api.create_role(role3['id'], role3)
        self.assertDictEqual(role3, role_ref3)
        # Check that updating one doesn't change the others
        role1['name'] = uuid.uuid4().hex
        PROVIDERS.role_api.update_role(role1['id'], role1)
        role_ref1 = PROVIDERS.role_api.get_role(role1['id'])
        self.assertDictEqual(role1, role_ref1)
        role_ref2 = PROVIDERS.role_api.get_role(role2['id'])
        self.assertDictEqual(role2, role_ref2)
        role_ref3 = PROVIDERS.role_api.get_role(role3['id'])
        self.assertDictEqual(role3, role_ref3)
        # Check that deleting one of these, doesn't affect the others
        PROVIDERS.role_api.delete_role(role1['id'])
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          role1['id'])
        PROVIDERS.role_api.get_role(role2['id'])
        PROVIDERS.role_api.get_role(role3['id'])
