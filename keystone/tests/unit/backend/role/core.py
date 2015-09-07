# Copyright 2012 OpenStack Foundation
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

import copy
import uuid

from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures


class RoleTests(object):

    def test_get_role_404(self):
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          uuid.uuid4().hex)

    def test_create_duplicate_role_name_fails(self):
        role = {'id': 'fake1',
                'name': 'fake1name'}
        self.role_api.create_role('fake1', role)
        role['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.role_api.create_role,
                          'fake2',
                          role)

    def test_rename_duplicate_role_name_fails(self):
        role1 = {
            'id': 'fake1',
            'name': 'fake1name'
        }
        role2 = {
            'id': 'fake2',
            'name': 'fake2name'
        }
        self.role_api.create_role('fake1', role1)
        self.role_api.create_role('fake2', role2)
        role1['name'] = 'fake2name'
        self.assertRaises(exception.Conflict,
                          self.role_api.update_role,
                          'fake1',
                          role1)

    def test_role_crud(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role_ref_dict, role)

        role['name'] = uuid.uuid4().hex
        updated_role_ref = self.role_api.update_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role_ref_dict, role)
        self.assertDictEqual(role_ref_dict, updated_role_ref)

        self.role_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role['id'])

    def test_update_role_404(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.update_role,
                          role['id'],
                          role)

    def test_list_roles(self):
        roles = self.role_api.list_roles()
        self.assertEqual(len(default_fixtures.ROLES), len(roles))
        role_ids = set(role['id'] for role in roles)
        expected_role_ids = set(role['id'] for role in default_fixtures.ROLES)
        self.assertEqual(expected_role_ids, role_ids)

    @unit.skip_if_cache_disabled('role')
    def test_cache_layer_role_crud(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        role_id = role['id']
        # Create role
        self.role_api.create_role(role_id, role)
        role_ref = self.role_api.get_role(role_id)
        updated_role_ref = copy.deepcopy(role_ref)
        updated_role_ref['name'] = uuid.uuid4().hex
        # Update role, bypassing the role api manager
        self.role_api.driver.update_role(role_id, updated_role_ref)
        # Verify get_role still returns old ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Invalidate Cache
        self.role_api.get_role.invalidate(self.role_api, role_id)
        # Verify get_role returns the new role_ref
        self.assertDictEqual(updated_role_ref,
                             self.role_api.get_role(role_id))
        # Update role back to original via the assignment api manager
        self.role_api.update_role(role_id, role_ref)
        # Verify get_role returns the original role ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Delete role bypassing the role api manager
        self.role_api.driver.delete_role(role_id)
        # Verify get_role still returns the role_ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Invalidate cache
        self.role_api.get_role.invalidate(self.role_api, role_id)
        # Verify RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role_id)
        # recreate role
        self.role_api.create_role(role_id, role)
        self.role_api.get_role(role_id)
        # delete role via the assignment api manager
        self.role_api.delete_role(role_id)
        # verity RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role_id)
