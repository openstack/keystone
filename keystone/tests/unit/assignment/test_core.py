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

from keystone.common import provider_api
from keystone.common.resource_options import options as ro_opt
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures

PROVIDERS = provider_api.ProviderAPIs


class RoleTests(object):

    def test_get_role_returns_not_found(self):
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          uuid.uuid4().hex)

    def test_get_unique_role_by_name_returns_not_found(self):
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_unique_role_by_name,
                          uuid.uuid4().hex)

    def test_create_duplicate_role_name_fails(self):
        role_id = uuid.uuid4().hex
        role = unit.new_role_ref(id=role_id, name='fake1name')
        PROVIDERS.role_api.create_role(role_id, role)
        new_role_id = uuid.uuid4().hex
        role['id'] = new_role_id
        self.assertRaises(exception.Conflict,
                          PROVIDERS.role_api.create_role,
                          new_role_id,
                          role)

    def test_rename_duplicate_role_name_fails(self):
        role_id1 = uuid.uuid4().hex
        role_id2 = uuid.uuid4().hex
        role1 = unit.new_role_ref(id=role_id1, name='fake1name')
        role2 = unit.new_role_ref(id=role_id2, name='fake2name')
        PROVIDERS.role_api.create_role(role_id1, role1)
        PROVIDERS.role_api.create_role(role_id2, role2)
        role1['name'] = 'fake2name'
        self.assertRaises(exception.Conflict,
                          PROVIDERS.role_api.update_role,
                          role_id1,
                          role1)

    def test_role_crud(self):
        role = unit.new_role_ref()
        role_name = role['name']
        PROVIDERS.role_api.create_role(role['id'], role)
        role_ref = PROVIDERS.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role, role_ref_dict)

        role_ref = PROVIDERS.role_api.get_unique_role_by_name(role_name)
        self.assertEqual(role['id'], role_ref['id'])

        role['name'] = uuid.uuid4().hex
        updated_role_ref = PROVIDERS.role_api.update_role(role['id'], role)
        role_ref = PROVIDERS.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role, role_ref_dict)
        self.assertDictEqual(role_ref_dict, updated_role_ref)

        PROVIDERS.role_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          role['id'])

    def test_role_crud_without_description(self):
        role = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': None,
            'options': {}
        }
        self.role_api.create_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertIsNone(role_ref_dict['description'])
        role_ref_dict.pop('description')
        self.assertDictEqual(role, role_ref_dict)

        role['name'] = uuid.uuid4().hex
        updated_role_ref = self.role_api.update_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertIsNone(updated_role_ref['description'])
        self.assertDictEqual(role_ref_dict, updated_role_ref)

        self.role_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role['id'])

    def test_update_role_returns_not_found(self):
        role = unit.new_role_ref()
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.update_role,
                          role['id'],
                          role)

    def test_list_roles(self):
        roles = PROVIDERS.role_api.list_roles()
        self.assertEqual(len(default_fixtures.ROLES), len(roles))
        role_ids = set(role['id'] for role in roles)
        expected_role_ids = set(role['id'] for role in default_fixtures.ROLES)
        self.assertEqual(expected_role_ids, role_ids)

    @unit.skip_if_cache_disabled('role')
    def test_cache_layer_role_crud(self):
        role = unit.new_role_ref()
        role_id = role['id']
        # Create role
        PROVIDERS.role_api.create_role(role_id, role)
        role_ref = PROVIDERS.role_api.get_role(role_id)
        updated_role_ref = copy.deepcopy(role_ref)
        updated_role_ref['name'] = uuid.uuid4().hex
        # Update role, bypassing the role api manager
        PROVIDERS.role_api.driver.update_role(role_id, updated_role_ref)
        # Verify get_role still returns old ref
        self.assertDictEqual(role_ref, PROVIDERS.role_api.get_role(role_id))
        # Invalidate Cache
        PROVIDERS.role_api.get_role.invalidate(PROVIDERS.role_api, role_id)
        # Verify get_role returns the new role_ref
        self.assertDictEqual(updated_role_ref,
                             PROVIDERS.role_api.get_role(role_id))
        # Update role back to original via the assignment api manager
        PROVIDERS.role_api.update_role(role_id, role_ref)
        # Verify get_role returns the original role ref
        self.assertDictEqual(role_ref, PROVIDERS.role_api.get_role(role_id))
        # Delete role bypassing the role api manager
        PROVIDERS.role_api.driver.delete_role(role_id)
        # Verify get_role still returns the role_ref
        self.assertDictEqual(role_ref, PROVIDERS.role_api.get_role(role_id))
        # Invalidate cache
        PROVIDERS.role_api.get_role.invalidate(PROVIDERS.role_api, role_id)
        # Verify RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          role_id)
        # recreate role
        PROVIDERS.role_api.create_role(role_id, role)
        PROVIDERS.role_api.get_role(role_id)
        # delete role via the assignment api manager
        PROVIDERS.role_api.delete_role(role_id)
        # verity RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          PROVIDERS.role_api.get_role,
                          role_id)

    def test_create_role_immutable(self):
        role = unit.new_role_ref()
        role_id = role['id']
        role['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        role_created = PROVIDERS.role_api.create_role(role_id, role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_created)
        self.assertTrue('options' in role_via_manager)
        self.assertTrue(
            role_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            role_created['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_cannot_update_immutable_role(self):
        role = unit.new_role_ref()
        role_id = role['id']
        role['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.role_api.create_role(role_id, role)
        update_role = {'name': uuid.uuid4().hex}
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.role_api.update_role,
                          role_id,
                          update_role)

    def test_cannot_update_immutable_role_while_unsetting_immutable(self):
        role = unit.new_role_ref()
        role_id = role['id']
        role['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.role_api.create_role(role_id, role)
        update_role = {
            'name': uuid.uuid4().hex,
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }
        }
        self.assertRaises(exception.ResourceUpdateForbidden,
                          PROVIDERS.role_api.update_role,
                          role_id,
                          update_role)

    def test_cannot_delete_immutable_role(self):
        role = unit.new_role_ref()
        role_id = role['id']
        role['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.role_api.create_role(role_id, role)
        self.assertRaises(exception.ResourceDeleteForbidden,
                          PROVIDERS.role_api.delete_role,
                          role_id)

    def test_update_role_set_immutable(self):
        role = unit.new_role_ref()
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)
        update_role = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }
        }
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
        role_update = PROVIDERS.role_api.update_role(role_id, update_role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in role_update['options'])
        self.assertTrue(
            role_update['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
        self.assertTrue(
            role_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_update_role_set_immutable_with_additional_updates(self):
        role = unit.new_role_ref()
        role_id = role['id']
        PROVIDERS.role_api.create_role(role_id, role)
        update_role = {
            'name': uuid.uuid4().hex,
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: True
            }
        }
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
        role_update = PROVIDERS.role_api.update_role(role_id, update_role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertEqual(role_update['name'], update_role['name'])
        self.assertEqual(role_via_manager['name'], update_role['name'])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in role_update['options'])
        self.assertTrue(
            role_update['options'][ro_opt.IMMUTABLE_OPT.option_name])
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
        self.assertTrue(
            role_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])

    def test_update_role_unset_immutable(self):
        role = unit.new_role_ref()
        role_id = role['id']
        role['options'][ro_opt.IMMUTABLE_OPT.option_name] = True
        PROVIDERS.role_api.create_role(role_id, role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_via_manager)
        self.assertTrue(
            role_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])
        update_role = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: False
            }
        }
        PROVIDERS.role_api.update_role(role_id, update_role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_via_manager)
        self.assertTrue(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
        self.assertFalse(
            role_via_manager['options'][ro_opt.IMMUTABLE_OPT.option_name])
        update_role = {
            'options': {
                ro_opt.IMMUTABLE_OPT.option_name: None
            }
        }
        role_updated = PROVIDERS.role_api.update_role(role_id, update_role)
        role_via_manager = PROVIDERS.role_api.get_role(role_id)
        self.assertTrue('options' in role_updated)
        self.assertTrue('options' in role_via_manager)
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in role_updated['options'])
        self.assertFalse(
            ro_opt.IMMUTABLE_OPT.option_name in role_via_manager['options'])
