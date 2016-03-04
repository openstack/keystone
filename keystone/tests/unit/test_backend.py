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

import mock
from oslo_config import cfg
from six.moves import range
from testtools import matchers

from keystone.catalog import core
from keystone.common import driver_hints
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import filtering


CONF = cfg.CONF


class IdentityTests(object):

    def _get_domain_fixture(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        return domain

    def _set_domain_scope(self, domain_id):
        # We only provide a domain scope if we have multiple drivers
        if CONF.identity.domain_specific_drivers_enabled:
            return domain_id

    def test_authenticate_bad_user(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=uuid.uuid4().hex,
                          password=self.user_foo['password'])

    def test_authenticate_bad_password(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=self.user_foo['id'],
                          password=uuid.uuid4().hex)

    def test_authenticate(self):
        user_ref = self.identity_api.authenticate(
            context={},
            user_id=self.user_sna['id'],
            password=self.user_sna['password'])
        # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_sna.pop('password')
        self.user_sna['enabled'] = True
        self.assertDictEqual(self.user_sna, user_ref)

    def test_authenticate_and_get_roles_no_metadata(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        # Remove user id. It is ignored by create_user() and will break the
        # subset test below.
        del user['id']

        new_user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                new_user['id'])
        user_ref = self.identity_api.authenticate(
            context={},
            user_id=new_user['id'],
            password=user['password'])
        self.assertNotIn('password', user_ref)
        # NOTE(termie): the password field is left in user_sna to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        user.pop('password')
        self.assertDictContainsSubset(user, user_ref)
        role_list = self.assignment_api.get_roles_for_user_and_project(
            new_user['id'], self.tenant_baz['id'])
        self.assertEqual(1, len(role_list))
        self.assertIn(CONF.member_role_id, role_list)

    def test_authenticate_if_no_password_set(self):
        id_ = uuid.uuid4().hex
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)

        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=id_,
                          password='password')

    def test_create_unicode_user_name(self):
        unicode_name = u'name \u540d\u5b57'
        user = unit.new_user_ref(name=unicode_name,
                                 domain_id=CONF.identity.default_domain_id)
        ref = self.identity_api.create_user(user)
        self.assertEqual(unicode_name, ref['name'])

    def test_get_user(self):
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        # cache the result.
        self.identity_api.get_user(ref['id'])
        # delete bypassing identity api
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, self.identity_api.get_user(ref['id']))
        self.identity_api.get_user.invalidate(self.identity_api, ref['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user, ref['id'])
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        user['description'] = uuid.uuid4().hex
        # cache the result.
        self.identity_api.get_user(ref['id'])
        # update using identity api and get back updated user.
        user_updated = self.identity_api.update_user(ref['id'], user)
        self.assertDictContainsSubset(self.identity_api.get_user(ref['id']),
                                      user_updated)
        self.assertDictContainsSubset(
            self.identity_api.get_user_by_name(ref['name'], ref['domain_id']),
            user_updated)

    def test_get_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          uuid.uuid4().hex)

    def test_get_user_by_name(self):
        user_ref = self.identity_api.get_user_by_name(
            self.user_foo['name'], CONF.identity.default_domain_id)
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(self.user_foo, user_ref)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user_by_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        # delete bypassing the identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, self.identity_api.get_user_by_name(
            user['name'], CONF.identity.default_domain_id))
        self.identity_api.get_user_by_name.invalidate(
            self.identity_api, user['name'], CONF.identity.default_domain_id)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'], CONF.identity.default_domain_id)
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        user['description'] = uuid.uuid4().hex
        user_updated = self.identity_api.update_user(ref['id'], user)
        self.assertDictContainsSubset(self.identity_api.get_user(ref['id']),
                                      user_updated)
        self.assertDictContainsSubset(
            self.identity_api.get_user_by_name(ref['name'], ref['domain_id']),
            user_updated)

    def test_get_user_by_name_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    def test_create_duplicate_user_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_user,
                          user)

    def test_create_duplicate_user_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user2 = unit.new_user_ref(name=user1['name'],
                                  domain_id=new_domain['id'])

        self.identity_api.create_user(user1)
        self.identity_api.create_user(user2)

    def test_move_user_between_domains(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        user = unit.new_user_ref(domain_id=domain1['id'])
        user = self.identity_api.create_user(user)
        user['domain_id'] = domain2['id']
        # Update the user asserting that a deprecation warning is emitted
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            self.identity_api.update_user(user['id'], user)
            self.assertTrue(mock_dep.called)

        updated_user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(domain2['id'], updated_user_ref['domain_id'])

    def test_move_user_between_domains_with_clashing_names_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a user in domain1
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        # Now create a user in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        user2 = unit.new_user_ref(name=user1['name'],
                                  domain_id=domain2['id'])
        user2 = self.identity_api.create_user(user2)
        # Now try and move user1 into the 2nd domain - which should
        # fail since the names clash
        user1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user1['id'],
                          user1)

    def test_rename_duplicate_user_name_fails(self):
        user1 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user2 = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_user(user1)
        user2 = self.identity_api.create_user(user2)
        user2['name'] = user1['name']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user2['id'],
                          user2)

    def test_update_user_id_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        original_id = user['id']
        user['id'] = 'fake2'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          original_id,
                          user)
        user_ref = self.identity_api.get_user(original_id)
        self.assertEqual(original_id, user_ref['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'fake2')

    def test_delete_user_with_group_project_domain_links(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_user(user1['id'])
        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          user1['id'],
                          group1['id'])

    def test_delete_group_with_user_project_domain_links(self):
        role1 = unit.new_role_ref()
        self.role_api.create_role(role1['id'], role1)
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = unit.new_project_ref(domain_id=domain1['id'])
        self.resource_api.create_project(project1['id'], project1)
        user1 = unit.new_user_ref(domain_id=domain1['id'])
        user1 = self.identity_api.create_user(user1)
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)

        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_group(group1['id'])
        self.identity_api.get_user(user1['id'])

    def test_update_user_returns_not_found(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.update_user,
                          user_id,
                          {'id': user_id,
                           'domain_id': CONF.identity.default_domain_id})

    def test_delete_user_returns_not_found(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_create_user_long_name_fails(self):
        user = unit.new_user_ref(name='a' * 256,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_blank_name_fails(self):
        user = unit.new_user_ref(name='',
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_missed_password(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password='')
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=None)

    def test_create_user_none_password(self):
        user = unit.new_user_ref(password=None,
                                 domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.identity_api.get_user(user['id'])
        # Make sure  the user is not allowed to login
        # with a password that  is empty string or None
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password='')
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=user['id'],
                          password=None)

    def test_create_user_invalid_name_fails(self):
        user = unit.new_user_ref(name=None,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

        user = unit.new_user_ref(name=123,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_invalid_enabled_type_string(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id,
                                 # invalid string value
                                 enabled='true')
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_update_user_long_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['name'] = 'a' * 256
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_blank_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_invalid_name_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)

        user['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

        user['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_list_users(self):
        users = self.identity_api.list_users(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
                                for user in default_fixtures.USERS)
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def test_list_groups(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)
        groups = self.identity_api.list_groups(
            domain_scope=self._set_domain_scope(
                CONF.identity.default_domain_id))
        self.assertEqual(2, len(groups))
        group_ids = []
        for group in groups:
            group_ids.append(group.get('id'))
        self.assertIn(group1['id'], group_ids)
        self.assertIn(group2['id'], group_ids)

    def test_create_user_doesnt_modify_passed_in_dict(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        original_user = new_user.copy()
        self.identity_api.create_user(new_user)
        self.assertDictEqual(original_user, new_user)

    def test_update_user_enable(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        # If not present, enabled field should not be updated
        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertFalse(user_ref['enabled'])

        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        # Integers are valid Python's booleans. Explicitly test it.
        user['enabled'] = 0
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertFalse(user_ref['enabled'])

        # Any integers other than 0 are interpreted as True
        user['enabled'] = -42
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        # NOTE(breton): below, attribute `enabled` is explicitly tested to be
        # equal True. assertTrue should not be used, because it converts
        # the passed value to bool().
        self.assertIs(user_ref['enabled'], True)

    def test_update_user_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['name'], user_ref['name'])

        changed_name = user_ref['name'] + '_changed'
        user_ref['name'] = changed_name
        updated_user = self.identity_api.update_user(user_ref['id'], user_ref)

        # NOTE(dstanek): the SQL backend adds an 'extra' field containing a
        #                dictionary of the extra fields in addition to the
        #                fields in the object. For the details see:
        #                SqlIdentity.test_update_project_returns_extra
        updated_user.pop('extra', None)

        self.assertDictEqual(user_ref, updated_user)

        user_ref = self.identity_api.get_user(user_ref['id'])
        self.assertEqual(changed_name, user_ref['name'])

    def test_update_user_enable_fails(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertTrue(user_ref['enabled'])

        # Strings are not valid boolean values
        user['enabled'] = 'false'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_add_user_to_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])

        found = False
        for x in groups:
            if (x['id'] == new_group['id']):
                found = True
        self.assertTrue(found)

    def test_add_user_to_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.add_user_to_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_check_user_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        self.identity_api.check_user_in_group(new_user['id'], new_group['id'])

    def test_check_user_not_in_group(self):
        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = self.identity_api.create_group(new_group)

        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = self.identity_api.create_user(new_user)

        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          new_user['id'],
                          new_group['id'])

    def test_check_user_in_group_returns_not_found(self):
        new_user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        new_user = self.identity_api.create_user(new_user)

        new_group = unit.new_group_ref(
            domain_id=CONF.identity.default_domain_id)
        new_group = self.identity_api.create_group(new_group)

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.check_user_in_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_list_users_in_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        # Make sure we get an empty list back on a new group, not an error.
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        self.assertEqual([], user_refs)
        # Make sure we get the correct users back once they have been added
        # to the group.
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        found = False
        for x in user_refs:
            if (x['id'] == new_user['id']):
                found = True
            self.assertNotIn('password', x)
        self.assertTrue(found)

    def test_list_users_in_group_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.list_users_in_group,
                          uuid.uuid4().hex)

    def test_list_groups_for_user(self):
        domain = self._get_domain_fixture()
        test_groups = []
        test_users = []
        GROUP_COUNT = 3
        USER_COUNT = 2

        for x in range(0, USER_COUNT):
            new_user = unit.new_user_ref(domain_id=domain['id'])
            new_user = self.identity_api.create_user(new_user)
            test_users.append(new_user)
        positive_user = test_users[0]
        negative_user = test_users[1]

        for x in range(0, USER_COUNT):
            group_refs = self.identity_api.list_groups_for_user(
                test_users[x]['id'])
            self.assertEqual(0, len(group_refs))

        for x in range(0, GROUP_COUNT):
            before_count = x
            after_count = x + 1
            new_group = unit.new_group_ref(domain_id=domain['id'])
            new_group = self.identity_api.create_group(new_group)
            test_groups.append(new_group)

            # add the user to the group and ensure that the
            # group count increases by one for each
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            self.identity_api.add_user_to_group(
                positive_user['id'],
                new_group['id'])
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))

            # Make sure the group count for the unrelated user did not change
            group_refs = self.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

        # remove the user from each group and ensure that
        # the group count reduces by one for each
        for x in range(0, 3):
            before_count = GROUP_COUNT - x
            after_count = GROUP_COUNT - x - 1
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            self.identity_api.remove_user_from_group(
                positive_user['id'],
                test_groups[x]['id'])
            group_refs = self.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))
            # Make sure the group count for the unrelated user
            # did not change
            group_refs = self.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

    def test_remove_user_from_group(self):
        domain = self._get_domain_fixture()
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertIn(new_group['id'], [x['id'] for x in groups])
        self.identity_api.remove_user_from_group(new_user['id'],
                                                 new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertNotIn(new_group['id'], [x['id'] for x in groups])

    def test_remove_user_from_group_returns_not_found(self):
        domain = self._get_domain_fixture()
        new_user = unit.new_user_ref(domain_id=domain['id'])
        new_user = self.identity_api.create_user(new_user)
        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = self.identity_api.create_group(new_group)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.remove_user_from_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_group_crud(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        group = unit.new_group_ref(domain_id=domain['id'])
        group = self.identity_api.create_group(group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictContainsSubset(group, group_ref)

        group['name'] = uuid.uuid4().hex
        self.identity_api.update_group(group['id'], group)
        group_ref = self.identity_api.get_group(group['id'])
        self.assertDictContainsSubset(group, group_ref)

        self.identity_api.delete_group(group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group,
                          group['id'])

    def test_get_group_by_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group_name = group['name']
        group = self.identity_api.create_group(group)
        spoiler = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        self.identity_api.create_group(spoiler)

        group_ref = self.identity_api.get_group_by_name(
            group_name, CONF.identity.default_domain_id)
        self.assertDictEqual(group, group_ref)

    def test_get_group_by_name_returns_not_found(self):
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group_by_name,
                          uuid.uuid4().hex,
                          CONF.identity.default_domain_id)

    @unit.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        # cache the result
        group_ref = self.identity_api.get_group(group['id'])
        # delete the group bypassing identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(group['id']))
        driver.delete_group(entity_id)

        self.assertEqual(group_ref, self.identity_api.get_group(group['id']))
        self.identity_api.get_group.invalidate(self.identity_api, group['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group, group['id'])

        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        # cache the result
        self.identity_api.get_group(group['id'])
        group['name'] = uuid.uuid4().hex
        group_ref = self.identity_api.update_group(group['id'], group)
        # after updating through identity api, get updated group
        self.assertDictContainsSubset(self.identity_api.get_group(group['id']),
                                      group_ref)

    def test_create_duplicate_group_name_fails(self):
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id,
                                    name=group1['name'])
        group1 = self.identity_api.create_group(group1)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_group,
                          group2)

    def test_create_duplicate_group_name_in_different_domains(self):
        new_domain = unit.new_domain_ref()
        self.resource_api.create_domain(new_domain['id'], new_domain)
        group1 = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group2 = unit.new_group_ref(domain_id=new_domain['id'],
                                    name=group1['name'])
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)

    def test_move_group_between_domains(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        group = unit.new_group_ref(domain_id=domain1['id'])
        group = self.identity_api.create_group(group)
        group['domain_id'] = domain2['id']
        # Update the group asserting that a deprecation warning is emitted
        with mock.patch(
                'oslo_log.versionutils.report_deprecated_feature') as mock_dep:
            self.identity_api.update_group(group['id'], group)
            self.assertTrue(mock_dep.called)

        updated_group_ref = self.identity_api.get_group(group['id'])
        self.assertEqual(domain2['id'], updated_group_ref['domain_id'])

    def test_move_group_between_domains_with_clashing_names_fails(self):
        domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a group in domain1
        group1 = unit.new_group_ref(domain_id=domain1['id'])
        group1 = self.identity_api.create_group(group1)
        # Now create a group in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        group2 = unit.new_group_ref(name=group1['name'],
                                    domain_id=domain2['id'])
        group2 = self.identity_api.create_group(group2)
        # Now try and move group1 into the 2nd domain - which should
        # fail since the names clash
        group1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_group,
                          group1['id'],
                          group1)

    def test_user_crud(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        del user_dict['id']
        user = self.identity_api.create_user(user_dict)
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        user_dict['password'] = uuid.uuid4().hex
        self.identity_api.update_user(user['id'], user_dict)
        user_ref = self.identity_api.get_user(user['id'])
        del user_dict['password']
        user_ref_dict = {x: user_ref[x] for x in user_ref}
        self.assertDictContainsSubset(user_dict, user_ref_dict)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_arbitrary_attributes_are_returned_from_create_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user = self.identity_api.create_user(user_data)

        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        user_data = self.identity_api.create_user(user_data)

        user = self.identity_api.get_user(user_data['id'])
        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)

        user = self.identity_api.create_user(user_data)
        attr_value = uuid.uuid4().hex
        user['arbitrary_attr'] = attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(attr_value, updated_user['arbitrary_attr'])

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        attr_value = uuid.uuid4().hex
        user_data = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id,
            arbitrary_attr=attr_value)

        new_attr_value = uuid.uuid4().hex
        user = self.identity_api.create_user(user_data)
        user['arbitrary_attr'] = new_attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(new_attr_value, updated_user['arbitrary_attr'])

    def test_user_update_and_user_get_return_same_response(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)

        user = self.identity_api.create_user(user)

        updated_user = {'enabled': False}
        updated_user_ref = self.identity_api.update_user(
            user['id'], updated_user)

        # SQL backend adds 'extra' field
        updated_user_ref.pop('extra', None)

        self.assertIs(False, updated_user_ref['enabled'])

        user_ref = self.identity_api.get_user(user['id'])
        self.assertDictEqual(updated_user_ref, user_ref)


class CatalogTests(object):

    _legacy_endpoint_id_in_endpoint = True
    _enabled_default_to_true_when_creating_endpoint = False

    def test_region_crud(self):
        # create
        region_id = '0' * 255
        new_region = unit.new_region_ref(id=region_id)
        res = self.catalog_api.create_region(new_region)

        # Ensure that we don't need to have a
        # parent_region_id in the original supplied
        # ref dict, but that it will be returned from
        # the endpoint, with None value.
        expected_region = new_region.copy()
        expected_region['parent_region_id'] = None
        self.assertDictEqual(expected_region, res)

        # Test adding another region with the one above
        # as its parent. We will check below whether deleting
        # the parent successfully deletes any child regions.
        parent_region_id = region_id
        new_region = unit.new_region_ref(parent_region_id=parent_region_id)
        region_id = new_region['id']
        res = self.catalog_api.create_region(new_region)
        self.assertDictEqual(new_region, res)

        # list
        regions = self.catalog_api.list_regions()
        self.assertThat(regions, matchers.HasLength(2))
        region_ids = [x['id'] for x in regions]
        self.assertIn(parent_region_id, region_ids)
        self.assertIn(region_id, region_ids)

        # update
        region_desc_update = {'description': uuid.uuid4().hex}
        res = self.catalog_api.update_region(region_id, region_desc_update)
        expected_region = new_region.copy()
        expected_region['description'] = region_desc_update['description']
        self.assertDictEqual(expected_region, res)

        # delete
        self.catalog_api.delete_region(parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.delete_region,
                          parent_region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          parent_region_id)
        # Ensure the child is also gone...
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_id)

    def _create_region_with_parent_id(self, parent_id=None):
        new_region = unit.new_region_ref(parent_region_id=parent_id)
        self.catalog_api.create_region(new_region)
        return new_region

    def test_list_regions_filtered_by_parent_region_id(self):
        new_region = self._create_region_with_parent_id()
        parent_id = new_region['id']
        new_region = self._create_region_with_parent_id(parent_id)
        new_region = self._create_region_with_parent_id(parent_id)

        # filter by parent_region_id
        hints = driver_hints.Hints()
        hints.add_filter('parent_region_id', parent_id)
        regions = self.catalog_api.list_regions(hints)
        for region in regions:
            self.assertEqual(parent_id, region['parent_region_id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_region_crud(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        self.catalog_api.create_region(new_region.copy())
        updated_region = copy.deepcopy(new_region)
        updated_region['description'] = uuid.uuid4().hex
        # cache the result
        self.catalog_api.get_region(region_id)
        # update the region bypassing catalog_api
        self.catalog_api.driver.update_region(region_id, updated_region)
        self.assertDictContainsSubset(new_region,
                                      self.catalog_api.get_region(region_id))
        self.catalog_api.get_region.invalidate(self.catalog_api, region_id)
        self.assertDictContainsSubset(updated_region,
                                      self.catalog_api.get_region(region_id))
        # delete the region
        self.catalog_api.driver.delete_region(region_id)
        # still get the old region
        self.assertDictContainsSubset(updated_region,
                                      self.catalog_api.get_region(region_id))
        self.catalog_api.get_region.invalidate(self.catalog_api, region_id)
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region, region_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_region(self):
        new_region = unit.new_region_ref()
        region_id = new_region['id']
        self.catalog_api.create_region(new_region)

        # cache the region
        self.catalog_api.get_region(region_id)

        # update the region via catalog_api
        new_description = {'description': uuid.uuid4().hex}
        self.catalog_api.update_region(region_id, new_description)

        # assert that we can get the new region
        current_region = self.catalog_api.get_region(region_id)
        self.assertEqual(new_description['description'],
                         current_region['description'])

    def test_create_region_with_duplicate_id(self):
        new_region = unit.new_region_ref()
        self.catalog_api.create_region(new_region)
        # Create region again with duplicate id
        self.assertRaises(exception.Conflict,
                          self.catalog_api.create_region,
                          new_region)

    def test_get_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          uuid.uuid4().hex)

    def test_delete_region_returns_not_found(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.delete_region,
                          uuid.uuid4().hex)

    def test_create_region_invalid_parent_region_returns_not_found(self):
        new_region = unit.new_region_ref(parent_region_id='nonexisting')
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.create_region,
                          new_region)

    def test_avoid_creating_circular_references_in_regions_update(self):
        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_one['id']})

        # region_one->region_two->region_one
        region_two = self._create_region_with_parent_id(region_one['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_one['id'],
                          {'parent_region_id': region_two['id']})

        # region_one region_two->region_three->region_four->region_two
        region_three = self._create_region_with_parent_id(region_two['id'])
        region_four = self._create_region_with_parent_id(region_three['id'])
        self.assertRaises(exception.CircularRegionHierarchyError,
                          self.catalog_api.update_region,
                          region_two['id'],
                          {'parent_region_id': region_four['id']})

    @mock.patch.object(core.CatalogDriverV8,
                       "_ensure_no_circle_in_hierarchical_regions")
    def test_circular_regions_can_be_deleted(self, mock_ensure_on_circle):
        # turn off the enforcement so that cycles can be created for the test
        mock_ensure_on_circle.return_value = None

        region_one = self._create_region_with_parent_id()

        # self circle: region_one->region_one
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_one['id']})
        self.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])

        # region_one->region_two->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_two['id']})
        self.catalog_api.delete_region(region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_two['id'])

        # region_one->region_two->region_three->region_one
        region_one = self._create_region_with_parent_id()
        region_two = self._create_region_with_parent_id(region_one['id'])
        region_three = self._create_region_with_parent_id(region_two['id'])
        self.catalog_api.update_region(
            region_one['id'],
            {'parent_region_id': region_three['id']})
        self.catalog_api.delete_region(region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_two['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_one['id'])
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          region_three['id'])

    def test_service_crud(self):
        # create
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = self.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)

        # list
        services = self.catalog_api.list_services()
        self.assertIn(service_id, [x['id'] for x in services])

        # update
        service_name_update = {'name': uuid.uuid4().hex}
        res = self.catalog_api.update_service(service_id, service_name_update)
        expected_service = new_service.copy()
        expected_service['name'] = service_name_update['name']
        self.assertDictEqual(expected_service, res)

        # delete
        self.catalog_api.delete_service(service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          service_id)

    def _create_random_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        return self.catalog_api.create_service(service_id, new_service)

    def test_service_filtering(self):
        target_service = self._create_random_service()
        unrelated_service1 = self._create_random_service()
        unrelated_service2 = self._create_random_service()

        # filter by type
        hint_for_type = driver_hints.Hints()
        hint_for_type.add_filter(name="type", value=target_service['type'])
        services = self.catalog_api.list_services(hint_for_type)

        self.assertEqual(1, len(services))
        filtered_service = services[0]
        self.assertEqual(target_service['type'], filtered_service['type'])
        self.assertEqual(target_service['id'], filtered_service['id'])

        # filter should have been removed, since it was already used by the
        # backend
        self.assertEqual(0, len(hint_for_type.filters))

        # the backend shouldn't filter by name, since this is handled by the
        # front end
        hint_for_name = driver_hints.Hints()
        hint_for_name.add_filter(name="name", value=target_service['name'])
        services = self.catalog_api.list_services(hint_for_name)

        self.assertEqual(3, len(services))

        # filter should still be there, since it wasn't used by the backend
        self.assertEqual(1, len(hint_for_name.filters))

        self.catalog_api.delete_service(target_service['id'])
        self.catalog_api.delete_service(unrelated_service1['id'])
        self.catalog_api.delete_service(unrelated_service2['id'])

    @unit.skip_if_cache_disabled('catalog')
    def test_cache_layer_service_crud(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        res = self.catalog_api.create_service(service_id, new_service)
        self.assertDictEqual(new_service, res)
        self.catalog_api.get_service(service_id)
        updated_service = copy.deepcopy(new_service)
        updated_service['description'] = uuid.uuid4().hex
        # update bypassing catalog api
        self.catalog_api.driver.update_service(service_id, updated_service)
        self.assertDictContainsSubset(new_service,
                                      self.catalog_api.get_service(service_id))
        self.catalog_api.get_service.invalidate(self.catalog_api, service_id)
        self.assertDictContainsSubset(updated_service,
                                      self.catalog_api.get_service(service_id))

        # delete bypassing catalog api
        self.catalog_api.driver.delete_service(service_id)
        self.assertDictContainsSubset(updated_service,
                                      self.catalog_api.get_service(service_id))
        self.catalog_api.get_service.invalidate(self.catalog_api, service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          service_id)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_service(self):
        new_service = unit.new_service_ref()
        service_id = new_service['id']
        self.catalog_api.create_service(service_id, new_service)

        # cache the service
        self.catalog_api.get_service(service_id)

        # update the service via catalog api
        new_type = {'type': uuid.uuid4().hex}
        self.catalog_api.update_service(service_id, new_type)

        # assert that we can get the new service
        current_service = self.catalog_api.get_service(service_id)
        self.assertEqual(new_type['type'], current_service['type'])

    def test_delete_service_with_endpoint(self):
        # create a service
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # deleting the service should also delete the endpoint
        self.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])

    def test_cache_layer_delete_service_with_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        # cache the result
        self.catalog_api.get_service(service['id'])
        self.catalog_api.get_endpoint(endpoint['id'])
        # delete the service bypassing catalog api
        self.catalog_api.driver.delete_service(service['id'])
        self.assertDictContainsSubset(endpoint,
                                      self.catalog_api.
                                      get_endpoint(endpoint['id']))
        self.assertDictContainsSubset(service,
                                      self.catalog_api.
                                      get_service(service['id']))
        self.catalog_api.get_endpoint.invalidate(self.catalog_api,
                                                 endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])
        # multiple endpoints associated with a service
        second_endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                                region_id=None)
        self.catalog_api.create_service(service['id'], service)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        self.catalog_api.create_endpoint(second_endpoint['id'],
                                         second_endpoint)
        self.catalog_api.delete_service(service['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          second_endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          second_endpoint['id'])

    def test_get_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          uuid.uuid4().hex)

    def test_delete_service_returns_not_found(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          uuid.uuid4().hex)

    def test_create_endpoint_nonexistent_service(self):
        endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex,
                                         region_id=None)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_service(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_create_endpoint_nonexistent_region(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'])
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_region(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = unit.new_endpoint_ref(service_id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_get_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          uuid.uuid4().hex)

    def test_delete_endpoint_returns_not_found(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          uuid.uuid4().hex)

    def test_create_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

    def test_update_endpoint(self):
        dummy_service_ref, endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())
        res = self.catalog_api.update_endpoint(endpoint_ref['id'],
                                               {'interface': 'private'})
        expected_endpoint = endpoint_ref.copy()
        expected_endpoint['enabled'] = True
        expected_endpoint['interface'] = 'private'
        if self._legacy_endpoint_id_in_endpoint:
            expected_endpoint['legacy_endpoint_id'] = None
        if self._enabled_default_to_true_when_creating_endpoint:
            expected_endpoint['enabled'] = True
        self.assertDictEqual(expected_endpoint, res)

    def _create_endpoints(self):
        # Creates a service and 2 endpoints for the service in the same region.
        # The 'public' interface is enabled and the 'internal' interface is
        # disabled.

        def create_endpoint(service_id, region, **kwargs):
            ref = unit.new_endpoint_ref(
                service_id=service_id,
                region_id=region,
                url='http://localhost/%s' % uuid.uuid4().hex,
                **kwargs)

            self.catalog_api.create_endpoint(ref['id'], ref)
            return ref

        # Create a service for use with the endpoints.
        service_ref = unit.new_service_ref()
        service_id = service_ref['id']
        self.catalog_api.create_service(service_id, service_ref)

        region = unit.new_region_ref()
        self.catalog_api.create_region(region)

        # Create endpoints
        enabled_endpoint_ref = create_endpoint(service_id, region['id'])
        disabled_endpoint_ref = create_endpoint(
            service_id, region['id'], enabled=False, interface='internal')

        return service_ref, enabled_endpoint_ref, disabled_endpoint_ref

    def test_list_endpoints(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        expected_ids = set([uuid.uuid4().hex for _ in range(3)])
        for endpoint_id in expected_ids:
            endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                             id=endpoint_id,
                                             region_id=None)
            self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        endpoints = self.catalog_api.list_endpoints()
        self.assertEqual(expected_ids, set(e['id'] for e in endpoints))

    def test_get_catalog_endpoint_disabled(self):
        """Get back only enabled endpoints when get the v2 catalog."""
        service_ref, enabled_endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())

        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        catalog = self.catalog_api.get_catalog(user_id, project_id)

        exp_entry = {
            'id': enabled_endpoint_ref['id'],
            'name': service_ref['name'],
            'publicURL': enabled_endpoint_ref['url'],
        }

        region = enabled_endpoint_ref['region_id']
        self.assertEqual(exp_entry, catalog[region][service_ref['type']])

    def test_get_v3_catalog_endpoint_disabled(self):
        """Get back only enabled endpoints when get the v3 catalog."""
        enabled_endpoint_ref = self._create_endpoints()[1]

        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        catalog = self.catalog_api.get_v3_catalog(user_id, project_id)

        endpoint_ids = [x['id'] for x in catalog[0]['endpoints']]
        self.assertEqual([enabled_endpoint_ref['id']], endpoint_ids)

    @unit.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_endpoint(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint)

        # cache the endpoint
        self.catalog_api.get_endpoint(endpoint['id'])

        # update the endpoint via catalog api
        new_url = {'url': uuid.uuid4().hex}
        self.catalog_api.update_endpoint(endpoint['id'], new_url)

        # assert that we can get the new endpoint
        current_endpoint = self.catalog_api.get_endpoint(endpoint['id'])
        self.assertEqual(new_url['url'], current_endpoint['url'])


class PolicyTests(object):
    def test_create(self):
        ref = unit.new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)
        self.assertDictEqual(ref, res)

    def test_get(self):
        ref = unit.new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.get_policy(ref['id'])
        self.assertDictEqual(ref, res)

    def test_list(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.list_policies()
        res = [x for x in res if x['id'] == ref['id']][0]
        self.assertDictEqual(ref, res)

    def test_update(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)
        orig = ref

        ref = unit.new_policy_ref()

        # (cannot change policy ID)
        self.assertRaises(exception.ValidationError,
                          self.policy_api.update_policy,
                          orig['id'],
                          ref)

        ref['id'] = orig['id']
        res = self.policy_api.update_policy(orig['id'], ref)
        self.assertDictEqual(ref, res)

    def test_delete(self):
        ref = unit.new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)

        self.policy_api.delete_policy(ref['id'])
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.delete_policy,
                          ref['id'])
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.get_policy,
                          ref['id'])
        res = self.policy_api.list_policies()
        self.assertFalse(len([x for x in res if x['id'] == ref['id']]))

    def test_get_policy_returns_not_found(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.get_policy,
                          uuid.uuid4().hex)

    def test_update_policy_returns_not_found(self):
        ref = unit.new_policy_ref()
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.update_policy,
                          ref['id'],
                          ref)

    def test_delete_policy_returns_not_found(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.delete_policy,
                          uuid.uuid4().hex)


class FilterTests(filtering.FilterTests):
    def test_list_entities_filtered(self):
        for entity in ['user', 'group', 'project']:
            # Create 20 entities
            entity_list = self._create_test_data(entity, 20)

            # Try filtering to get one an exact item out of the list
            hints = driver_hints.Hints()
            hints.add_filter('name', entity_list[10]['name'])
            entities = self._list_entities(entity)(hints=hints)
            self.assertEqual(1, len(entities))
            self.assertEqual(entity_list[10]['id'], entities[0]['id'])
            # Check the driver has removed the filter from the list hints
            self.assertFalse(hints.get_exact_filter_by_name('name'))
            self._delete_test_data(entity, entity_list)

    def test_list_users_inexact_filtered(self):
        # Create 20 users, some with specific names. We set the names at create
        # time (rather than updating them), since the LDAP driver does not
        # support name updates.
        user_name_data = {
            # user index: name for user
            5: 'The',
            6: 'The Ministry',
            7: 'The Ministry of',
            8: 'The Ministry of Silly',
            9: 'The Ministry of Silly Walks',
            # ...and one for useful case insensitivity testing
            10: 'The ministry of silly walks OF'
        }
        user_list = self._create_test_data(
            'user', 20, domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)

        hints = driver_hints.Hints()
        hints.add_filter('name', 'ministry', comparator='contains')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(5, len(users))
        self._match_with_list(users, user_list,
                              list_start=6, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'The', comparator='startswith')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(6, len(users))
        self._match_with_list(users, user_list,
                              list_start=5, list_end=11)
        # TODO(henry-nash) Check inexact filter has been removed.

        hints = driver_hints.Hints()
        hints.add_filter('name', 'of', comparator='endswith')
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(2, len(users))
        # We can't assume we will get back the users in any particular order
        self.assertIn(user_list[7]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[10]['id'], [users[0]['id'], users[1]['id']])
        # TODO(henry-nash) Check inexact filter has been removed.

        # TODO(henry-nash): Add some case sensitive tests.  However,
        # these would be hard to validate currently, since:
        #
        # For SQL, the issue is that MySQL 0.7, by default, is installed in
        # case insensitive mode (which is what is run by default for our
        # SQL backend tests).  For production deployments. OpenStack
        # assumes a case sensitive database.  For these tests, therefore, we
        # need to be able to check the sensitivity of the database so as to
        # know whether to run case sensitive tests here.
        #
        # For LDAP/AD, although dependent on the schema being used, attributes
        # are typically configured to be case aware, but not case sensitive.

        self._delete_test_data('user', user_list)

    def _groups_for_user_data(self):
        number_of_groups = 10
        group_name_data = {
            # entity index: name for entity
            5: 'The',
            6: 'The Ministry',
            9: 'The Ministry of Silly Walks',
        }
        group_list = self._create_test_data(
            'group', number_of_groups,
            domain_id=CONF.identity.default_domain_id,
            name_dict=group_name_data)
        user_list = self._create_test_data('user', 2)

        for group in range(7):
            # Create membership, including with two out of the three groups
            # with well know names
            self.identity_api.add_user_to_group(user_list[0]['id'],
                                                group_list[group]['id'])
        # ...and some spoiler memberships
        for group in range(7, number_of_groups):
            self.identity_api.add_user_to_group(user_list[1]['id'],
                                                group_list[group]['id'])

        hints = driver_hints.Hints()
        return group_list, user_list, hints

    def test_groups_for_user_inexact_filtered(self):
        """Test use of filtering doesn't break groups_for_user listing.

        Some backends may use filtering to achieve the list of groups for a
        user, so test that it can combine a second filter.

        Test Plan:

        - Create 10 groups, some with names we can filter on
        - Create 2 users
        - Assign 1 of those users to most of the groups, including some of the
          well known named ones
        - Assign the other user to other groups as spoilers
        - Ensure that when we list groups for users with a filter on the group
          name, both restrictions have been enforced on what is returned.

        """
        group_list, user_list, hints = self._groups_for_user_data()
        hints.add_filter('name', 'The', comparator='startswith')
        groups = self.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 2 out of the 3 groups that start with 'The'
        # hence showing that both "filters" have been applied
        self.assertThat(len(groups), matchers.Equals(2))
        self.assertIn(group_list[5]['id'], [groups[0]['id'], groups[1]['id']])
        self.assertIn(group_list[6]['id'], [groups[0]['id'], groups[1]['id']])
        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def test_groups_for_user_exact_filtered(self):
        """Test exact filters doesn't break groups_for_user listing."""
        group_list, user_list, hints = self._groups_for_user_data()
        hints.add_filter('name', 'The Ministry', comparator='equals')
        groups = self.identity_api.list_groups_for_user(
            user_list[0]['id'], hints=hints)
        # We should only get back 1 out of the 3 groups with name 'The
        # Ministry' hence showing that both "filters" have been applied.
        self.assertEqual(1, len(groups))
        self.assertEqual(group_list[6]['id'], groups[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_test_data('group', group_list)

    def _get_user_name_field_size(self):
        """Return the size of the user name field for the backend.

        Subclasses can override this method to indicate that the user name
        field is limited in length. The user name is the field used in the test
        that validates that a filter value works even if it's longer than a
        field.

        If the backend doesn't limit the value length then return None.

        """
        return None

    def test_filter_value_wider_than_field(self):
        # If a filter value is given that's larger than the field in the
        # backend then no values are returned.

        user_name_field_size = self._get_user_name_field_size()

        if user_name_field_size is None:
            # The backend doesn't limit the size of the user name, so pass this
            # test.
            return

        # Create some users just to make sure would return something if the
        # filter was ignored.
        self._create_test_data('user', 2)

        hints = driver_hints.Hints()
        value = 'A' * (user_name_field_size + 1)
        hints.add_filter('name', value)
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual([], users)

    def _list_users_in_group_data(self):
        number_of_users = 10
        user_name_data = {
            1: 'Arthur Conan Doyle',
            3: 'Arthur Rimbaud',
            9: 'Arthur Schopenhauer',
        }
        user_list = self._create_test_data(
            'user', number_of_users,
            domain_id=CONF.identity.default_domain_id,
            name_dict=user_name_data)
        group = self._create_one_entity(
            'group', CONF.identity.default_domain_id, 'Great Writers')
        for i in range(7):
            self.identity_api.add_user_to_group(user_list[i]['id'],
                                                group['id'])

        hints = driver_hints.Hints()
        return user_list, group, hints

    def test_list_users_in_group_inexact_filtered(self):
        user_list, group, hints = self._list_users_in_group_data()
        hints.add_filter('name', 'Arthur', comparator='startswith')
        users = self.identity_api.list_users_in_group(group['id'], hints=hints)
        self.assertThat(len(users), matchers.Equals(2))
        self.assertIn(user_list[1]['id'], [users[0]['id'], users[1]['id']])
        self.assertIn(user_list[3]['id'], [users[0]['id'], users[1]['id']])
        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])

    def test_list_users_in_group_exact_filtered(self):
        user_list, group, hints = self._list_users_in_group_data()
        hints.add_filter('name', 'Arthur Rimbaud', comparator='equals')
        users = self.identity_api.list_users_in_group(group['id'], hints=hints)
        self.assertEqual(1, len(users))
        self.assertEqual(user_list[3]['id'], users[0]['id'])
        self._delete_test_data('user', user_list)
        self._delete_entity('group')(group['id'])


class LimitTests(filtering.FilterTests):
    ENTITIES = ['user', 'group', 'project']

    def setUp(self):
        """Setup for Limit Test Cases."""
        self.entity_lists = {}

        for entity in self.ENTITIES:
            # Create 20 entities
            self.entity_lists[entity] = self._create_test_data(entity, 20)
        self.addCleanup(self.clean_up_entities)

    def clean_up_entities(self):
        """Clean up entity test data from Limit Test Cases."""
        for entity in self.ENTITIES:
            self._delete_test_data(entity, self.entity_lists[entity])
        del self.entity_lists

    def _test_list_entity_filtered_and_limited(self, entity):
        self.config_fixture.config(list_limit=10)
        # Should get back just 10 entities
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))
        self.assertTrue(hints.limit['truncated'])

        # Override with driver specific limit
        if entity == 'project':
            self.config_fixture.config(group='resource', list_limit=5)
        else:
            self.config_fixture.config(group='identity', list_limit=5)

        # Should get back just 5 users
        hints = driver_hints.Hints()
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))

        # Finally, let's pretend we want to get the full list of entities,
        # even with the limits set, as part of some internal calculation.
        # Calling the API without a hints list should achieve this, and
        # return at least the 20 entries we created (there may be other
        # entities lying around created by other tests/setup).
        entities = self._list_entities(entity)()
        self.assertTrue(len(entities) >= 20)
        self._match_with_list(self.entity_lists[entity], entities)

    def test_list_users_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('user')

    def test_list_groups_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('group')

    def test_list_projects_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('project')
