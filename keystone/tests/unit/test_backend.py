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
import datetime
import hashlib
import uuid

from keystoneclient.common import cms
import mock
from oslo_config import cfg
from oslo_utils import timeutils
import six
from testtools import matchers

from keystone.catalog import core
from keystone.common import driver_hints
from keystone import exception
from keystone.tests import unit as tests
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import filtering
from keystone.tests.unit import utils as test_utils
from keystone.token import provider


CONF = cfg.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id
NULL_OBJECT = object()


class IdentityTests(object):
    def _get_domain_fixture(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        return domain

    def _set_domain_scope(self, domain_id):
        # We only provide a domain scope if we have multiple drivers
        if CONF.identity.domain_specific_drivers_enabled:
            return domain_id

    def test_project_add_and_remove_user_role(self):
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

        self.assignment_api.add_role_to_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertIn(self.user_two['id'], user_ids)

        self.assignment_api.remove_role_from_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])

        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], user_ids)

    def test_remove_user_role_not_assigned(self):
        # Expect failure if attempt to remove a role that was never assigned to
        # the user.
        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.
                          remove_role_from_user_and_project,
                          tenant_id=self.tenant_bar['id'],
                          user_id=self.user_two['id'],
                          role_id=self.role_other['id'])

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
        self.assertDictEqual(user_ref, self.user_sna)

    def test_authenticate_and_get_roles_no_metadata(self):
        user = {
            'name': 'NO_META',
            'domain_id': DEFAULT_DOMAIN_ID,
            'password': 'no_meta2',
        }
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
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
        }
        self.identity_api.create_user(user)

        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          context={},
                          user_id=id_,
                          password='password')

    def test_create_unicode_user_name(self):
        unicode_name = u'name \u540d\u5b57'
        user = {'name': unicode_name,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        ref = self.identity_api.create_user(user)
        self.assertEqual(unicode_name, ref['name'])

    def test_get_project(self):
        tenant_ref = self.resource_api.get_project(self.tenant_bar['id'])
        self.assertDictEqual(tenant_ref, self.tenant_bar)

    def test_get_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          uuid.uuid4().hex)

    def test_get_project_by_name(self):
        tenant_ref = self.resource_api.get_project_by_name(
            self.tenant_bar['name'],
            DEFAULT_DOMAIN_ID)
        self.assertDictEqual(tenant_ref, self.tenant_bar)

    def test_get_project_by_name_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project_by_name,
                          uuid.uuid4().hex,
                          DEFAULT_DOMAIN_ID)

    def test_list_user_ids_for_project(self):
        user_ids = self.assignment_api.list_user_ids_for_project(
            self.tenant_baz['id'])
        self.assertEqual(2, len(user_ids))
        self.assertIn(self.user_two['id'], user_ids)
        self.assertIn(self.user_badguy['id'], user_ids)

    def test_list_user_ids_for_project_no_duplicates(self):
        # Create user
        user_ref = {
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
            'password': uuid.uuid4().hex,
            'enabled': True}
        user_ref = self.identity_api.create_user(user_ref)
        # Create project
        project_ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(
            project_ref['id'], project_ref)
        # Create 2 roles and give user each role in project
        for i in range(2):
            role_ref = {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
            self.role_api.create_role(role_ref['id'], role_ref)
            self.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                tenant_id=project_ref['id'],
                role_id=role_ref['id'])
        # Get the list of user_ids in project
        user_ids = self.assignment_api.list_user_ids_for_project(
            project_ref['id'])
        # Ensure the user is only returned once
        self.assertEqual(1, len(user_ids))

    def test_get_project_user_ids_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.list_user_ids_for_project,
                          uuid.uuid4().hex)

    def test_get_user(self):
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

    @tests.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user(self):
        user = {
            'name': uuid.uuid4().hex.lower(),
            'domain_id': DEFAULT_DOMAIN_ID
        }
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
        user = {
            'name': uuid.uuid4().hex.lower(),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        self.identity_api.create_user(user)
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

    def test_get_user_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          uuid.uuid4().hex)

    def test_get_user_by_name(self):
        user_ref = self.identity_api.get_user_by_name(
            self.user_foo['name'], DEFAULT_DOMAIN_ID)
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

    @tests.skip_if_cache_disabled('identity')
    def test_cache_layer_get_user_by_name(self):
        user = {
            'name': uuid.uuid4().hex.lower(),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        # delete bypassing the identity api.
        domain_id, driver, entity_id = (
            self.identity_api._get_domain_driver_and_entity_id(ref['id']))
        driver.delete_user(entity_id)

        self.assertDictEqual(ref, self.identity_api.get_user_by_name(
            user['name'], DEFAULT_DOMAIN_ID))
        self.identity_api.get_user_by_name.invalidate(
            self.identity_api, user['name'], DEFAULT_DOMAIN_ID)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'], DEFAULT_DOMAIN_ID)
        user = {
            'name': uuid.uuid4().hex.lower(),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        self.identity_api.create_user(user)
        ref = self.identity_api.get_user_by_name(user['name'],
                                                 user['domain_id'])
        user['description'] = uuid.uuid4().hex
        user_updated = self.identity_api.update_user(ref['id'], user)
        self.assertDictContainsSubset(self.identity_api.get_user(ref['id']),
                                      user_updated)
        self.assertDictContainsSubset(
            self.identity_api.get_user_by_name(ref['name'], ref['domain_id']),
            user_updated)

    def test_get_user_by_name_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          uuid.uuid4().hex,
                          DEFAULT_DOMAIN_ID)

    def test_create_duplicate_user_name_fails(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'fakepass',
                'tenants': ['bar']}
        user = self.identity_api.create_user(user)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_user,
                          user)

    def test_create_duplicate_user_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        user1 = {'name': uuid.uuid4().hex,
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': uuid.uuid4().hex}
        user2 = {'name': user1['name'],
                 'domain_id': new_domain['id'],
                 'password': uuid.uuid4().hex}
        self.identity_api.create_user(user1)
        self.identity_api.create_user(user2)

    def test_move_user_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        user = {'name': uuid.uuid4().hex,
                'domain_id': domain1['id'],
                'password': uuid.uuid4().hex}
        user = self.identity_api.create_user(user)
        user['domain_id'] = domain2['id']
        self.identity_api.update_user(user['id'], user)

    def test_move_user_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a user in domain1
        user1 = {'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex}
        user1 = self.identity_api.create_user(user1)
        # Now create a user in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        user2 = {'name': user1['name'],
                 'domain_id': domain2['id'],
                 'password': uuid.uuid4().hex}
        user2 = self.identity_api.create_user(user2)
        # Now try and move user1 into the 2nd domain - which should
        # fail since the names clash
        user1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user1['id'],
                          user1)

    def test_rename_duplicate_user_name_fails(self):
        user1 = {'name': 'fake1',
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': 'fakepass',
                 'tenants': ['bar']}
        user2 = {'name': 'fake2',
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': 'fakepass',
                 'tenants': ['bar']}
        self.identity_api.create_user(user1)
        user2 = self.identity_api.create_user(user2)
        user2['name'] = 'fake1'
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user2['id'],
                          user2)

    def test_update_user_id_fails(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'fakepass',
                'tenants': ['bar']}
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

    def test_create_duplicate_project_id_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['name'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.resource_api.create_project,
                          'fake1',
                          tenant)

    def test_create_duplicate_project_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.resource_api.create_project,
                          'fake1',
                          tenant)

    def test_create_duplicate_project_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        tenant1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID}
        tenant2 = {'id': uuid.uuid4().hex, 'name': tenant1['name'],
                   'domain_id': new_domain['id']}
        self.resource_api.create_project(tenant1['id'], tenant1)
        self.resource_api.create_project(tenant2['id'], tenant2)

    def test_move_project_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain1['id']}
        self.resource_api.create_project(project['id'], project)
        project['domain_id'] = domain2['id']
        self.resource_api.update_project(project['id'], project)

    def test_move_project_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a project in domain1
        project1 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        # Now create a project in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        project2 = {'id': uuid.uuid4().hex,
                    'name': project1['name'],
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project2['id'], project2)
        # Now try and move project1 into the 2nd domain - which should
        # fail since the names clash
        project1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.resource_api.update_project,
                          project1['id'],
                          project1)

    def test_rename_duplicate_project_name_fails(self):
        tenant1 = {'id': 'fake1', 'name': 'fake1',
                   'domain_id': DEFAULT_DOMAIN_ID}
        tenant2 = {'id': 'fake2', 'name': 'fake2',
                   'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant1)
        self.resource_api.create_project('fake2', tenant2)
        tenant2['name'] = 'fake1'
        self.assertRaises(exception.Error,
                          self.resource_api.update_project,
                          'fake2',
                          tenant2)

    def test_update_project_id_does_nothing(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['id'] = 'fake2'
        self.resource_api.update_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual('fake1', tenant_ref['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          'fake2')

    def test_list_role_assignments_unfiltered(self):
        """Test for unfiltered listing role assignments.

        Test Plan:

        - Create a domain, with a user, group & project
        - Find how many role assignments already exist (from default
          fixtures)
        - Create a grant of each type (user/group on project/domain)
        - Check the number of assignments has gone up by 4 and that
          the entries we added are in the list returned
        - Check that if we list assignments by role_id, then we get back
          assignments that only contain that role.

        """
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_project = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.resource_api.create_project(new_project['id'], new_project)

        # First check how many role grants already exist
        existing_assignments = len(self.assignment_api.list_role_assignments())
        existing_assignments_for_role = len(
            self.assignment_api.list_role_assignments_for_role(
                role_id='admin'))

        # Now create the grants (roles are defined in default_fixtures)
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         project_id=new_project['id'],
                                         role_id='other')
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='admin')
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=new_project['id'],
                                         role_id='admin')

        # Read back the full list of assignments - check it is gone up by 4
        assignment_list = self.assignment_api.list_role_assignments()
        self.assertEqual(existing_assignments + 4, len(assignment_list))

        # Now check that each of our four new entries are in the list
        self.assertIn(
            {'user_id': new_user['id'], 'domain_id': new_domain['id'],
             'role_id': 'member'},
            assignment_list)
        self.assertIn(
            {'user_id': new_user['id'], 'project_id': new_project['id'],
             'role_id': 'other'},
            assignment_list)
        self.assertIn(
            {'group_id': new_group['id'], 'domain_id': new_domain['id'],
             'role_id': 'admin'},
            assignment_list)
        self.assertIn(
            {'group_id': new_group['id'], 'project_id': new_project['id'],
             'role_id': 'admin'},
            assignment_list)

        # Read back the list of assignments for just the admin role, checking
        # this only goes up by two.
        assignment_list = self.assignment_api.list_role_assignments_for_role(
            role_id='admin')
        self.assertEqual(existing_assignments_for_role + 2,
                         len(assignment_list))

        # Now check that each of our two new entries are in the list
        self.assertIn(
            {'group_id': new_group['id'], 'domain_id': new_domain['id'],
             'role_id': 'admin'},
            assignment_list)
        self.assertIn(
            {'group_id': new_group['id'], 'project_id': new_project['id'],
             'role_id': 'admin'},
            assignment_list)

    def test_list_group_role_assignment(self):
        # When a group role assignment is created and the role assignments are
        # listed then the group role assignment is included in the list.

        MEMBER_ROLE_ID = 'member'

        def get_member_assignments():
            assignments = self.assignment_api.list_role_assignments()
            return filter(lambda x: x['role_id'] == MEMBER_ROLE_ID,
                          assignments)

        orig_member_assignments = get_member_assignments()

        # Create a group.
        new_group = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': self.getUniqueString(prefix='tlgra')}
        new_group = self.identity_api.create_group(new_group)

        # Create a project.
        new_project = {
            'id': uuid.uuid4().hex,
            'name': self.getUniqueString(prefix='tlgra'),
            'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(new_project['id'], new_project)

        # Assign a role to the group.
        self.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=MEMBER_ROLE_ID)

        # List role assignments
        new_member_assignments = get_member_assignments()

        expected_member_assignments = orig_member_assignments + [{
            'group_id': new_group['id'], 'project_id': new_project['id'],
            'role_id': MEMBER_ROLE_ID}]
        self.assertThat(new_member_assignments,
                        matchers.Equals(expected_member_assignments))

    def test_list_role_assignments_bad_role(self):
        assignment_list = self.assignment_api.list_role_assignments_for_role(
            role_id=uuid.uuid4().hex)
        self.assertEqual([], assignment_list)

    def test_add_duplicate_role_grant(self):
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        self.assertRaises(exception.Conflict,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          self.role_admin['id'])

    def test_get_role_by_user_and_project_with_user_in_group(self):
        """Test for get role by user and project, user was added into a group.

        Test Plan:

        - Create a user, a project & a group, add this user to group
        - Create roles and grant them to user and project
        - Check the role list get by the user and project was as expected

        """
        user_ref = {'name': uuid.uuid4().hex,
                    'domain_id': DEFAULT_DOMAIN_ID,
                    'password': uuid.uuid4().hex,
                    'enabled': True}
        user_ref = self.identity_api.create_user(user_ref)

        project_ref = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex,
                       'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(project_ref['id'], project_ref)

        group = {'name': uuid.uuid4().hex,
                 'domain_id': DEFAULT_DOMAIN_ID}
        group_id = self.identity_api.create_group(group)['id']
        self.identity_api.add_user_to_group(user_ref['id'], group_id)

        role_ref_list = []
        for i in range(2):
            role_ref = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role_ref['id'], role_ref)
            role_ref_list.append(role_ref)

            self.assignment_api.add_role_to_user_and_project(
                user_id=user_ref['id'],
                tenant_id=project_ref['id'],
                role_id=role_ref['id'])

        role_list = self.assignment_api.get_roles_for_user_and_project(
            user_id=user_ref['id'],
            tenant_id=project_ref['id'])

        self.assertEqual(set(role_list),
                         set([r['id'] for r in role_ref_list]))

    def test_get_role_by_user_and_project(self):
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertNotIn('member', roles_ref)

        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertIn('member', roles_ref)

    def test_get_roles_for_user_and_domain(self):
        """Test for getting roles for user on a domain.

        Test Plan:

        - Create a domain, with 2 users
        - Check no roles yet exit
        - Give user1 two roles on the domain, user2 one role
        - Get roles on user1 and the domain - maybe sure we only
          get back the 2 roles on user1
        - Delete both roles from user1
        - Check we get no roles back for user1 on domain

        """
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                     'enabled': True, 'domain_id': new_domain['id']}
        new_user1 = self.identity_api.create_user(new_user1)
        new_user2 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                     'enabled': True, 'domain_id': new_domain['id']}
        new_user2 = self.identity_api.create_user(new_user2)
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now create the grants (roles are defined in default_fixtures)
        self.assignment_api.create_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        self.assignment_api.create_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='other')
        self.assignment_api.create_grant(user_id=new_user2['id'],
                                         domain_id=new_domain['id'],
                                         role_id='admin')
        # Read back the roles for user1 on domain
        roles_ids = self.assignment_api.get_roles_for_user_and_domain(
            new_user1['id'], new_domain['id'])
        self.assertEqual(2, len(roles_ids))
        self.assertIn(self.role_member['id'], roles_ids)
        self.assertIn(self.role_other['id'], roles_ids)

        # Now delete both grants for user1
        self.assignment_api.delete_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        self.assignment_api.delete_grant(user_id=new_user1['id'],
                                         domain_id=new_domain['id'],
                                         role_id='other')
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))

    def test_get_roles_for_user_and_domain_404(self):
        """Test errors raised when getting roles for user on a domain.

        Test Plan:

        - Check non-existing user gives UserNotFound
        - Check non-existing domain gives DomainNotFound

        """
        new_domain = self._get_domain_fixture()
        new_user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                     'enabled': True, 'domain_id': new_domain['id']}
        new_user1 = self.identity_api.create_user(new_user1)

        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.get_roles_for_user_and_domain,
                          uuid.uuid4().hex,
                          new_domain['id'])

        self.assertRaises(exception.DomainNotFound,
                          self.assignment_api.get_roles_for_user_and_domain,
                          new_user1['id'],
                          uuid.uuid4().hex)

    def test_get_roles_for_user_and_project_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.get_roles_for_user_and_project,
                          uuid.uuid4().hex,
                          self.tenant_bar['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.get_roles_for_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex)

    def test_add_role_to_user_and_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex,
                          self.role_admin['id'])

        self.assertRaises(exception.RoleNotFound,
                          self.assignment_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

    def test_add_role_to_user_and_project_no_user(self):
        # If add_role_to_user_and_project and the user doesn't exist, then
        # no error.
        user_id_not_exist = uuid.uuid4().hex
        self.assignment_api.add_role_to_user_and_project(
            user_id_not_exist, self.tenant_bar['id'], self.role_admin['id'])

    def test_remove_role_from_user_and_project(self):
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        self.assignment_api.remove_role_from_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn('member', roles_ref)
        self.assertRaises(exception.NotFound,
                          self.assignment_api.
                          remove_role_from_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          'member')

    def test_get_role_grant_by_user_and_project(self):
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(1, len(roles_ref))
        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_admin['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'],
                      [role_ref['id'] for role_ref in roles_ref])

        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(self.role_admin['id'], roles_ref_ids)
        self.assertIn('member', roles_ref_ids)

    def test_remove_role_grant_from_user_and_project(self):
        self.assignment_api.create_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(user_id=self.user_foo['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          user_id=self.user_foo['id'],
                          domain_id=self.domain_default['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.check_grant_role_id,
                          group_id=uuid.uuid4().hex,
                          domain_id=self.domain_default['id'],
                          role_id='member')

    def test_del_role_assignment_by_project_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_del_role_assignment_by_domain_not_found(self):
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=self.user_foo['id'],
                          domain_id=self.domain_default['id'],
                          role_id='member')

        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=uuid.uuid4().hex,
                          domain_id=self.domain_default['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': 'secret',
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          project_id=self.tenant_bar['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_domain(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))

        self.assignment_api.create_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.resource_api.create_project(new_project['id'], new_project)
        new_group = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_group2 = {'domain_id': new_domain['id'], 'name': uuid.uuid4().hex}
        new_group2 = self.identity_api.create_group(new_group2)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        new_user2 = {'name': 'new_user2', 'password': uuid.uuid4().hex,
                     'enabled': True, 'domain_id': new_domain['id']}
        new_user2 = self.identity_api.create_user(new_user2)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        # First check we have no grants
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        # Now add the grant we are going to test for, and some others as
        # well just to make sure we get back the right one
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')

        self.assignment_api.create_grant(group_id=new_group2['id'],
                                         domain_id=new_domain['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(user_id=new_user2['id'],
                                         domain_id=new_domain['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=new_group['id'],
                                         project_id=new_project['id'],
                                         role_id=self.role_admin['id'])

        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(group_id=new_group['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        new_user = {'name': 'new_user', 'password': 'secret',
                    'enabled': True, 'domain_id': new_domain['id']}
        new_user = self.identity_api.create_user(new_user)
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=new_user['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.assignment_api.delete_grant(user_id=new_user['id'],
                                         domain_id=new_domain['id'],
                                         role_id='member')
        roles_ref = self.assignment_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=new_user['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        group1_domain1_role = {'id': uuid.uuid4().hex,
                               'name': uuid.uuid4().hex}
        self.role_api.create_role(group1_domain1_role['id'],
                                  group1_domain1_role)
        group1_domain2_role = {'id': uuid.uuid4().hex,
                               'name': uuid.uuid4().hex}
        self.role_api.create_role(group1_domain2_role['id'],
                                  group1_domain2_role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        group1 = {'domain_id': domain1['id'], 'name': uuid.uuid4().hex}
        group1 = self.identity_api.create_group(group1)
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=group1_domain1_role['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=group1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(roles_ref[0], group1_domain1_role)
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(roles_ref[0], group1_domain2_role)

        self.assignment_api.delete_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=group1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          group_id=group1['id'],
                          domain_id=domain2['id'],
                          role_id=group1_domain2_role['id'])

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        user1_domain1_role = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.role_api.create_role(user1_domain1_role['id'], user1_domain1_role)
        user1_domain2_role = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.role_api.create_role(user1_domain2_role['id'], user1_domain2_role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=user1_domain1_role['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain2['id'],
                                         role_id=user1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(roles_ref[0], user1_domain1_role)
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(roles_ref[0], user1_domain2_role)

        self.assignment_api.delete_grant(user_id=user1['id'],
                                         domain_id=domain2['id'],
                                         role_id=user1_domain2_role['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEqual(0, len(roles_ref))
        self.assertRaises(exception.RoleAssignmentNotFound,
                          self.assignment_api.delete_grant,
                          user_id=user1['id'],
                          domain_id=domain2['id'],
                          role_id=user1_domain2_role['id'])

    def test_role_grant_by_group_and_cross_domain_project(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)
        role2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role2['id'], role2)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group1 = self.identity_api.create_group(group1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project1['id'], project1)
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role2['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.assignment_api.delete_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(roles_ref[0], role2)

    def test_role_grant_by_user_and_cross_domain_project(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)
        role2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role2['id'], role2)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project1['id'], project1)
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role2['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for ref in roles_ref:
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.assignment_api.delete_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        self.assertDictEqual(roles_ref[0], role2)

    def test_delete_user_grant_no_user(self):
        # Can delete a grant where the user doesn't exist.
        role_id = uuid.uuid4().hex
        role = {'id': role_id, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role_id, role)

        user_id = uuid.uuid4().hex

        self.assignment_api.create_grant(role_id, user_id=user_id,
                                         project_id=self.tenant_bar['id'])

        self.assignment_api.delete_grant(role_id, user_id=user_id,
                                         project_id=self.tenant_bar['id'])

    def test_delete_group_grant_no_group(self):
        # Can delete a grant where the group doesn't exist.
        role_id = uuid.uuid4().hex
        role = {'id': role_id, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role_id, role)

        group_id = uuid.uuid4().hex

        self.assignment_api.create_grant(role_id, group_id=group_id,
                                         project_id=self.tenant_bar['id'])

        self.assignment_api.delete_grant(role_id, group_id=group_id,
                                         project_id=self.tenant_bar['id'])

    def test_grant_crud_throws_exception_if_invalid_role(self):
        """Ensure RoleNotFound thrown if role does not exist."""

        def assert_role_not_found_exception(f, **kwargs):
            self.assertRaises(exception.RoleNotFound, f,
                              role_id=uuid.uuid4().hex, **kwargs)

        user = {'name': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex, 'enabled': True}
        user_resp = self.identity_api.create_user(user)
        group = {'name': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                 'enabled': True}
        group_resp = self.identity_api.create_group(group)
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID}
        project_resp = self.resource_api.create_project(project['id'], project)

        for manager_call in [self.assignment_api.create_grant,
                             self.assignment_api.get_grant,
                             self.assignment_api.delete_grant]:
            assert_role_not_found_exception(
                manager_call,
                user_id=user_resp['id'], project_id=project_resp['id'])
            assert_role_not_found_exception(
                manager_call,
                group_id=group_resp['id'], project_id=project_resp['id'])
            assert_role_not_found_exception(
                manager_call,
                user_id=user_resp['id'], domain_id=DEFAULT_DOMAIN_ID)
            assert_role_not_found_exception(
                manager_call,
                group_id=group_resp['id'], domain_id=DEFAULT_DOMAIN_ID)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        role_list = []
        for _ in range(10):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group1 = self.identity_api.create_group(group1)
        group2 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group2 = self.identity_api.create_group(group2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[5]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[6]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[7]['id'])
        roles_ref = self.assignment_api.list_grants(user_id=user1['id'],
                                                    domain_id=domain1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[0], roles_ref)
        self.assertIn(role_list[1], roles_ref)
        roles_ref = self.assignment_api.list_grants(group_id=group1['id'],
                                                    domain_id=domain1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[2], roles_ref)
        self.assertIn(role_list[3], roles_ref)
        roles_ref = self.assignment_api.list_grants(user_id=user1['id'],
                                                    project_id=project1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[4], roles_ref)
        self.assertIn(role_list[5], roles_ref)
        roles_ref = self.assignment_api.list_grants(group_id=group1['id'],
                                                    project_id=project1['id'])
        self.assertEqual(2, len(roles_ref))
        self.assertIn(role_list[6], roles_ref)
        self.assertIn(role_list[7], roles_ref)

        # Now test the alternate way of getting back lists of grants,
        # where user and group roles are combined.  These should match
        # the above results.
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(4, len(combined_list))
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)
        self.assertIn(role_list[6]['id'], combined_list)
        self.assertIn(role_list[7]['id'], combined_list)

        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
        self.assertEqual(4, len(combined_role_list))
        self.assertIn(role_list[0]['id'], combined_role_list)
        self.assertIn(role_list[1]['id'], combined_role_list)
        self.assertIn(role_list[2]['id'], combined_role_list)
        self.assertIn(role_list[3]['id'], combined_role_list)

    def test_multi_group_grants_on_project_domain(self):
        """Test multiple group roles for user on project and domain.

        Test Plan:

        - Create 6 roles
        - Create a domain, with a project, user and two groups
        - Make the user a member of both groups
        - Check no roles yet exit
        - Assign a role to each user and both groups on both the
          project and domain
        - Get a list of effective roles for the user on both the
          project and domain, checking we get back the correct three
          roles

        """
        role_list = []
        for _ in range(6):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group1 = self.identity_api.create_group(group1)
        group2 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group2 = self.identity_api.create_group(group2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[5]['id'])

        # Read by the roles, ensuring we get the correct 3 roles for
        # both project and domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(3, len(combined_list))
        self.assertIn(role_list[3]['id'], combined_list)
        self.assertIn(role_list[4]['id'], combined_list)
        self.assertIn(role_list[5]['id'], combined_list)

        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
        self.assertEqual(3, len(combined_role_list))
        self.assertIn(role_list[0]['id'], combined_role_list)
        self.assertIn(role_list[1]['id'], combined_role_list)
        self.assertIn(role_list[2]['id'], combined_role_list)

    def test_delete_role_with_user_and_group_grants(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group1 = self.identity_api.create_group(group1)
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(1, len(roles_ref))
        self.role_api.delete_role(role1['id'])
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))
        roles_ref = self.assignment_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEqual(0, len(roles_ref))

    def test_delete_user_with_group_project_domain_links(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
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
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
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

    def test_delete_domain_with_user_group_project_links(self):
        # TODO(chungg):add test case once expected behaviour defined
        pass

    def test_add_user_to_project(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertIn(self.tenant_baz, tenants)

    def test_add_user_to_project_missing_default_role(self):
        self.role_api.delete_role(CONF.member_role_id)
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          CONF.member_role_id)
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        tenants = (
            self.assignment_api.list_projects_for_user(self.user_foo['id']))
        self.assertIn(self.tenant_baz, tenants)
        default_role = self.role_api.get_role(CONF.member_role_id)
        self.assertIsNotNone(default_role)

    def test_add_user_to_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.add_user_to_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

    def test_add_user_to_project_no_user(self):
        # If add_user_to_project and the user doesn't exist, then
        # no error.
        user_id_not_exist = uuid.uuid4().hex
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user_id_not_exist)

    def test_remove_user_from_project(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        self.assignment_api.remove_user_from_project(self.tenant_baz['id'],
                                                     self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertNotIn(self.tenant_baz, tenants)

    def test_remove_user_from_project_race_delete_role(self):
        self.assignment_api.add_user_to_project(self.tenant_baz['id'],
                                                self.user_foo['id'])
        self.assignment_api.add_role_to_user_and_project(
            tenant_id=self.tenant_baz['id'],
            user_id=self.user_foo['id'],
            role_id=self.role_other['id'])

        # Mock a race condition, delete a role after
        # get_roles_for_user_and_project() is called in
        # remove_user_from_project().
        roles = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_baz['id'])
        self.role_api.delete_role(self.role_other['id'])
        self.assignment_api.get_roles_for_user_and_project = mock.Mock(
            return_value=roles)
        self.assignment_api.remove_user_from_project(self.tenant_baz['id'],
                                                     self.user_foo['id'])
        tenants = self.assignment_api.list_projects_for_user(
            self.user_foo['id'])
        self.assertNotIn(self.tenant_baz, tenants)

    def test_remove_user_from_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.assignment_api.remove_user_from_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.remove_user_from_project,
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.assignment_api.remove_user_from_project,
                          self.tenant_baz['id'],
                          self.user_foo['id'])

    def test_list_user_project_ids_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          uuid.uuid4().hex)

    def test_update_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.update_project,
                          uuid.uuid4().hex,
                          dict())

    def test_delete_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.delete_project,
                          uuid.uuid4().hex)

    def test_update_user_404(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.update_user,
                          user_id,
                          {'id': user_id,
                           'domain_id': DEFAULT_DOMAIN_ID})

    def test_delete_user_with_project_association(self):
        user = {'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_user_with_project_roles(self):
        user = {'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        user = self.identity_api.create_user(user)
        self.assignment_api.add_role_to_user_and_project(
            user['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_delete_user_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_delete_role_404(self):
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.delete_role,
                          uuid.uuid4().hex)

    def test_create_update_delete_unicode_project(self):
        unicode_project_name = u'name \u540d\u5b57'
        project = {'id': uuid.uuid4().hex,
                   'name': unicode_project_name,
                   'description': uuid.uuid4().hex,
                   'domain_id': CONF.identity.default_domain_id}
        self.resource_api.create_project(project['id'], project)
        self.resource_api.update_project(project['id'], project)
        self.resource_api.delete_project(project['id'])

    def test_create_project_with_no_enabled_field(self):
        ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex.lower(),
            'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(ref['id'], ref)

        project = self.resource_api.get_project(ref['id'])
        self.assertIs(project['enabled'], True)

    def test_create_project_long_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'a' * 65,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          tenant['id'],
                          tenant)

    def test_create_project_blank_name_fails(self):
        tenant = {'id': 'fake1', 'name': '',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          tenant['id'],
                          tenant)

    def test_create_project_invalid_name_fails(self):
        tenant = {'id': 'fake1', 'name': None,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          tenant['id'],
                          tenant)
        tenant = {'id': 'fake1', 'name': 123,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          tenant['id'],
                          tenant)

    def test_update_project_blank_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          tenant['id'],
                          tenant)

    def test_update_project_long_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['name'] = 'a' * 65
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          tenant['id'],
                          tenant)

    def test_update_project_invalid_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          tenant['id'],
                          tenant)

        tenant['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          tenant['id'],
                          tenant)

    def test_create_user_long_name_fails(self):
        user = {'name': 'a' * 256,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_blank_name_fails(self):
        user = {'name': '',
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_create_user_missed_password(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
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
        user = {'name': 'fake1', 'password': None,
                'domain_id': DEFAULT_DOMAIN_ID}
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
        user = {'name': None,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

        user = {'name': 123,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_update_project_invalid_enabled_type_string(self):
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'enabled': True,
                   'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertEqual(True, project_ref['enabled'])

        # Strings are not valid boolean values
        project['enabled'] = "false"
        self.assertRaises(exception.ValidationError,
                          self.resource_api.update_project,
                          project['id'],
                          project)

    def test_create_project_invalid_enabled_type_string(self):
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID,
                   # invalid string value
                   'enabled': "true"}
        self.assertRaises(exception.ValidationError,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_user_invalid_enabled_type_string(self):
        user = {'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex,
                # invalid string value
                'enabled': "true"}
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)

    def test_update_user_long_name_fails(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
        user = self.identity_api.create_user(user)
        user['name'] = 'a' * 256
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_blank_name_fails(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
        user = self.identity_api.create_user(user)
        user['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_user_invalid_name_fails(self):
        user = {'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
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
            domain_scope=self._set_domain_scope(DEFAULT_DOMAIN_ID))
        self.assertEqual(len(default_fixtures.USERS), len(users))
        user_ids = set(user['id'] for user in users)
        expected_user_ids = set(getattr(self, 'user_%s' % user['id'])['id']
                                for user in default_fixtures.USERS)
        for user_ref in users:
            self.assertNotIn('password', user_ref)
        self.assertEqual(expected_user_ids, user_ids)

    def test_list_groups(self):
        group1 = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': uuid.uuid4().hex}
        group2 = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': uuid.uuid4().hex}
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)
        groups = self.identity_api.list_groups(
            domain_scope=self._set_domain_scope(DEFAULT_DOMAIN_ID))
        self.assertEqual(2, len(groups))
        group_ids = []
        for group in groups:
            group_ids.append(group.get('id'))
        self.assertIn(group1['id'], group_ids)
        self.assertIn(group2['id'], group_ids)

    def test_list_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        self.resource_api.create_domain(domain2['id'], domain2)
        domains = self.resource_api.list_domains()
        self.assertEqual(3, len(domains))
        domain_ids = []
        for domain in domains:
            domain_ids.append(domain.get('id'))
        self.assertIn(DEFAULT_DOMAIN_ID, domain_ids)
        self.assertIn(domain1['id'], domain_ids)
        self.assertIn(domain2['id'], domain_ids)

    def test_list_projects(self):
        projects = self.resource_api.list_projects()
        self.assertEqual(4, len(projects))
        project_ids = []
        for project in projects:
            project_ids.append(project.get('id'))
        self.assertIn(self.tenant_bar['id'], project_ids)
        self.assertIn(self.tenant_baz['id'], project_ids)

    def test_list_projects_with_multiple_filters(self):
        # Create a project
        project = {'id': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                   'name': uuid.uuid4().hex, 'description': uuid.uuid4().hex,
                   'enabled': True, 'parent_id': None}
        self.resource_api.create_project(project['id'], project)

        # Build driver hints with the project's name and inexistent description
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', uuid.uuid4().hex)

        # Retrieve projects based on hints and check an empty list is returned
        projects = self.resource_api.list_projects(hints)
        self.assertEqual([], projects)

        # Build correct driver hints
        hints = driver_hints.Hints()
        hints.add_filter('name', project['name'])
        hints.add_filter('description', project['description'])

        # Retrieve projects based on hints
        projects = self.resource_api.list_projects(hints)

        # Check that the returned list contains only the first project
        self.assertEqual(1, len(projects))
        self.assertEqual(project, projects[0])

    def test_list_projects_for_domain(self):
        project_ids = ([x['id'] for x in
                       self.resource_api.list_projects_in_domain(
                           DEFAULT_DOMAIN_ID)])
        self.assertEqual(4, len(project_ids))
        self.assertIn(self.tenant_bar['id'], project_ids)
        self.assertIn(self.tenant_baz['id'], project_ids)
        self.assertIn(self.tenant_mtu['id'], project_ids)
        self.assertIn(self.tenant_service['id'], project_ids)

    @tests.skip_if_no_multiple_domains_support
    def test_list_projects_for_alternate_domain(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project2['id'], project2)
        project_ids = ([x['id'] for x in
                       self.resource_api.list_projects_in_domain(
                           domain1['id'])])
        self.assertEqual(2, len(project_ids))
        self.assertIn(project1['id'], project_ids)
        self.assertIn(project2['id'], project_ids)

    def _create_projects_hierarchy(self, hierarchy_size=2,
                                   domain_id=DEFAULT_DOMAIN_ID):
        """Creates a project hierarchy with specified size.

        :param hierarchy_size: the desired hierarchy size, default is 2 -
                               a project with one child.
        :param domain_id: domain where the projects hierarchy will be created.

        :returns projects: a list of the projects in the created hierarchy.

        """
        project_id = uuid.uuid4().hex
        project = {'id': project_id,
                   'description': '',
                   'domain_id': domain_id,
                   'enabled': True,
                   'name': uuid.uuid4().hex,
                   'parent_id': None}
        self.resource_api.create_project(project_id, project)

        projects = [project]
        for i in range(1, hierarchy_size):
            new_project = {'id': uuid.uuid4().hex,
                           'description': '',
                           'domain_id': domain_id,
                           'enabled': True,
                           'name': uuid.uuid4().hex,
                           'parent_id': project_id}
            self.resource_api.create_project(new_project['id'], new_project)
            projects.append(new_project)
            project_id = new_project['id']

        return projects

    def test_check_leaf_projects(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        self.assertFalse(self.resource_api.is_leaf_project(
            root_project['id']))
        self.assertTrue(self.resource_api.is_leaf_project(
            leaf_project['id']))

        # Delete leaf_project
        self.resource_api.delete_project(leaf_project['id'])

        # Now, root_project should be leaf
        self.assertTrue(self.resource_api.is_leaf_project(
            root_project['id']))

    def test_list_projects_in_subtree(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = {'id': uuid.uuid4().hex,
                    'description': '',
                    'domain_id': DEFAULT_DOMAIN_ID,
                    'enabled': True,
                    'name': uuid.uuid4().hex,
                    'parent_id': project2['id']}
        self.resource_api.create_project(project4['id'], project4)

        subtree = self.resource_api.list_projects_in_subtree(project1['id'])
        self.assertEqual(3, len(subtree))
        self.assertIn(project2, subtree)
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = self.resource_api.list_projects_in_subtree(project2['id'])
        self.assertEqual(2, len(subtree))
        self.assertIn(project3, subtree)
        self.assertIn(project4, subtree)

        subtree = self.resource_api.list_projects_in_subtree(project3['id'])
        self.assertEqual(0, len(subtree))

    def test_list_project_parents(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]
        project4 = {'id': uuid.uuid4().hex,
                    'description': '',
                    'domain_id': DEFAULT_DOMAIN_ID,
                    'enabled': True,
                    'name': uuid.uuid4().hex,
                    'parent_id': project2['id']}
        self.resource_api.create_project(project4['id'], project4)

        parents1 = self.resource_api.list_project_parents(project3['id'])
        self.assertEqual(2, len(parents1))
        self.assertIn(project1, parents1)
        self.assertIn(project2, parents1)

        parents2 = self.resource_api.list_project_parents(project4['id'])
        self.assertEqual(parents1, parents2)

        parents = self.resource_api.list_project_parents(project1['id'])
        self.assertEqual(0, len(parents))

    def test_delete_project_with_role_assignments(self):
        tenant = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(tenant['id'], tenant)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], tenant['id'], 'member')
        self.resource_api.delete_project(tenant['id'])
        self.assertRaises(exception.NotFound,
                          self.resource_api.get_project,
                          tenant['id'])

    def test_delete_role_check_role_grant(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        alt_role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role['id'], role)
        self.role_api.create_role(alt_role['id'], alt_role)
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], role['id'])
        self.assignment_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], alt_role['id'])
        self.role_api.delete_role(role['id'])
        roles_ref = self.assignment_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(role['id'], roles_ref)
        self.assertIn(alt_role['id'], roles_ref)

    def test_create_project_doesnt_modify_passed_in_dict(self):
        new_project = {'id': 'tenant_id', 'name': uuid.uuid4().hex,
                       'domain_id': DEFAULT_DOMAIN_ID}
        original_project = new_project.copy()
        self.resource_api.create_project('tenant_id', new_project)
        self.assertDictEqual(original_project, new_project)

    def test_create_user_doesnt_modify_passed_in_dict(self):
        new_user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                    'domain_id': DEFAULT_DOMAIN_ID}
        original_user = new_user.copy()
        self.identity_api.create_user(new_user)
        self.assertDictEqual(original_user, new_user)

    def test_update_user_enable(self):
        user = {'name': 'fake1', 'enabled': True,
                'domain_id': DEFAULT_DOMAIN_ID}
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(True, user_ref['enabled'])

        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        # If not present, enabled field should not be updated
        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(False, user_ref['enabled'])

        user['enabled'] = True
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(user['enabled'], user_ref['enabled'])

        del user['enabled']
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(True, user_ref['enabled'])

        # Integers are valid Python's booleans. Explicitly test it.
        user['enabled'] = 0
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(False, user_ref['enabled'])

        # Any integers other than 0 are interpreted as True
        user['enabled'] = -42
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(True, user_ref['enabled'])

    def test_update_user_name(self):
        user = {'name': uuid.uuid4().hex,
                'enabled': True,
                'domain_id': DEFAULT_DOMAIN_ID}
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
        user = {'name': 'fake1', 'enabled': True,
                'domain_id': DEFAULT_DOMAIN_ID}
        user = self.identity_api.create_user(user)
        user_ref = self.identity_api.get_user(user['id'])
        self.assertEqual(True, user_ref['enabled'])

        # Strings are not valid boolean values
        user['enabled'] = "false"
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          user['id'],
                          user)

    def test_update_project_enable(self):
        tenant = {'id': 'fake1', 'name': 'fake1', 'enabled': True,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual(True, tenant_ref['enabled'])

        tenant['enabled'] = False
        self.resource_api.update_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual(tenant['enabled'], tenant_ref['enabled'])

        # If not present, enabled field should not be updated
        del tenant['enabled']
        self.resource_api.update_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual(False, tenant_ref['enabled'])

        tenant['enabled'] = True
        self.resource_api.update_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual(tenant['enabled'], tenant_ref['enabled'])

        del tenant['enabled']
        self.resource_api.update_project('fake1', tenant)
        tenant_ref = self.resource_api.get_project('fake1')
        self.assertEqual(True, tenant_ref['enabled'])

    def test_add_user_to_group(self):
        domain = self._get_domain_fixture()
        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])

        found = False
        for x in groups:
            if (x['id'] == new_group['id']):
                found = True
        self.assertTrue(found)

    def test_add_user_to_group_404(self):
        domain = self._get_domain_fixture()
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.add_user_to_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
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
        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        self.identity_api.check_user_in_group(new_user['id'], new_group['id'])

    def test_create_invalid_domain_fails(self):
        new_group = {'domain_id': "doesnotexist", 'name': uuid.uuid4().hex}
        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.create_group,
                          new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': "doesnotexist"}
        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.create_user,
                          new_user)

    def test_check_user_not_in_group(self):
        new_group = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)

        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': DEFAULT_DOMAIN_ID}
        new_user = self.identity_api.create_user(new_user)

        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          new_user['id'],
                          new_group['id'])

    def test_check_user_in_group_404(self):
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': DEFAULT_DOMAIN_ID}
        new_user = self.identity_api.create_user(new_user)

        new_group = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': uuid.uuid4().hex}
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
        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        # Make sure we get an empty list back on a new group, not an error.
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        self.assertEqual([], user_refs)
        # Make sure we get the correct users back once they have been added
        # to the group.
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
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

    def test_list_users_in_group_404(self):
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
            new_user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                        'enabled': True, 'domain_id': domain['id']}
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
            new_group = {'domain_id': domain['id'],
                         'name': uuid.uuid4().hex}
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
        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertIn(new_group['id'], [x['id'] for x in groups])
        self.identity_api.remove_user_from_group(new_user['id'],
                                                 new_group['id'])
        groups = self.identity_api.list_groups_for_user(new_user['id'])
        self.assertNotIn(new_group['id'], [x['id'] for x in groups])

    def test_remove_user_from_group_404(self):
        domain = self._get_domain_fixture()
        new_user = {'name': 'new_user', 'password': uuid.uuid4().hex,
                    'enabled': True, 'domain_id': domain['id']}
        new_user = self.identity_api.create_user(new_user)
        new_group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
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
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        group = {'domain_id': domain['id'], 'name': uuid.uuid4().hex}
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
        group_name = uuid.uuid4().hex
        group = {'domain_id': DEFAULT_DOMAIN_ID, 'name': group_name}
        group = self.identity_api.create_group(group)
        spoiler = {'domain_id': DEFAULT_DOMAIN_ID, 'name': uuid.uuid4().hex}
        self.identity_api.create_group(spoiler)

        group_ref = self.identity_api.get_group_by_name(
            group_name, DEFAULT_DOMAIN_ID)
        self.assertDictEqual(group_ref, group)

    def test_get_group_by_name_404(self):
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.get_group_by_name,
                          uuid.uuid4().hex,
                          DEFAULT_DOMAIN_ID)

    @tests.skip_if_cache_disabled('identity')
    def test_cache_layer_group_crud(self):
        group = {'domain_id': DEFAULT_DOMAIN_ID, 'name': uuid.uuid4().hex}
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

        group = {'domain_id': DEFAULT_DOMAIN_ID, 'name': uuid.uuid4().hex}
        group = self.identity_api.create_group(group)
        # cache the result
        self.identity_api.get_group(group['id'])
        group['name'] = uuid.uuid4().hex
        group_ref = self.identity_api.update_group(group['id'], group)
        # after updating through identity api, get updated group
        self.assertDictContainsSubset(self.identity_api.get_group(group['id']),
                                      group_ref)

    def test_create_duplicate_group_name_fails(self):
        group1 = {'domain_id': DEFAULT_DOMAIN_ID, 'name': uuid.uuid4().hex}
        group2 = {'domain_id': DEFAULT_DOMAIN_ID, 'name': group1['name']}
        group1 = self.identity_api.create_group(group1)
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_group,
                          group2)

    def test_create_duplicate_group_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(new_domain['id'], new_domain)
        group1 = {'domain_id': DEFAULT_DOMAIN_ID, 'name': uuid.uuid4().hex}
        group2 = {'domain_id': new_domain['id'], 'name': group1['name']}
        group1 = self.identity_api.create_group(group1)
        group2 = self.identity_api.create_group(group2)

    def test_move_group_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        group = {'name': uuid.uuid4().hex,
                 'domain_id': domain1['id']}
        group = self.identity_api.create_group(group)
        group['domain_id'] = domain2['id']
        self.identity_api.update_group(group['id'], group)

    def test_move_group_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        # First, create a group in domain1
        group1 = {'name': uuid.uuid4().hex,
                  'domain_id': domain1['id']}
        group1 = self.identity_api.create_group(group1)
        # Now create a group in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        group2 = {'name': group1['name'],
                  'domain_id': domain2['id']}
        group2 = self.identity_api.create_group(group2)
        # Now try and move group1 into the 2nd domain - which should
        # fail since the names clash
        group1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_group,
                          group1['id'],
                          group1)

    @tests.skip_if_no_multiple_domains_support
    def test_project_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.resource_api.create_domain(domain['id'], domain)
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': domain['id']}
        self.resource_api.create_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        project['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)
        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

    def test_domain_delete_hierarchy(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.resource_api.create_domain(domain['id'], domain)

        # Creating a root and a leaf project inside the domain
        projects_hierarchy = self._create_projects_hierarchy(
            domain_id=domain['id'])
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[0]

        # Disable the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        self.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

        # Make sure the root project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project['id'])

        # Make sure the leaf project no longer exists
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          leaf_project['id'])

    def test_hierarchical_projects_crud(self):
        # create a hierarchy with just a root project (which is a leaf as well)
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=1)
        root_project1 = projects_hierarchy[0]

        # create a hierarchy with one root project and one leaf project
        projects_hierarchy = self._create_projects_hierarchy()
        root_project2 = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        # update description from leaf_project
        leaf_project['description'] = 'new description'
        self.resource_api.update_project(leaf_project['id'], leaf_project)
        proj_ref = self.resource_api.get_project(leaf_project['id'])
        self.assertDictEqual(proj_ref, leaf_project)

        # update the parent_id is not allowed
        leaf_project['parent_id'] = root_project1['id']
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

        # delete root_project1
        self.resource_api.delete_project(root_project1['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project1['id'])

        # delete root_project2 is not allowed since it is not a leaf project
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.delete_project,
                          root_project2['id'])

    def test_create_project_with_invalid_parent(self):
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'description': '',
                   'domain_id': DEFAULT_DOMAIN_ID,
                   'enabled': True,
                   'parent_id': 'fake'}
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.create_project,
                          project['id'],
                          project)

    def test_create_leaf_project_with_invalid_domain(self):
        root_project = {'id': uuid.uuid4().hex,
                        'name': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': DEFAULT_DOMAIN_ID,
                        'enabled': True,
                        'parent_id': None}
        self.resource_api.create_project(root_project['id'], root_project)

        leaf_project = {'id': uuid.uuid4().hex,
                        'name': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': 'fake',
                        'enabled': True,
                        'parent_id': root_project['id']}

        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.create_project,
                          leaf_project['id'],
                          leaf_project)

    def test_delete_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        self.resource_api.delete_project(leaf_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          leaf_project['id'])

        self.resource_api.delete_project(root_project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          root_project['id'])

    def test_delete_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.delete_project,
                          root_project['id'])

    def test_update_project_parent(self):
        projects_hierarchy = self._create_projects_hierarchy(hierarchy_size=3)
        project1 = projects_hierarchy[0]
        project2 = projects_hierarchy[1]
        project3 = projects_hierarchy[2]

        # project2 is the parent from project3
        self.assertEqual(project3.get('parent_id'), project2['id'])

        # try to update project3 parent to parent1
        project3['parent_id'] = project1['id']
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          project3['id'],
                          project3)

    def test_create_project_under_disabled_one(self):
        project1 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': DEFAULT_DOMAIN_ID,
                    'enabled': False,
                    'parent_id': None}
        self.resource_api.create_project(project1['id'], project1)

        project2 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': DEFAULT_DOMAIN_ID,
                    'parent_id': project1['id']}

        # It's not possible to create a project under a disabled one in the
        # hierarchy
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.create_project,
                          project2['id'],
                          project2)

    def test_disable_hierarchical_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        leaf_project = projects_hierarchy[1]

        leaf_project['enabled'] = False
        self.resource_api.update_project(leaf_project['id'], leaf_project)

        project_ref = self.resource_api.get_project(leaf_project['id'])
        self.assertEqual(project_ref['enabled'], leaf_project['enabled'])

    def test_disable_hierarchical_not_leaf_project(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]

        root_project['enabled'] = False
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          root_project['id'],
                          root_project)

    def test_enable_project_with_disabled_parent(self):
        projects_hierarchy = self._create_projects_hierarchy()
        root_project = projects_hierarchy[0]
        leaf_project = projects_hierarchy[1]

        # Disable leaf and root
        leaf_project['enabled'] = False
        self.resource_api.update_project(leaf_project['id'], leaf_project)
        root_project['enabled'] = False
        self.resource_api.update_project(root_project['id'], root_project)

        # Try to enable the leaf project, it's not possible since it has
        # a disabled parent
        leaf_project['enabled'] = True
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.update_project,
                          leaf_project['id'],
                          leaf_project)

    def _get_hierarchy_depth(self, project_id):
        return len(self.resource_api.list_project_parents(project_id)) + 1

    def test_check_hierarchy_depth(self):
        # First create a hierarchy with the max allowed depth
        projects_hierarchy = self._create_projects_hierarchy(
            CONF.max_project_tree_depth)
        leaf_project = projects_hierarchy[CONF.max_project_tree_depth - 1]

        depth = self._get_hierarchy_depth(leaf_project['id'])
        self.assertEqual(CONF.max_project_tree_depth, depth)

        # Creating another project in the hierarchy shouldn't be allowed
        project_id = uuid.uuid4().hex
        project = {
            'id': project_id,
            'name': uuid.uuid4().hex,
            'domain_id': DEFAULT_DOMAIN_ID,
            'parent_id': leaf_project['id']}
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.create_project,
                          project_id,
                          project)

    def test_project_update_missing_attrs_with_a_value(self):
        # Creating a project with no description attribute.
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID,
                   'enabled': True,
                   'parent_id': None}
        self.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

    def test_project_update_missing_attrs_with_a_falsey_value(self):
        # Creating a project with no description attribute.
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID,
                   'enabled': True,
                   'parent_id': None}
        self.resource_api.create_project(project['id'], project)

        # Add a description attribute.
        project['description'] = ''
        self.resource_api.update_project(project['id'], project)

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, project)

    def test_domain_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.resource_api.create_domain(domain['id'], domain)
        domain_ref = self.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain_ref, domain)

        domain['name'] = uuid.uuid4().hex
        self.resource_api.update_domain(domain['id'], domain)
        domain_ref = self.resource_api.get_domain(domain['id'])
        self.assertDictEqual(domain_ref, domain)

        # Ensure an 'enabled' domain cannot be deleted
        self.assertRaises(exception.ForbiddenAction,
                          self.resource_api.delete_domain,
                          domain_id=domain['id'])

        # Disable the domain
        domain['enabled'] = False
        self.resource_api.update_domain(domain['id'], domain)

        # Delete the domain
        self.resource_api.delete_domain(domain['id'])

        # Make sure the domain no longer exists
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain['id'])

    @tests.skip_if_no_multiple_domains_support
    def test_create_domain_case_sensitivity(self):
        # create a ref with a lowercase name
        ref = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex.lower()}
        self.resource_api.create_domain(ref['id'], ref)

        # assign a new ID with the same name, but this time in uppercase
        ref['id'] = uuid.uuid4().hex
        ref['name'] = ref['name'].upper()
        self.resource_api.create_domain(ref['id'], ref)

    def test_attribute_update(self):
        project = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex}
        self.resource_api.create_project(project['id'], project)

        # pick a key known to be non-existent
        key = 'description'

        def assert_key_equals(value):
            project_ref = self.resource_api.update_project(
                project['id'], project)
            self.assertEqual(value, project_ref[key])
            project_ref = self.resource_api.get_project(project['id'])
            self.assertEqual(value, project_ref[key])

        def assert_get_key_is(value):
            project_ref = self.resource_api.update_project(
                project['id'], project)
            self.assertIs(project_ref.get(key), value)
            project_ref = self.resource_api.get_project(project['id'])
            self.assertIs(project_ref.get(key), value)

        # add an attribute that doesn't exist, set it to a falsey value
        value = ''
        project[key] = value
        assert_key_equals(value)

        # set an attribute with a falsey value to null
        value = None
        project[key] = value
        assert_get_key_is(value)

        # do it again, in case updating from this situation is handled oddly
        value = None
        project[key] = value
        assert_get_key_is(value)

        # set a possibly-null value to a falsey value
        value = ''
        project[key] = value
        assert_key_equals(value)

        # set a falsey value to a truthy value
        value = uuid.uuid4().hex
        project[key] = value
        assert_key_equals(value)

    def test_user_crud(self):
        user_dict = {'domain_id': DEFAULT_DOMAIN_ID,
                     'name': uuid.uuid4().hex, 'password': 'passw0rd'}
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

    def test_list_projects_for_user(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(0, len(user_projects))
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_baz['id'],
                                         role_id=self.role_member['id'])
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(2, len(user_projects))

    def test_list_projects_for_user_with_grants(self):
        # Create two groups each with a role on a different project, and
        # make user1 a member of both groups.  Both these new projects
        # should now be included, along with any direct user grants.
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group1 = self.identity_api.create_group(group1)
        group2 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group2 = self.identity_api.create_group(group2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project2['id'], project2)
        self.identity_api.add_user_to_group(user1['id'], group1['id'])
        self.identity_api.add_user_to_group(user1['id'], group2['id'])

        # Create 3 grants, one user grant, the other two as group grants
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         project_id=project1['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         project_id=project2['id'],
                                         role_id=self.role_admin['id'])
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(3, len(user_projects))

    @tests.skip_if_cache_disabled('resource')
    @tests.skip_if_no_multiple_domains_support
    def test_domain_rename_invalidates_get_domain_by_name_cache(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        domain_id = domain['id']
        domain_name = domain['name']
        self.resource_api.create_domain(domain_id, domain)
        domain_ref = self.resource_api.get_domain_by_name(domain_name)
        domain_ref['name'] = uuid.uuid4().hex
        self.resource_api.update_domain(domain_id, domain_ref)
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain_by_name,
                          domain_name)

    @tests.skip_if_cache_disabled('resource')
    def test_cache_layer_domain_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        domain_id = domain['id']
        # Create Domain
        self.resource_api.create_domain(domain_id, domain)
        domain_ref = self.resource_api.get_domain(domain_id)
        updated_domain_ref = copy.deepcopy(domain_ref)
        updated_domain_ref['name'] = uuid.uuid4().hex
        # Update domain, bypassing resource api manager
        self.resource_api.driver.update_domain(domain_id, updated_domain_ref)
        # Verify get_domain still returns the domain
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Invalidate cache
        self.resource_api.get_domain.invalidate(self.resource_api,
                                                domain_id)
        # Verify get_domain returns the updated domain
        self.assertDictContainsSubset(
            updated_domain_ref, self.resource_api.get_domain(domain_id))
        # Update the domain back to original ref, using the assignment api
        # manager
        self.resource_api.update_domain(domain_id, domain_ref)
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Make sure domain is 'disabled', bypass resource api manager
        domain_ref_disabled = domain_ref.copy()
        domain_ref_disabled['enabled'] = False
        self.resource_api.driver.update_domain(domain_id,
                                               domain_ref_disabled)
        # Delete domain, bypassing resource api manager
        self.resource_api.driver.delete_domain(domain_id)
        # Verify get_domain still returns the domain
        self.assertDictContainsSubset(
            domain_ref, self.resource_api.get_domain(domain_id))
        # Invalidate cache
        self.resource_api.get_domain.invalidate(self.resource_api,
                                                domain_id)
        # Verify get_domain now raises DomainNotFound
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain, domain_id)
        # Recreate Domain
        self.resource_api.create_domain(domain_id, domain)
        self.resource_api.get_domain(domain_id)
        # Make sure domain is 'disabled', bypass resource api manager
        domain['enabled'] = False
        self.resource_api.driver.update_domain(domain_id, domain)
        # Delete domain
        self.resource_api.delete_domain(domain_id)
        # verify DomainNotFound raised
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain,
                          domain_id)

    @tests.skip_if_cache_disabled('resource')
    @tests.skip_if_no_multiple_domains_support
    def test_project_rename_invalidates_get_project_by_name_cache(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': domain['id']}
        project_id = project['id']
        project_name = project['name']
        self.resource_api.create_domain(domain['id'], domain)
        # Create a project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project_by_name(project_name, domain['id'])
        project['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project_id, project)
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project_by_name,
                          project_name,
                          domain['id'])

    @tests.skip_if_cache_disabled('resource')
    @tests.skip_if_no_multiple_domains_support
    def test_cache_layer_project_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': domain['id']}
        project_id = project['id']
        self.resource_api.create_domain(domain['id'], domain)
        # Create a project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project(project_id)
        updated_project = copy.deepcopy(project)
        updated_project['name'] = uuid.uuid4().hex
        # Update project, bypassing resource manager
        self.resource_api.driver.update_project(project_id,
                                                updated_project)
        # Verify get_project still returns the original project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Invalidate cache
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 project_id)
        # Verify get_project now returns the new project
        self.assertDictContainsSubset(
            updated_project,
            self.resource_api.get_project(project_id))
        # Update project using the resource_api manager back to original
        self.resource_api.update_project(project['id'], project)
        # Verify get_project returns the original project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Delete project bypassing resource
        self.resource_api.driver.delete_project(project_id)
        # Verify get_project still returns the project_ref
        self.assertDictContainsSubset(
            project, self.resource_api.get_project(project_id))
        # Invalidate cache
        self.resource_api.get_project.invalidate(self.resource_api,
                                                 project_id)
        # Verify ProjectNotFound now raised
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project_id)
        # recreate project
        self.resource_api.create_project(project_id, project)
        self.resource_api.get_project(project_id)
        # delete project
        self.resource_api.delete_project(project_id)
        # Verify ProjectNotFound is raised
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project_id)

    def create_user_dict(self, **attributes):
        user_dict = {'name': uuid.uuid4().hex,
                     'domain_id': DEFAULT_DOMAIN_ID,
                     'enabled': True}
        user_dict.update(attributes)
        return user_dict

    def test_arbitrary_attributes_are_returned_from_create_user(self):
        attr_value = uuid.uuid4().hex
        user_data = self.create_user_dict(arbitrary_attr=attr_value)

        user = self.identity_api.create_user(user_data)

        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_arbitrary_attributes_are_returned_from_get_user(self):
        attr_value = uuid.uuid4().hex
        user_data = self.create_user_dict(arbitrary_attr=attr_value)

        user_data = self.identity_api.create_user(user_data)

        user = self.identity_api.get_user(user_data['id'])
        self.assertEqual(attr_value, user['arbitrary_attr'])

    def test_new_arbitrary_attributes_are_returned_from_update_user(self):
        user_data = self.create_user_dict()

        user = self.identity_api.create_user(user_data)
        attr_value = uuid.uuid4().hex
        user['arbitrary_attr'] = attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(attr_value, updated_user['arbitrary_attr'])

    def test_updated_arbitrary_attributes_are_returned_from_update_user(self):
        attr_value = uuid.uuid4().hex
        user_data = self.create_user_dict(arbitrary_attr=attr_value)

        new_attr_value = uuid.uuid4().hex
        user = self.identity_api.create_user(user_data)
        user['arbitrary_attr'] = new_attr_value
        updated_user = self.identity_api.update_user(user['id'], user)

        self.assertEqual(new_attr_value, updated_user['arbitrary_attr'])

    def test_create_grant_no_user(self):
        # If call create_grant with a user that doesn't exist, doesn't fail.
        self.assignment_api.create_grant(
            self.role_other['id'],
            user_id=uuid.uuid4().hex,
            project_id=self.tenant_bar['id'])

    def test_create_grant_no_group(self):
        # If call create_grant with a group that doesn't exist, doesn't fail.
        self.assignment_api.create_grant(
            self.role_other['id'],
            group_id=uuid.uuid4().hex,
            project_id=self.tenant_bar['id'])

    @tests.skip_if_no_multiple_domains_support
    def test_get_default_domain_by_name(self):
        domain_name = 'default'

        domain = {'id': uuid.uuid4().hex, 'name': domain_name, 'enabled': True}
        self.resource_api.create_domain(domain['id'], domain)

        domain_ref = self.resource_api.get_domain_by_name(domain_name)
        self.assertEqual(domain, domain_ref)

    def test_get_not_default_domain_by_name(self):
        domain_name = 'foo'
        self.assertRaises(exception.DomainNotFound,
                          self.resource_api.get_domain_by_name,
                          domain_name)

    def test_project_update_and_project_get_return_same_response(self):
        project = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'description': uuid.uuid4().hex,
            'enabled': True}

        self.resource_api.create_project(project['id'], project)

        updated_project = {'enabled': False}
        updated_project_ref = self.resource_api.update_project(
            project['id'], updated_project)

        # SQL backend adds 'extra' field
        updated_project_ref.pop('extra', None)

        self.assertIs(False, updated_project_ref['enabled'])

        project_ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project_ref, updated_project_ref)

    def test_user_update_and_user_get_return_same_response(self):
        user = {
            'name': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'description': uuid.uuid4().hex,
            'enabled': True}

        user = self.identity_api.create_user(user)

        updated_user = {'enabled': False}
        updated_user_ref = self.identity_api.update_user(
            user['id'], updated_user)

        # SQL backend adds 'extra' field
        updated_user_ref.pop('extra', None)

        self.assertIs(False, updated_user_ref['enabled'])

        user_ref = self.identity_api.get_user(user['id'])
        self.assertDictEqual(user_ref, updated_user_ref)

    def test_delete_group_removes_role_assignments(self):
        # When a group is deleted any role assignments for the group are
        # removed.

        MEMBER_ROLE_ID = 'member'

        def get_member_assignments():
            assignments = self.assignment_api.list_role_assignments()
            return filter(lambda x: x['role_id'] == MEMBER_ROLE_ID,
                          assignments)

        orig_member_assignments = get_member_assignments()

        # Create a group.
        new_group = {
            'domain_id': DEFAULT_DOMAIN_ID,
            'name': self.getUniqueString(prefix='tdgrra')}
        new_group = self.identity_api.create_group(new_group)

        # Create a project.
        new_project = {
            'id': uuid.uuid4().hex,
            'name': self.getUniqueString(prefix='tdgrra'),
            'domain_id': DEFAULT_DOMAIN_ID}
        self.resource_api.create_project(new_project['id'], new_project)

        # Assign a role to the group.
        self.assignment_api.create_grant(
            group_id=new_group['id'], project_id=new_project['id'],
            role_id=MEMBER_ROLE_ID)

        # Delete the group.
        self.identity_api.delete_group(new_group['id'])

        # Check that the role assignment for the group is gone
        member_assignments = get_member_assignments()

        self.assertThat(member_assignments,
                        matchers.Equals(orig_member_assignments))

    def test_get_roles_for_groups_on_domain(self):
        """Test retrieving group domain roles.

        Test Plan:

        - Create a domain, three groups and three roles
        - Assign one an inherited and the others a non-inherited group role
          to the domain
        - Ensure that only the non-inherited roles are returned on the domain

        """
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(3):
            group = {'name': uuid.uuid4().hex, 'domain_id': domain1['id']}
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one is inherited
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the groups on the domain project. We
        # shouldn't get back the inherited role.

        role_refs = self.assignment_api.get_roles_for_groups(
            group_id_list, domain_id=domain1['id'])

        self.assertThat(role_refs, matchers.HasLength(2))
        self.assertIn(role_list[0], role_refs)
        self.assertIn(role_list[1], role_refs)

    def test_get_roles_for_groups_on_project(self):
        """Test retrieving group project roles.

        Test Plan:

        - Create two domains, two projects, six groups and six roles
        - Project1 is in Domain1, Project2 is in Domain2
        - Domain2/Project2 are spoilers
        - Assign a different direct group role to each project as well
          as both an inherited and non-inherited role to each domain
        - Get the group roles for Project 1 - depending on whether we have
          enabled inheritance, we should either get back just the direct role
          or both the direct one plus the inherited domain role from Domain 1

        """
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project2['id'], project2)
        group_list = []
        group_id_list = []
        role_list = []
        for _ in range(6):
            group = {'name': uuid.uuid4().hex, 'domain_id': domain1['id']}
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[2]['id'])

        # ...and a duplicate set of spoiler assignments to Domain2/Project2
        self.assignment_api.create_grant(group_id=group_list[3]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[3]['id'])
        self.assignment_api.create_grant(group_id=group_list[4]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[4]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[5]['id'],
                                         project_id=project2['id'],
                                         role_id=role_list[5]['id'])

        # Now get the effective roles for all groups on the Project1. With
        # inheritance off, we should only get back the direct role.

        self.config_fixture.config(group='os_inherit', enabled=False)
        role_refs = self.assignment_api.get_roles_for_groups(
            group_id_list, project_id=project1['id'])

        self.assertThat(role_refs, matchers.HasLength(1))
        self.assertIn(role_list[2], role_refs)

        # With inheritance on, we should also get back the inherited role from
        # its owning domain.

        self.config_fixture.config(group='os_inherit', enabled=True)
        role_refs = self.assignment_api.get_roles_for_groups(
            group_id_list, project_id=project1['id'])

        self.assertThat(role_refs, matchers.HasLength(2))
        self.assertIn(role_list[1], role_refs)
        self.assertIn(role_list[2], role_refs)

    def test_list_domains_for_groups(self):
        """Test retrieving domains for a list of groups.

        Test Plan:

        - Create three domains, three groups and one role
        - Assign a non-inherited group role to two domains, and an inherited
          group role to the third
        - Ensure only the domains with non-inherited roles are returned

        """
        domain_list = []
        group_list = []
        group_id_list = []
        for _ in range(3):
            domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.resource_api.create_domain(domain['id'], domain)
            domain_list.append(domain)

            group = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
            group = self.identity_api.create_group(group)
            group_list.append(group)
            group_id_list.append(group['id'])

        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(role1['id'], role1)

        # Assign the roles - one is inherited
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain_list[0]['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain_list[1]['id'],
                                         role_id=role1['id'])
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         domain_id=domain_list[2]['id'],
                                         role_id=role1['id'],
                                         inherited_to_projects=True)

        # Now list the domains that have roles for any of the 3 groups
        # We shouldn't get back domain[2] since that had an inherited role.

        domain_refs = (
            self.assignment_api.list_domains_for_groups(group_id_list))

        self.assertThat(domain_refs, matchers.HasLength(2))
        self.assertIn(domain_list[0], domain_refs)
        self.assertIn(domain_list[1], domain_refs)

    def test_list_projects_for_groups(self):
        """Test retrieving projects for a list of groups.

        Test Plan:

        - Create two domains, four projects, seven groups and seven roles
        - Project1-3 are in Domain1, Project4 is in Domain2
        - Domain2/Project4 are spoilers
        - Project1 and 2 have direct group roles, Project3 has no direct
          roles but should inherit a group role from Domain1
        - Get the projects for the group roles that are assigned to Project1
          Project2 and the inherited one on Domain1. Depending on whether we
          have enabled inheritance, we should either get back just the projects
          with direct roles (Project 1 and 2) or also Project3 due to its
          inherited role from Domain1.

        """
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        project1 = self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        project2 = self.resource_api.create_project(project2['id'], project2)
        project3 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        project3 = self.resource_api.create_project(project3['id'], project3)
        project4 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        project4 = self.resource_api.create_project(project4['id'], project4)
        group_list = []
        role_list = []
        for _ in range(7):
            group = {'name': uuid.uuid4().hex, 'domain_id': domain1['id']}
            group = self.identity_api.create_group(group)
            group_list.append(group)

            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        # Assign the roles - one inherited and one non-inherited on Domain1,
        # plus one on Project1 and Project2
        self.assignment_api.create_grant(group_id=group_list[0]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group_list[1]['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[2]['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[2]['id'])
        self.assignment_api.create_grant(group_id=group_list[3]['id'],
                                         project_id=project2['id'],
                                         role_id=role_list[3]['id'])

        # ...and a few of spoiler assignments to Domain2/Project4
        self.assignment_api.create_grant(group_id=group_list[4]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[4]['id'])
        self.assignment_api.create_grant(group_id=group_list[5]['id'],
                                         domain_id=domain2['id'],
                                         role_id=role_list[5]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group_list[6]['id'],
                                         project_id=project4['id'],
                                         role_id=role_list[6]['id'])

        # Now get the projects for the groups that have roles on Project1,
        # Project2 and the inherited role on Domain!. With inheritance off,
        # we should only get back the projects with direct role.

        self.config_fixture.config(group='os_inherit', enabled=False)
        group_id_list = [group_list[1]['id'], group_list[2]['id'],
                         group_list[3]['id']]
        project_refs = (
            self.assignment_api.list_projects_for_groups(group_id_list))

        self.assertThat(project_refs, matchers.HasLength(2))
        self.assertIn(project1, project_refs)
        self.assertIn(project2, project_refs)

        # With inheritance on, we should also get back the Project3 due to the
        # inherited role from its owning domain.

        self.config_fixture.config(group='os_inherit', enabled=True)
        project_refs = (
            self.assignment_api.list_projects_for_groups(group_id_list))

        self.assertThat(project_refs, matchers.HasLength(3))
        self.assertIn(project1, project_refs)
        self.assertIn(project2, project_refs)
        self.assertIn(project3, project_refs)

    def test_update_role_no_name(self):
        # A user can update a role and not include the name.

        # description is picked just because it's not name.
        self.role_api.update_role(self.role_member['id'],
                                  {'description': uuid.uuid4().hex})
        # If the previous line didn't raise an exception then the test passes.

    def test_update_role_same_name(self):
        # A user can update a role and set the name to be the same as it was.

        self.role_api.update_role(self.role_member['id'],
                                  {'name': self.role_member['name']})
        # If the previous line didn't raise an exception then the test passes.


class TokenTests(object):
    def _create_token_id(self):
        # Use a token signed by the cms module
        token_id = ""
        for i in range(1, 20):
            token_id += uuid.uuid4().hex
        return cms.cms_sign_token(token_id,
                                  CONF.signing.certfile,
                                  CONF.signing.keyfile)

    def _assert_revoked_token_list_matches_token_persistence(
            self, revoked_token_id_list):
        # Assert that the list passed in matches the list returned by the
        # token persistence service
        persistence_list = [
            x['id']
            for x in self.token_provider_api.list_revoked_tokens()
        ]
        self.assertEqual(persistence_list, revoked_token_id_list)

    def test_token_crud(self):
        token_id = self._create_token_id()
        data = {'id': token_id, 'a': 'b',
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        expires = data_ref.pop('expires')
        data_ref.pop('user_id')
        self.assertIsInstance(expires, datetime.datetime)
        data_ref.pop('id')
        data.pop('id')
        self.assertDictEqual(data_ref, data)

        new_data_ref = self.token_provider_api._persistence.get_token(token_id)
        expires = new_data_ref.pop('expires')
        self.assertIsInstance(expires, datetime.datetime)
        new_data_ref.pop('user_id')
        new_data_ref.pop('id')

        self.assertEqual(data, new_data_ref)

        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token, token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token, token_id)

    def create_token_sample_data(self, token_id=None, tenant_id=None,
                                 trust_id=None, user_id=None, expires=None):
        if token_id is None:
            token_id = self._create_token_id()
        if user_id is None:
            user_id = 'testuserid'
        # FIXME(morganfainberg): These tokens look nothing like "Real" tokens.
        # This should be fixed when token issuance is cleaned up.
        data = {'id': token_id, 'a': 'b',
                'user': {'id': user_id}}
        if tenant_id is not None:
            data['tenant'] = {'id': tenant_id, 'name': tenant_id}
        if tenant_id is NULL_OBJECT:
            data['tenant'] = None
        if expires is not None:
            data['expires'] = expires
        if trust_id is not None:
            data['trust_id'] = trust_id
            data.setdefault('access', {}).setdefault('trust', {})
            # Testuserid2 is used here since a trustee will be different in
            # the cases of impersonation and therefore should not match the
            # token's user_id.
            data['access']['trust']['trustee_user_id'] = 'testuserid2'
        data['token_version'] = provider.V2
        # Issue token stores a copy of all token data at token['token_data'].
        # This emulates that assumption as part of the test.
        data['token_data'] = copy.deepcopy(data)
        new_token = self.token_provider_api._persistence.create_token(token_id,
                                                                      data)
        return new_token['id'], data

    def test_delete_tokens(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid')
        token_id3, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(0, len(tokens))
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id2)

        self.token_provider_api._persistence.get_token(token_id3)

    def test_delete_tokens_trust(self):
        tokens = self.token_provider_api._persistence._list_tokens(
            user_id='testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            trust_id='testtrustid')
        token_id2, data = self.create_token_sample_data(
            tenant_id='testtenantid',
            user_id='testuserid1',
            trust_id='testtrustid1')
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_tokens(
            user_id='testuserid',
            tenant_id='testtenantid',
            trust_id='testtrustid')
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id1)
        self.token_provider_api._persistence.get_token(token_id2)

    def _test_token_list(self, token_list_fn):
        tokens = token_list_fn('testuserid')
        self.assertEqual(0, len(tokens))
        token_id1, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id1, tokens)
        token_id2, data = self.create_token_sample_data()
        tokens = token_list_fn('testuserid')
        self.assertEqual(2, len(tokens))
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id1)
        tokens = token_list_fn('testuserid')
        self.assertIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)
        self.token_provider_api._persistence.delete_token(token_id2)
        tokens = token_list_fn('testuserid')
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)

        # tenant-specific tokens
        tenant1 = uuid.uuid4().hex
        tenant2 = uuid.uuid4().hex
        token_id3, data = self.create_token_sample_data(tenant_id=tenant1)
        token_id4, data = self.create_token_sample_data(tenant_id=tenant2)
        # test for existing but empty tenant (LP:1078497)
        token_id5, data = self.create_token_sample_data(tenant_id=NULL_OBJECT)
        tokens = token_list_fn('testuserid')
        self.assertEqual(3, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)
        self.assertIn(token_id5, tokens)
        tokens = token_list_fn('testuserid', tenant2)
        self.assertEqual(1, len(tokens))
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)

    def test_token_list(self):
        self._test_token_list(
            self.token_provider_api._persistence._list_tokens)

    def test_token_list_trust(self):
        trust_id = uuid.uuid4().hex
        token_id5, data = self.create_token_sample_data(trust_id=trust_id)
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid', trust_id=trust_id)
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id5, tokens)

    def test_get_token_404(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          uuid.uuid4().hex)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          None)

    def test_delete_token_404(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.delete_token,
                          uuid.uuid4().hex)

    def test_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api._persistence.get_token,
                          token_id)

    def test_null_expires_token(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'id_hash': token_id, 'a': 'b', 'expires': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.assertIsNotNone(data_ref['expires'])
        new_data_ref = self.token_provider_api._persistence.get_token(token_id)

        # MySQL doesn't store microseconds, so discard them before testing
        data_ref['expires'] = data_ref['expires'].replace(microsecond=0)
        new_data_ref['expires'] = new_data_ref['expires'].replace(
            microsecond=0)

        self.assertEqual(data_ref, new_data_ref)

    def check_list_revoked_tokens(self, token_ids):
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        for token_id in token_ids:
            self.assertIn(token_id, revoked_ids)

    def delete_token(self):
        token_id = uuid.uuid4().hex
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        self.token_provider_api._persistence.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.get_token,
            data_ref['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api._persistence.delete_token,
            data_ref['id'])
        return token_id

    def test_list_revoked_tokens_returns_empty_list(self):
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertEqual([], revoked_ids)

    def test_list_revoked_tokens_for_single_token(self):
        self.check_list_revoked_tokens([self.delete_token()])

    def test_list_revoked_tokens_for_multiple_tokens(self):
        self.check_list_revoked_tokens([self.delete_token()
                                        for x in six.moves.range(2)])

    def test_flush_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)

        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_provider_api._persistence.create_token(token_id,
                                                                     data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)

        self.token_provider_api._persistence.flush_expired_tokens()
        tokens = self.token_provider_api._persistence._list_tokens(
            'testuserid')
        self.assertEqual(1, len(tokens))
        self.assertIn(token_id, tokens)

    @tests.skip_if_cache_disabled('token')
    def test_revocation_list_cache(self):
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=10)
        token_id = uuid.uuid4().hex
        token_data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                      'expires': expire_time,
                      'trust_id': None,
                      'user': {'id': 'testuserid'}}
        token2_id = uuid.uuid4().hex
        token2_data = {'id_hash': token2_id, 'id': token2_id, 'a': 'b',
                       'expires': expire_time,
                       'trust_id': None,
                       'user': {'id': 'testuserid'}}
        # Create 2 Tokens.
        self.token_provider_api._persistence.create_token(token_id,
                                                          token_data)
        self.token_provider_api._persistence.create_token(token2_id,
                                                          token2_data)
        # Verify the revocation list is empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Delete a token directly, bypassing the manager.
        self.token_provider_api._persistence.driver.delete_token(token_id)
        # Verify the revocation list is still empty.
        self.assertEqual(
            [], self.token_provider_api._persistence.list_revoked_tokens())
        self.assertEqual([], self.token_provider_api.list_revoked_tokens())
        # Invalidate the revocation list.
        self.token_provider_api._persistence.invalidate_revocation_list()
        # Verify the deleted token is in the revocation list.
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        # Delete the second token, through the manager
        self.token_provider_api._persistence.delete_token(token2_id)
        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        # Verify both tokens are in the revocation list.
        self.assertIn(token_id, revoked_ids)
        self.assertIn(token2_id, revoked_ids)

    def _test_predictable_revoked_pki_token_id(self, hash_fn):
        token_id = self._create_token_id()
        token_id_hash = hash_fn(token_id).hexdigest()
        token = {'user': {'id': uuid.uuid4().hex}}

        self.token_provider_api._persistence.create_token(token_id, token)
        self.token_provider_api._persistence.delete_token(token_id)

        revoked_ids = [x['id']
                       for x in self.token_provider_api.list_revoked_tokens()]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id_hash, revoked_ids)
        self.assertNotIn(token_id, revoked_ids)
        for t in self.token_provider_api._persistence.list_revoked_tokens():
            self.assertIn('expires', t)

    def test_predictable_revoked_pki_token_id_default(self):
        self._test_predictable_revoked_pki_token_id(hashlib.md5)

    def test_predictable_revoked_pki_token_id_sha256(self):
        self.config_fixture.config(group='token', hash_algorithm='sha256')
        self._test_predictable_revoked_pki_token_id(hashlib.sha256)

    def test_predictable_revoked_uuid_token_id(self):
        token_id = uuid.uuid4().hex
        token = {'user': {'id': uuid.uuid4().hex}}

        self.token_provider_api._persistence.create_token(token_id, token)
        self.token_provider_api._persistence.delete_token(token_id)

        revoked_tokens = self.token_provider_api.list_revoked_tokens()
        revoked_ids = [x['id'] for x in revoked_tokens]
        self._assert_revoked_token_list_matches_token_persistence(revoked_ids)
        self.assertIn(token_id, revoked_ids)
        for t in revoked_tokens:
            self.assertIn('expires', t)

    def test_create_unicode_token_id(self):
        token_id = six.text_type(self._create_token_id())
        self.create_token_sample_data(token_id=token_id)
        self.token_provider_api._persistence.get_token(token_id)

    def test_create_unicode_user_id(self):
        user_id = six.text_type(uuid.uuid4().hex)
        token_id, data = self.create_token_sample_data(user_id=user_id)
        self.token_provider_api._persistence.get_token(token_id)

    def test_token_expire_timezone(self):

        @test_utils.timezone
        def _create_token(expire_time):
            token_id = uuid.uuid4().hex
            user_id = six.text_type(uuid.uuid4().hex)
            return self.create_token_sample_data(token_id=token_id,
                                                 user_id=user_id,
                                                 expires=expire_time)

        for d in ['+0', '-11', '-8', '-5', '+5', '+8', '+14']:
            test_utils.TZ = 'UTC' + d
            expire_time = timeutils.utcnow() + datetime.timedelta(minutes=1)
            token_id, data_in = _create_token(expire_time)
            data_get = self.token_provider_api._persistence.get_token(token_id)

            self.assertEqual(data_in['id'], data_get['id'],
                             'TZ=%s' % test_utils.TZ)

            expire_time_expired = (
                timeutils.utcnow() + datetime.timedelta(minutes=-1))
            token_id, data_in = _create_token(expire_time_expired)
            self.assertRaises(exception.TokenNotFound,
                              self.token_provider_api._persistence.get_token,
                              data_in['id'])


class TokenCacheInvalidation(object):
    def _create_test_data(self):
        self.user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex,
                     'domain_id': DEFAULT_DOMAIN_ID, 'enabled': True}
        self.tenant = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                       'domain_id': DEFAULT_DOMAIN_ID, 'enabled': True}

        # Create an equivalent of a scoped token
        token_dict = {'user': self.user, 'tenant': self.tenant,
                      'metadata': {}, 'id': 'placeholder'}
        token_id, data = self.token_provider_api.issue_v2_token(token_dict)
        self.scoped_token_id = token_id

        # ..and an un-scoped one
        token_dict = {'user': self.user, 'tenant': None,
                      'metadata': {}, 'id': 'placeholder'}
        token_id, data = self.token_provider_api.issue_v2_token(token_dict)
        self.unscoped_token_id = token_id

        # Validate them, in the various ways possible - this will load the
        # responses into the token cache.
        self._check_scoped_tokens_are_valid()
        self._check_unscoped_tokens_are_valid()

    def _check_unscoped_tokens_are_invalid(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.unscoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.unscoped_token_id)

    def _check_scoped_tokens_are_invalid(self):
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.scoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_token,
            self.scoped_token_id,
            self.tenant['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.scoped_token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_provider_api.validate_v2_token,
            self.scoped_token_id,
            self.tenant['id'])

    def _check_scoped_tokens_are_valid(self):
        self.token_provider_api.validate_token(self.scoped_token_id)
        self.token_provider_api.validate_token(
            self.scoped_token_id, belongs_to=self.tenant['id'])
        self.token_provider_api.validate_v2_token(self.scoped_token_id)
        self.token_provider_api.validate_v2_token(
            self.scoped_token_id, belongs_to=self.tenant['id'])

    def _check_unscoped_tokens_are_valid(self):
        self.token_provider_api.validate_token(self.unscoped_token_id)
        self.token_provider_api.validate_v2_token(self.unscoped_token_id)

    def test_delete_unscoped_token(self):
        self.token_provider_api._persistence.delete_token(
            self.unscoped_token_id)
        self._check_unscoped_tokens_are_invalid()
        self._check_scoped_tokens_are_valid()

    def test_delete_scoped_token_by_id(self):
        self.token_provider_api._persistence.delete_token(self.scoped_token_id)
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_valid()

    def test_delete_scoped_token_by_user(self):
        self.token_provider_api._persistence.delete_tokens(self.user['id'])
        # Since we are deleting all tokens for this user, they should all
        # now be invalid.
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_invalid()

    def test_delete_scoped_token_by_user_and_tenant(self):
        self.token_provider_api._persistence.delete_tokens(
            self.user['id'],
            tenant_id=self.tenant['id'])
        self._check_scoped_tokens_are_invalid()
        self._check_unscoped_tokens_are_valid()


class TrustTests(object):
    def create_sample_trust(self, new_id, remaining_uses=None):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        trust_data = (self.trust_api.create_trust
                      (new_id,
                       {'trustor_user_id': self.trustor['id'],
                        'trustee_user_id': self.user_two['id'],
                        'project_id': self.tenant_bar['id'],
                        'expires_at': timeutils.
                        parse_isotime('2031-02-18T18:10:00Z'),
                        'impersonation': True,
                        'remaining_uses': remaining_uses},
                       roles=[{"id": "member"},
                              {"id": "other"},
                              {"id": "browser"}]))
        return trust_data

    def test_delete_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = self.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        self.trust_api.delete_trust(trust_id)
        self.assertIsNone(self.trust_api.get_trust(trust_id))

    def test_delete_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        self.assertRaises(exception.TrustNotFound,
                          self.trust_api.delete_trust,
                          trust_id)

    def test_get_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = self.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        self.trust_api.delete_trust(trust_data['id'])

    def test_get_deleted_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        self.assertIsNotNone(trust_data)
        self.assertIsNone(trust_data['deleted_at'])
        self.trust_api.delete_trust(new_id)
        self.assertIsNone(self.trust_api.get_trust(new_id))
        deleted_trust = self.trust_api.get_trust(trust_data['id'],
                                                 deleted=True)
        self.assertEqual(trust_data['id'], deleted_trust['id'])
        self.assertIsNotNone(deleted_trust.get('deleted_at'))

    def test_create_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)

        self.assertEqual(new_id, trust_data['id'])
        self.assertEqual(self.trustee['id'], trust_data['trustee_user_id'])
        self.assertEqual(self.trustor['id'], trust_data['trustor_user_id'])
        self.assertTrue(timeutils.normalize_time(trust_data['expires_at']) >
                        timeutils.utcnow())

        self.assertEqual([{'id': 'member'},
                          {'id': 'other'},
                          {'id': 'browser'}], trust_data['roles'])

    def test_list_trust_by_trustee(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustee(self.trustee['id'])
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustee_user_id"], self.trustee['id'])
        trusts = self.trust_api.list_trusts_for_trustee(self.trustor['id'])
        self.assertEqual(0, len(trusts))

    def test_list_trust_by_trustor(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustor(self.trustor['id'])
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustor_user_id"], self.trustor['id'])
        trusts = self.trust_api.list_trusts_for_trustor(self.trustee['id'])
        self.assertEqual(0, len(trusts))

    def test_list_trusts(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts()
        self.assertEqual(3, len(trusts))

    def test_trust_has_remaining_uses_positive(self):
        # create a trust with limited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=5)
        self.assertEqual(5, trust_data['remaining_uses'])
        # create a trust with unlimited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex)
        self.assertIsNone(trust_data['remaining_uses'])

    def test_trust_has_remaining_uses_negative(self):
        # try to create a trust with no remaining uses, check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=0)
        # try to create a trust with negative remaining uses,
        # check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=-12)

    def test_consume_use(self):
        # consume a trust repeatedly until it has no uses anymore
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=2)
        self.trust_api.consume_use(trust_data['id'])
        t = self.trust_api.get_trust(trust_data['id'])
        self.assertEqual(1, t['remaining_uses'])
        self.trust_api.consume_use(trust_data['id'])
        # This was the last use, the trust isn't available anymore
        self.assertIsNone(self.trust_api.get_trust(trust_data['id']))


class CatalogTests(object):

    _legacy_endpoint_id_in_endpoint = False
    _enabled_default_to_true_when_creating_endpoint = False

    def test_region_crud(self):
        # create
        region_id = '0' * 255
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex,
        }
        res = self.catalog_api.create_region(
            new_region.copy())
        # Ensure that we don't need to have a
        # parent_region_id in the original supplied
        # ref dict, but that it will be returned from
        # the endpoint, with None value.
        expected_region = new_region.copy()
        expected_region['parent_region_id'] = None
        self.assertDictEqual(res, expected_region)

        # Test adding another region with the one above
        # as its parent. We will check below whether deleting
        # the parent successfully deletes any child regions.
        parent_region_id = region_id
        region_id = uuid.uuid4().hex
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex,
            'parent_region_id': parent_region_id,
        }
        res = self.catalog_api.create_region(
            new_region.copy())
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
        new_region = {
            'id': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'parent_region_id': parent_id
        }
        self.catalog_api.create_region(
            new_region)
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

    @tests.skip_if_cache_disabled('catalog')
    def test_cache_layer_region_crud(self):
        region_id = uuid.uuid4().hex
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex,
        }
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

    @tests.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_region(self):
        region_id = uuid.uuid4().hex
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex
        }
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
        region_id = uuid.uuid4().hex
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex
        }
        self.catalog_api.create_region(new_region)
        # Create region again with duplicate id
        self.assertRaises(exception.Conflict,
                          self.catalog_api.create_region,
                          new_region)

    def test_get_region_404(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.get_region,
                          uuid.uuid4().hex)

    def test_delete_region_404(self):
        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.delete_region,
                          uuid.uuid4().hex)

    def test_create_region_invalid_parent_region_404(self):
        region_id = uuid.uuid4().hex
        new_region = {
            'id': region_id,
            'description': uuid.uuid4().hex,
            'parent_region_id': 'nonexisting'
        }
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

    @mock.patch.object(core.Driver,
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
        service_id = uuid.uuid4().hex
        new_service = {
            'id': service_id,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        res = self.catalog_api.create_service(
            service_id,
            new_service.copy())
        new_service['enabled'] = True
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
        service_id = uuid.uuid4().hex
        new_service = {
            'id': service_id,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        return self.catalog_api.create_service(service_id, new_service.copy())

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

    @tests.skip_if_cache_disabled('catalog')
    def test_cache_layer_service_crud(self):
        service_id = uuid.uuid4().hex
        new_service = {
            'id': service_id,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        res = self.catalog_api.create_service(
            service_id,
            new_service.copy())
        new_service['enabled'] = True
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

    @tests.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_service(self):
        service_id = uuid.uuid4().hex
        new_service = {
            'id': service_id,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(
            service_id,
            new_service.copy())

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
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = {
            'id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'interface': uuid.uuid4().hex[:8],
            'url': uuid.uuid4().hex,
            'service_id': service['id'],
        }
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
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint = {
            'id': uuid.uuid4().hex,
            'region_id': None,
            'interface': uuid.uuid4().hex[:8],
            'url': uuid.uuid4().hex,
            'service_id': service['id'],
        }
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
        second_endpoint = {
            'id': uuid.uuid4().hex,
            'region_id': None,
            'interface': uuid.uuid4().hex[:8],
            'url': uuid.uuid4().hex,
            'service_id': service['id'],
        }
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

    def test_get_service_404(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.get_service,
                          uuid.uuid4().hex)

    def test_delete_service_404(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_api.delete_service,
                          uuid.uuid4().hex)

    def test_create_endpoint_nonexistent_service(self):
        endpoint = {
            'id': uuid.uuid4().hex,
            'service_id': uuid.uuid4().hex,
        }
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_service(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = {
            'service_id': uuid.uuid4().hex,
        }
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_create_endpoint_nonexistent_region(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service.copy())

        endpoint = {
            'id': uuid.uuid4().hex,
            'region_id': None,
            'service_id': service['id'],
            'interface': 'public',
            'url': uuid.uuid4().hex,
            'region_id': uuid.uuid4().hex,
        }
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint)

    def test_update_endpoint_nonexistent_region(self):
        dummy_service, enabled_endpoint, dummy_disabled_endpoint = (
            self._create_endpoints())
        new_endpoint = {
            'region_id': uuid.uuid4().hex,
        }
        self.assertRaises(exception.ValidationError,
                          self.catalog_api.update_endpoint,
                          enabled_endpoint['id'],
                          new_endpoint)

    def test_get_endpoint_404(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.get_endpoint,
                          uuid.uuid4().hex)

    def test_delete_endpoint_404(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_api.delete_endpoint,
                          uuid.uuid4().hex)

    def test_create_endpoint(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service.copy())

        endpoint = {
            'id': uuid.uuid4().hex,
            'region_id': None,
            'service_id': service['id'],
            'interface': 'public',
            'url': uuid.uuid4().hex,
        }
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

    def test_update_endpoint(self):
        dummy_service_ref, endpoint_ref, dummy_disabled_endpoint_ref = (
            self._create_endpoints())
        res = self.catalog_api.update_endpoint(endpoint_ref['id'],
                                               {'interface': 'private'})
        expected_endpoint = endpoint_ref.copy()
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
            id_ = uuid.uuid4().hex
            ref = {
                'id': id_,
                'interface': 'public',
                'region_id': region,
                'service_id': service_id,
                'url': 'http://localhost/%s' % uuid.uuid4().hex,
            }
            ref.update(kwargs)
            self.catalog_api.create_endpoint(id_, ref)
            return ref

        # Create a service for use with the endpoints.
        service_id = uuid.uuid4().hex
        service_ref = {
            'id': service_id,
            'name': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service_id, service_ref)

        region = {'id': uuid.uuid4().hex}
        self.catalog_api.create_region(region)

        # Create endpoints
        enabled_endpoint_ref = create_endpoint(service_id, region['id'])
        disabled_endpoint_ref = create_endpoint(
            service_id, region['id'], enabled=False, interface='internal')

        return service_ref, enabled_endpoint_ref, disabled_endpoint_ref

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

    @tests.skip_if_cache_disabled('catalog')
    def test_invalidate_cache_when_updating_endpoint(self):
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
        }
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service
        endpoint_id = uuid.uuid4().hex
        endpoint = {
            'id': endpoint_id,
            'region_id': None,
            'interface': uuid.uuid4().hex[:8],
            'url': uuid.uuid4().hex,
            'service_id': service['id'],
        }
        self.catalog_api.create_endpoint(endpoint_id, endpoint)

        # cache the endpoint
        self.catalog_api.get_endpoint(endpoint_id)

        # update the endpoint via catalog api
        new_url = {'url': uuid.uuid4().hex}
        self.catalog_api.update_endpoint(endpoint_id, new_url)

        # assert that we can get the new endpoint
        current_endpoint = self.catalog_api.get_endpoint(endpoint_id)
        self.assertEqual(new_url['url'], current_endpoint['url'])


class PolicyTests(object):
    def _new_policy_ref(self):
        return {
            'id': uuid.uuid4().hex,
            'policy': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'endpoint_id': uuid.uuid4().hex,
        }

    def assertEqualPolicies(self, a, b):
        self.assertEqual(a['id'], b['id'])
        self.assertEqual(a['endpoint_id'], b['endpoint_id'])
        self.assertEqual(a['policy'], b['policy'])
        self.assertEqual(a['type'], b['type'])

    def test_create(self):
        ref = self._new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)
        self.assertEqualPolicies(ref, res)

    def test_get(self):
        ref = self._new_policy_ref()
        res = self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.get_policy(ref['id'])
        self.assertEqualPolicies(ref, res)

    def test_list(self):
        ref = self._new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)

        res = self.policy_api.list_policies()
        res = [x for x in res if x['id'] == ref['id']][0]
        self.assertEqualPolicies(ref, res)

    def test_update(self):
        ref = self._new_policy_ref()
        self.policy_api.create_policy(ref['id'], ref)
        orig = ref

        ref = self._new_policy_ref()

        # (cannot change policy ID)
        self.assertRaises(exception.ValidationError,
                          self.policy_api.update_policy,
                          orig['id'],
                          ref)

        ref['id'] = orig['id']
        res = self.policy_api.update_policy(orig['id'], ref)
        self.assertEqualPolicies(ref, res)

    def test_delete(self):
        ref = self._new_policy_ref()
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

    def test_get_policy_404(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.get_policy,
                          uuid.uuid4().hex)

    def test_update_policy_404(self):
        ref = self._new_policy_ref()
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.update_policy,
                          ref['id'],
                          ref)

    def test_delete_policy_404(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_api.delete_policy,
                          uuid.uuid4().hex)


class InheritanceTests(object):

    def test_inherited_role_grants_for_user(self):
        """Test inherited user roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create 3 roles
        - Create a domain, with a project and a user
        - Check no roles yet exit
        - Assign a direct user role to the project and a (non-inherited)
          user role to the domain
        - Get a list of effective roles - should only get the one direct role
        - Now add an inherited user role to the domain
        - Get a list of effective roles - should have two roles, one
          direct and one by virtue of the inherited user role
        - Also get effective roles for the domain - the role marked as
          inherited should not show up

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        role_list = []
        for _ in range(3):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create the first two roles - the domain one is not inherited
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add an inherited role on the domain
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the user and project again, this
        # should now include the inherited role on the domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(2, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[2]['id'], combined_list)

        # Finally, check that the inherited role does not appear as a valid
        # directly assigned role on the domain itself
        combined_role_list = self.assignment_api.get_roles_for_user_and_domain(
            user1['id'], domain1['id'])
        self.assertEqual(1, len(combined_role_list))
        self.assertIn(role_list[1]['id'], combined_role_list)

    def test_inherited_role_grants_for_group(self):
        """Test inherited group roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create 4 roles
        - Create a domain, with a project, user and two groups
        - Make the user a member of both groups
        - Check no roles yet exit
        - Assign a direct user role to the project and a (non-inherited)
          group role on the domain
        - Get a list of effective roles - should only get the one direct role
        - Now add two inherited group roles to the domain
        - Get a list of effective roles - should have three roles, one
          direct and two by virtue of inherited group roles

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        role_list = []
        for _ in range(4):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.role_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        user1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex, 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group1 = self.identity_api.create_group(group1)
        group2 = {'name': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'enabled': True}
        group2 = self.identity_api.create_group(group2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])

        roles_ref = self.assignment_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEqual(0, len(roles_ref))

        # Create two roles - the domain one is not inherited
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project1['id'],
                                         role_id=role_list[0]['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[1]['id'])

        # Now get the effective roles for the user and project, this
        # should only include the direct role assignment on the project
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(1, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)

        # Now add to more group roles, both inherited, to the domain
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[2]['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=domain1['id'],
                                         role_id=role_list[3]['id'],
                                         inherited_to_projects=True)

        # Now get the effective roles for the user and project again, this
        # should now include the inherited roles on the domain
        combined_list = self.assignment_api.get_roles_for_user_and_project(
            user1['id'], project1['id'])
        self.assertEqual(3, len(combined_list))
        self.assertIn(role_list[0]['id'], combined_list)
        self.assertIn(role_list[2]['id'], combined_list)
        self.assertIn(role_list[3]['id'], combined_list)

    def test_list_projects_for_user_with_inherited_grants(self):
        """Test inherited user roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a domain, with two projects and a user
        - Assign an inherited user role on the domain, as well as a direct
          user role to a separate project in a different domain
        - Get a list of projects for user, should return all three projects

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project2['id'], project2)

        # Create 2 grants, one on a project and one inherited grant
        # on the domain
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Should get back all three projects, one by virtue of the direct
        # grant, plus both projects in the domain
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(3, len(user_projects))

    def test_list_projects_for_user_with_inherited_user_project_grants(self):
        """Test inherited role assignments for users on nested projects.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a hierarchy of projects with one root and one leaf project
        - Assign an inherited user role on root project
        - Assign a non-inherited user role on root project
        - Get a list of projects for user, should return both projects
        - Disable OS-INHERIT extension
        - Get a list of projects for user, should return only root project

        """
        # Enable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=True)
        root_project = {'id': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': DEFAULT_DOMAIN_ID,
                        'enabled': True,
                        'name': uuid.uuid4().hex,
                        'parent_id': None}
        self.resource_api.create_project(root_project['id'], root_project)
        leaf_project = {'id': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': DEFAULT_DOMAIN_ID,
                        'enabled': True,
                        'name': uuid.uuid4().hex,
                        'parent_id': root_project['id']}
        self.resource_api.create_project(leaf_project['id'], leaf_project)

        user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID, 'enabled': True}
        user = self.identity_api.create_user(user)

        # Grant inherited user role
        self.assignment_api.create_grant(user_id=user['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Grant non-inherited user role
        self.assignment_api.create_grant(user_id=user['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_member['id'])
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # Disable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Should get back just root project - due the direct role assignment
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(1, len(user_projects))
        self.assertIn(root_project, user_projects)

    def test_list_projects_for_user_with_inherited_group_grants(self):
        """Test inherited group roles.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create two domains, each with two projects
        - Create a user and group
        - Make the user a member of the group
        - Assign a user role two projects, an inherited
          group role to one domain and an inherited regular role on
          the other domain
        - Get a list of projects for user, should return both pairs of projects
          from the domain, plus the one separate project

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain['id'], domain)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain2['id'], domain2)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project1['id'], project1)
        project2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain['id']}
        self.resource_api.create_project(project2['id'], project2)
        project3 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project3['id'], project3)
        project4 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.resource_api.create_project(project4['id'], project4)
        user1 = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                 'domain_id': domain['id'], 'enabled': True}
        user1 = self.identity_api.create_user(user1)
        group1 = {'name': uuid.uuid4().hex, 'domain_id': domain['id']}
        group1 = self.identity_api.create_group(group1)
        self.identity_api.add_user_to_group(user1['id'], group1['id'])

        # Create 4 grants:
        # - one user grant on a project in domain2
        # - one user grant on a project in the default domain
        # - one inherited user grant on domain
        # - one inherited group grant on domain2
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=project3['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         project_id=self.tenant_bar['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user1['id'],
                                         domain_id=domain['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=domain2['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Should get back all five projects, but without a duplicate for
        # project3 (since it has both a direct user role and an inherited role)
        user_projects = self.assignment_api.list_projects_for_user(user1['id'])
        self.assertEqual(5, len(user_projects))

    def test_list_projects_for_user_with_inherited_group_project_grants(self):
        """Test inherited role assignments for groups on nested projects.

        Test Plan:

        - Enable OS-INHERIT extension
        - Create a hierarchy of projects with one root and one leaf project
        - Assign an inherited group role on root project
        - Assign a non-inherited group role on root project
        - Get a list of projects for user, should return both projects
        - Disable OS-INHERIT extension
        - Get a list of projects for user, should return only root project

        """
        self.config_fixture.config(group='os_inherit', enabled=True)
        root_project = {'id': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': DEFAULT_DOMAIN_ID,
                        'enabled': True,
                        'name': uuid.uuid4().hex,
                        'parent_id': None}
        self.resource_api.create_project(root_project['id'], root_project)
        leaf_project = {'id': uuid.uuid4().hex,
                        'description': '',
                        'domain_id': DEFAULT_DOMAIN_ID,
                        'enabled': True,
                        'name': uuid.uuid4().hex,
                        'parent_id': root_project['id']}
        self.resource_api.create_project(leaf_project['id'], leaf_project)

        user = {'name': uuid.uuid4().hex, 'password': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID, 'enabled': True}
        user = self.identity_api.create_user(user)

        group = {'name': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID}
        group = self.identity_api.create_group(group)
        self.identity_api.add_user_to_group(user['id'], group['id'])

        # Grant inherited group role
        self.assignment_api.create_grant(group_id=group['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_admin['id'],
                                         inherited_to_projects=True)
        # Grant non-inherited group role
        self.assignment_api.create_grant(group_id=group['id'],
                                         project_id=root_project['id'],
                                         role_id=self.role_member['id'])
        # Should get back both projects: because the direct role assignment for
        # the root project and inherited role assignment for leaf project
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(2, len(user_projects))
        self.assertIn(root_project, user_projects)
        self.assertIn(leaf_project, user_projects)

        # Disable OS-INHERIT extension
        self.config_fixture.config(group='os_inherit', enabled=False)
        # Should get back just root project - due the direct role assignment
        user_projects = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual(1, len(user_projects))
        self.assertIn(root_project, user_projects)


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
            self.assertEqual(entities[0]['id'], entity_list[10]['id'])
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
            'user', 20, domain_id=DEFAULT_DOMAIN_ID, name_dict=user_name_data)

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

    def test_groups_for_user_filtered(self):
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

        number_of_groups = 10
        group_name_data = {
            # entity index: name for entity
            5: 'The',
            6: 'The Ministry',
            9: 'The Ministry of Silly Walks',
        }
        group_list = self._create_test_data(
            'group', number_of_groups,
            domain_id=DEFAULT_DOMAIN_ID, name_dict=group_name_data)
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


class LimitTests(filtering.FilterTests):
    ENTITIES = ['user', 'group', 'project']

    def setUp(self):
        """Setup for Limit Test Cases."""

        self.domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(self.domain1['id'], self.domain1)
        self.addCleanup(self.clean_up_domain)

        self.entity_lists = {}
        self.domain1_entity_lists = {}

        for entity in self.ENTITIES:
            # Create 20 entities, 14 of which are in domain1
            self.entity_lists[entity] = self._create_test_data(entity, 6)
            self.domain1_entity_lists[entity] = self._create_test_data(
                entity, 14, self.domain1['id'])
        self.addCleanup(self.clean_up_entities)

    def clean_up_domain(self):
        """Clean up domain test data from Limit Test Cases."""

        self.domain1['enabled'] = False
        self.resource_api.update_domain(self.domain1['id'], self.domain1)
        self.resource_api.delete_domain(self.domain1['id'])
        del self.domain1

    def clean_up_entities(self):
        """Clean up entity test data from Limit Test Cases."""
        for entity in self.ENTITIES:
            self._delete_test_data(entity, self.entity_lists[entity])
            self._delete_test_data(entity, self.domain1_entity_lists[entity])
        del self.entity_lists
        del self.domain1_entity_lists

    def _test_list_entity_filtered_and_limited(self, entity):
        self.config_fixture.config(list_limit=10)
        # Should get back just 10 entities in domain1
        hints = driver_hints.Hints()
        hints.add_filter('domain_id', self.domain1['id'])
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))
        self.assertTrue(hints.limit['truncated'])
        self._match_with_list(entities, self.domain1_entity_lists[entity])

        # Override with driver specific limit
        if entity == 'project':
            self.config_fixture.config(group='resource', list_limit=5)
        else:
            self.config_fixture.config(group='identity', list_limit=5)

        # Should get back just 5 users in domain1
        hints = driver_hints.Hints()
        hints.add_filter('domain_id', self.domain1['id'])
        entities = self._list_entities(entity)(hints=hints)
        self.assertEqual(hints.limit['limit'], len(entities))
        self._match_with_list(entities, self.domain1_entity_lists[entity])

        # Finally, let's pretend we want to get the full list of entities,
        # even with the limits set, as part of some internal calculation.
        # Calling the API without a hints list should achieve this, and
        # return at least the 20 entries we created (there may be other
        # entities lying around created by other tests/setup).
        entities = self._list_entities(entity)()
        self.assertTrue(len(entities) >= 20)

    def test_list_users_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('user')

    def test_list_groups_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('group')

    def test_list_projects_filtered_and_limited(self):
        self._test_list_entity_filtered_and_limited('project')
