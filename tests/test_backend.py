# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import datetime
import default_fixtures
import uuid

from keystone.catalog import core
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import test


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
NULL_OBJECT = object()


class IdentityTests(object):
    def _get_domain_fixture(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain['id'], domain)
        return domain

    def test_project_add_and_remove_user_role(self):
        user_refs = self.identity_api.get_project_users(self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], [x['id'] for x in user_refs])

        self.identity_api.add_role_to_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])
        user_refs = self.identity_api.get_project_users(self.tenant_bar['id'])
        self.assertIn(self.user_two['id'], [x['id'] for x in user_refs])

        self.identity_api.remove_role_from_user_and_project(
            tenant_id=self.tenant_bar['id'],
            user_id=self.user_two['id'],
            role_id=self.role_other['id'])

        user_refs = self.identity_api.get_project_users(self.tenant_bar['id'])
        self.assertNotIn(self.user_two['id'], [x['id'] for x in user_refs])

    def test_authenticate_bad_user(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=uuid.uuid4().hex,
                          tenant_id=self.tenant_bar['id'],
                          password=self.user_foo['password'])

    def test_authenticate_bad_password(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=self.user_foo['id'],
                          tenant_id=self.tenant_bar['id'],
                          password=uuid.uuid4().hex)

    def test_authenticate_bad_project(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=self.user_foo['id'],
                          tenant_id=uuid.uuid4().hex,
                          password=self.user_foo['password'])

    def test_authenticate_no_project(self):
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=self.user_foo['id'],
            password=self.user_foo['password'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)
        self.assert_(tenant_ref is None)
        self.assert_(not metadata_ref)

    def test_authenticate(self):
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=self.user_sna['id'],
            tenant_id=self.tenant_bar['id'],
            password=self.user_sna['password'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_sna.pop('password')
        self.user_sna['enabled'] = True
        self.assertDictEqual(user_ref, self.user_sna)
        self.assertDictEqual(tenant_ref, self.tenant_bar)
        metadata_ref.pop('roles')
        self.assertDictEqual(metadata_ref, self.metadata_snamtu)

    def test_authenticate_role_return(self):
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_baz['id'], self.role_admin['id'])
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=self.user_foo['id'],
            tenant_id=self.tenant_baz['id'],
            password=self.user_foo['password'])
        self.assertIn('roles', metadata_ref)
        self.assertIn(self.role_admin['id'], metadata_ref['roles'])

    def test_authenticate_no_metadata(self):
        user = {
            'id': 'no_meta',
            'name': 'NO_META',
            'domain_id': DEFAULT_DOMAIN_ID,
            'password': 'no_meta2',
        }
        self.identity_api.create_user(user['id'], user)
        self.identity_api.add_user_to_project(self.tenant_baz['id'],
                                              user['id'])
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
            user_id=user['id'],
            tenant_id=self.tenant_baz['id'],
            password=user['password'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        user.pop('password')
        self.assertEquals(metadata_ref, {"roles":
                                         [CONF.member_role_id]})
        self.assertDictContainsSubset(user, user_ref)
        self.assertDictEqual(tenant_ref, self.tenant_baz)

    def test_password_hashed(self):
        user_ref = self.identity_api._get_user(self.user_foo['id'])
        self.assertNotEqual(user_ref['password'], self.user_foo['password'])

    def test_create_unicode_user_name(self):
        unicode_name = u'name \u540d\u5b57'
        user = {'id': uuid.uuid4().hex,
                'name': unicode_name,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        ref = self.identity_api.create_user(user['id'], user)
        self.assertEqual(unicode_name, ref['name'])

    def test_get_project(self):
        tenant_ref = self.identity_api.get_project(
            tenant_id=self.tenant_bar['id'])
        self.assertDictEqual(tenant_ref, self.tenant_bar)

    def test_get_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project,
                          tenant_id=uuid.uuid4().hex)

    def test_get_project_by_name(self):
        tenant_ref = self.identity_api.get_project_by_name(
            tenant_name=self.tenant_bar['name'],
            domain_id=DEFAULT_DOMAIN_ID)
        self.assertDictEqual(tenant_ref, self.tenant_bar)

    def test_get_project_by_name_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project_by_name,
                          tenant_name=uuid.uuid4().hex,
                          domain_id=DEFAULT_DOMAIN_ID)

    def test_get_project_users(self):
        tenant_ref = self.identity_api.get_project_users(self.tenant_baz['id'])
        user_ids = []
        for user in tenant_ref:
            self.assertNotIn('password', user)
            user_ids.append(user.get('id'))
        self.assertEquals(len(user_ids), 2)
        self.assertIn(self.user_two['id'], user_ids)
        self.assertIn(self.user_badguy['id'], user_ids)

    def test_get_project_users_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project_users,
                          tenant_id=uuid.uuid4().hex)

    def test_get_user(self):
        user_ref = self.identity_api.get_user(user_id=self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

    def test_get_user_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user_id=uuid.uuid4().hex)

    def test_get_user_by_name(self):
        user_ref = self.identity_api.get_user_by_name(
            user_name=self.user_foo['name'],
            domain_id=DEFAULT_DOMAIN_ID)
        # NOTE(termie): the password field is left in user_foo to make
        #               it easier to authenticate in tests, but should
        #               not be returned by the api
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

    def test_get_user_by_name_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user_name=uuid.uuid4().hex,
                          domain_id=DEFAULT_DOMAIN_ID)

    def test_get_metadata(self):
        metadata_ref = self.identity_api.get_metadata(
            user_id=self.user_sna['id'],
            tenant_id=self.tenant_bar['id'])
        metadata_ref.pop('roles')
        self.assertDictEqual(metadata_ref, self.metadata_snamtu)

    def test_get_metadata_404(self):
        # FIXME(dolph): these exceptions could be more specific
        self.assertRaises(exception.NotFound,
                          self.identity_api.get_metadata,
                          user_id=uuid.uuid4().hex,
                          tenant_id=self.tenant_bar['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.get_metadata,
                          user_id=self.user_foo['id'],
                          tenant_id=uuid.uuid4().hex)

    def test_get_role(self):
        role_ref = self.identity_api.get_role(
            role_id=self.role_admin['id'])
        role_ref_dict = dict((x, role_ref[x]) for x in role_ref)
        self.assertDictEqual(role_ref_dict, self.role_admin)

    def test_get_role_404(self):
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          role_id=uuid.uuid4().hex)

    def test_create_duplicate_role_name_fails(self):
        role = {'id': 'fake1',
                'name': 'fake1name'}
        self.identity_api.create_role('fake1', role)
        role['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.identity_api.create_role,
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
        self.identity_api.create_role('fake1', role1)
        self.identity_api.create_role('fake2', role2)
        role1['name'] = 'fake2name'
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_role,
                          'fake1',
                          role1)

    def test_create_duplicate_user_id_fails(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'fakepass',
                'tenants': ['bar']}
        self.identity_man.create_user({}, 'fake1', user)
        user['name'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.identity_man.create_user, {},
                          'fake1',
                          user)

    def test_create_duplicate_user_name_fails(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'fakepass',
                'tenants': ['bar']}
        self.identity_man.create_user({}, 'fake1', user)
        user['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.identity_man.create_user, {},
                          'fake2',
                          user)

    def test_create_duplicate_user_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        user1 = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': uuid.uuid4().hex}
        user2 = {'id': uuid.uuid4().hex,
                 'name': user1['name'],
                 'domain_id': new_domain['id'],
                 'password': uuid.uuid4().hex}
        self.identity_man.create_user({}, user1['id'], user1)
        self.identity_man.create_user({}, user2['id'], user2)

    def test_move_user_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': domain1['id'],
                'password': uuid.uuid4().hex}
        self.identity_man.create_user({}, user['id'], user)
        user['domain_id'] = domain2['id']
        self.identity_api.update_user(user['id'], user)

    def test_move_user_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        # First, create a user in domain1
        user1 = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'],
                 'password': uuid.uuid4().hex}
        self.identity_man.create_user({}, user1['id'], user1)
        # Now create a user in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        user2 = {'id': uuid.uuid4().hex,
                 'name': user1['name'],
                 'domain_id': domain2['id'],
                 'password': uuid.uuid4().hex}
        self.identity_man.create_user({}, user2['id'], user2)
        # Now try and move user1 into the 2nd domain - which should
        # fail since the names clash
        user1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          user1['id'],
                          user1)

    def test_rename_duplicate_user_name_fails(self):
        user1 = {'id': 'fake1',
                 'name': 'fake1',
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': 'fakepass',
                 'tenants': ['bar']}
        user2 = {'id': 'fake2',
                 'name': 'fake2',
                 'domain_id': DEFAULT_DOMAIN_ID,
                 'password': 'fakepass',
                 'tenants': ['bar']}
        self.identity_api.create_user('fake1', user1)
        self.identity_api.create_user('fake2', user2)
        user2['name'] = 'fake1'
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_user,
                          'fake2',
                          user2)

    def test_update_user_id_fails(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': 'fakepass',
                'tenants': ['bar']}
        self.identity_api.create_user('fake1', user)
        user['id'] = 'fake2'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake1',
                          user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['id'], 'fake1')
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'fake2')

    def test_create_duplicate_project_id_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant)
        tenant['name'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.identity_man.create_project, {},
                          'fake1',
                          tenant)

    def test_create_duplicate_project_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant)
        tenant['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.identity_man.create_project, {},
                          'fake1',
                          tenant)

    def test_create_duplicate_project_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        tenant1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': DEFAULT_DOMAIN_ID}
        tenant2 = {'id': uuid.uuid4().hex, 'name': tenant1['name'],
                   'domain_id': new_domain['id']}
        self.identity_man.create_project({}, tenant1['id'], tenant1)
        self.identity_man.create_project({}, tenant2['id'], tenant2)

    def test_move_project_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain1['id']}
        self.identity_man.create_project({}, project['id'], project)
        project['domain_id'] = domain2['id']
        self.identity_api.update_project(project['id'], project)

    def test_move_project_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        # First, create a project in domain1
        project1 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        # Now create a project in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        project2 = {'id': uuid.uuid4().hex,
                    'name': project1['name'],
                    'domain_id': domain2['id']}
        self.identity_man.create_project({}, project2['id'], project2)
        # Now try and move project1 into the 2nd domain - which should
        # fail since the names clash
        project1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_project,
                          project1['id'],
                          project1)

    def test_rename_duplicate_project_name_fails(self):
        tenant1 = {'id': 'fake1', 'name': 'fake1',
                   'domain_id': DEFAULT_DOMAIN_ID}
        tenant2 = {'id': 'fake2', 'name': 'fake2',
                   'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant1)
        self.identity_man.create_project({}, 'fake2', tenant2)
        tenant2['name'] = 'fake1'
        self.assertRaises(exception.Error,
                          self.identity_api.update_project,
                          'fake2',
                          tenant2)

    def test_update_project_id_does_nothing(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_api.create_project('fake1', tenant)
        tenant['id'] = 'fake2'
        self.identity_api.update_project('fake1', tenant)
        tenant_ref = self.identity_api.get_project('fake1')
        self.assertEqual(tenant_ref['id'], 'fake1')
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project,
                          'fake2')

    def test_add_duplicate_role_grant(self):
        roles_ref = self.identity_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        self.assertRaises(exception.Conflict,
                          self.identity_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          self.role_admin['id'])

    def test_get_role_by_user_and_project(self):
        roles_ref = self.identity_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(self.role_admin['id'], roles_ref)
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], self.role_admin['id'])
        roles_ref = self.identity_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'], roles_ref)
        self.assertNotIn('member', roles_ref)

        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.identity_api.get_roles_for_user_and_project(
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
        self.identity_api.create_domain(new_domain['id'], new_domain)
        new_user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex, 'enabled': True,
                     'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user1['id'], new_user1)
        new_user2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex, 'enabled': True,
                     'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user2['id'], new_user2)
        roles_ref = self.identity_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        # Now create the grants (roles are defined in default_fixtures)
        self.identity_api.create_grant(user_id=new_user1['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        self.identity_api.create_grant(user_id=new_user1['id'],
                                       domain_id=new_domain['id'],
                                       role_id='other')
        self.identity_api.create_grant(user_id=new_user2['id'],
                                       domain_id=new_domain['id'],
                                       role_id='admin')
        # Read back the roles for user1 on domain
        roles_ids = self.identity_api.get_roles_for_user_and_domain(
            new_user1['id'], new_domain['id'])
        self.assertEqual(len(roles_ids), 2)
        self.assertIn(self.role_member['id'], roles_ids)
        self.assertIn(self.role_other['id'], roles_ids)

        # Now delete both grants for user1
        self.identity_api.delete_grant(user_id=new_user1['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        self.identity_api.delete_grant(user_id=new_user1['id'],
                                       domain_id=new_domain['id'],
                                       role_id='other')
        roles_ref = self.identity_api.list_grants(
            user_id=new_user1['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)

    def test_get_roles_for_user_and_domain_404(self):
        """Test errors raised when getting roles for user on a domain.

        Test Plan:
        - Check non-existing user gives UserNotFound
        - Check non-existing domain gives DomainNotFound

        """
        new_domain = self._get_domain_fixture()
        new_user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex, 'enabled': True,
                     'domain_id': new_domain['id']}
        self.identity_api.create_user(new_user1['id'], new_user1)

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_roles_for_user_and_domain,
                          uuid.uuid4().hex,
                          new_domain['id'])

        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.get_roles_for_user_and_domain,
                          new_user1['id'],
                          uuid.uuid4().hex)

    def test_get_roles_for_user_and_project_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_roles_for_user_and_project,
                          uuid.uuid4().hex,
                          self.tenant_bar['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_roles_for_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex)

    def test_add_role_to_user_and_project_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.add_role_to_user_and_project,
                          uuid.uuid4().hex,
                          self.tenant_bar['id'],
                          self.role_admin['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          uuid.uuid4().hex,
                          self.role_admin['id'])

        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.add_role_to_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

    def test_remove_role_from_user_and_project(self):
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        self.identity_api.remove_role_from_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], 'member')
        roles_ref = self.identity_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn('member', roles_ref)
        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_role_from_user_and_project,
                          self.user_foo['id'],
                          self.tenant_bar['id'],
                          'member')

    def test_get_role_grant_by_user_and_project(self):
        roles_ref = self.identity_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertEquals(len(roles_ref), 1)
        self.identity_api.create_grant(user_id=self.user_foo['id'],
                                       project_id=self.tenant_bar['id'],
                                       role_id=self.role_admin['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])
        self.assertIn(self.role_admin['id'],
                      [role_ref['id'] for role_ref in roles_ref])

        self.identity_api.create_grant(user_id=self.user_foo['id'],
                                       project_id=self.tenant_bar['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_bar['id'])

        roles_ref_ids = []
        for i, ref in enumerate(roles_ref):
            roles_ref_ids.append(ref['id'])
        self.assertIn(self.role_admin['id'], roles_ref_ids)
        self.assertIn('member', roles_ref_ids)

    def test_get_role_grants_for_user_and_project_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.list_grants,
                          user_id=uuid.uuid4().hex,
                          project_id=self.tenant_bar['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.list_grants,
                          user_id=self.user_foo['id'],
                          project_id=uuid.uuid4().hex)

    def test_add_role_grant_to_user_and_project_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.create_grant,
                          user_id=uuid.uuid4().hex,
                          project_id=self.tenant_bar['id'],
                          role_id=self.role_admin['id'])

        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.create_grant,
                          user_id=self.user_foo['id'],
                          project_id=uuid.uuid4().hex,
                          role_id=self.role_admin['id'])

        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.create_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_bar['id'],
                          role_id=uuid.uuid4().hex)

    def test_remove_role_grant_from_user_and_project(self):
        self.identity_api.create_grant(user_id=self.user_foo['id'],
                                       project_id=self.tenant_baz['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.identity_api.delete_grant(user_id=self.user_foo['id'],
                                       project_id=self.tenant_baz['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            user_id=self.user_foo['id'],
            project_id=self.tenant_baz['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          user_id=self.user_foo['id'],
                          project_id=self.tenant_baz['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_project(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        new_group = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': 'secret', 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(group_id=new_group['id'],
                                       project_id=self.tenant_bar['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.identity_api.delete_grant(group_id=new_group['id'],
                                       project_id=self.tenant_bar['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          group_id=new_group['id'],
                          project_id=self.tenant_bar['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_domain(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        new_group = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])

        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)

        self.identity_api.create_grant(group_id=new_group['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')

        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.identity_api.delete_grant(group_id=new_group['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_correct_role_grant_from_a_mix(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        new_project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                       'domain_id': new_domain['id']}
        self.identity_man.create_project({}, new_project['id'], new_project)
        new_group = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_group2 = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                      'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group2['id'], new_group2)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        new_user2 = {'id': uuid.uuid4().hex, 'name': 'new_user2',
                     'password': uuid.uuid4().hex, 'enabled': True,
                     'domain_id': new_domain['id']}
        self.identity_man.create_user({}, new_user2['id'], new_user2)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        # First check we have no grants
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        # Now add the grant we are going to test for, and some others as
        # well just to make sure we get back the right one
        self.identity_api.create_grant(group_id=new_group['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')

        self.identity_api.create_grant(group_id=new_group2['id'],
                                       domain_id=new_domain['id'],
                                       role_id=self.role_admin['id'])
        self.identity_api.create_grant(user_id=new_user2['id'],
                                       domain_id=new_domain['id'],
                                       role_id=self.role_admin['id'])
        self.identity_api.create_grant(group_id=new_group['id'],
                                       project_id=new_project['id'],
                                       role_id=self.role_admin['id'])

        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.identity_api.delete_grant(group_id=new_group['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            group_id=new_group['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          group_id=new_group['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_user_and_domain(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': 'secret', 'enabled': True,
                    'domain_id': new_domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        roles_ref = self.identity_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(user_id=new_user['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertDictEqual(roles_ref[0], self.role_member)

        self.identity_api.delete_grant(user_id=new_user['id'],
                                       domain_id=new_domain['id'],
                                       role_id='member')
        roles_ref = self.identity_api.list_grants(
            user_id=new_user['id'],
            domain_id=new_domain['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          user_id=new_user['id'],
                          domain_id=new_domain['id'],
                          role_id='member')

    def test_get_and_remove_role_grant_by_group_and_cross_domain(self):
        group1_domain1_role = {'id': uuid.uuid4().hex,
                               'name': uuid.uuid4().hex}
        self.identity_api.create_role(group1_domain1_role['id'],
                                      group1_domain1_role)
        group1_domain2_role = {'id': uuid.uuid4().hex,
                               'name': uuid.uuid4().hex}
        self.identity_api.create_role(group1_domain2_role['id'],
                                      group1_domain2_role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        group1 = {'id': uuid.uuid4().hex, 'domain_id': domain1['id'],
                  'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, group1['id'], group1)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 0)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain1['id'],
                                       role_id=group1_domain1_role['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain2['id'],
                                       role_id=group1_domain2_role['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(roles_ref[0], group1_domain1_role)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(roles_ref[0], group1_domain2_role)

        self.identity_api.delete_grant(group_id=group1['id'],
                                       domain_id=domain2['id'],
                                       role_id=group1_domain2_role['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain2['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          group_id=group1['id'],
                          domain_id=domain2['id'],
                          role_id=group1_domain2_role['id'])

    def test_get_and_remove_role_grant_by_user_and_cross_domain(self):
        user1_domain1_role = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.identity_api.create_role(user1_domain1_role['id'],
                                      user1_domain1_role)
        user1_domain2_role = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.identity_api.create_role(user1_domain2_role['id'],
                                      user1_domain2_role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 0)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain1['id'],
                                       role_id=user1_domain1_role['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain2['id'],
                                       role_id=user1_domain2_role['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertDictEqual(roles_ref[0], user1_domain1_role)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertDictEqual(roles_ref[0], user1_domain2_role)

        self.identity_api.delete_grant(user_id=user1['id'],
                                       domain_id=domain2['id'],
                                       role_id=user1_domain2_role['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain2['id'])
        self.assertEquals(len(roles_ref), 0)
        self.assertRaises(exception.NotFound,
                          self.identity_api.delete_grant,
                          user_id=user1['id'],
                          domain_id=domain2['id'],
                          role_id=user1_domain2_role['id'])

    def test_role_grant_by_group_and_cross_domain_project(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role1['id'], role1)
        role2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role2['id'], role2)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain1['id'], 'enabled': True}
        self.identity_man.create_group({}, group1['id'], group1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role2['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for i, ref in enumerate(roles_ref):
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.identity_api.delete_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        self.assertDictEqual(roles_ref[0], role2)

    def test_role_grant_by_user_and_cross_domain_project(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role1['id'], role1)
        role2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role2['id'], role2)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain2['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role2['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])

        roles_ref_ids = []
        for i, ref in enumerate(roles_ref):
            roles_ref_ids.append(ref['id'])
        self.assertIn(role1['id'], roles_ref_ids)
        self.assertIn(role2['id'], roles_ref_ids)

        self.identity_api.delete_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        self.assertDictEqual(roles_ref[0], role2)

    def test_multi_role_grant_by_user_group_on_project_domain(self):
        role_list = []
        for _ in range(8):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            self.identity_api.create_role(role['id'], role)
            role_list.append(role)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain1['id'], 'enabled': True}
        self.identity_man.create_group({}, group1['id'], group1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_man.create_project({}, project1['id'], project1)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])

        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 0)
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role_list[0]['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role_list[1]['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role_list[2]['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role_list[3]['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role_list[4]['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role_list[5]['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role_list[6]['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role_list[7]['id'])
        roles_ref = self.identity_api.list_grants(user_id=user1['id'],
                                                  domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 2)
        self.assertIn(role_list[0], roles_ref)
        self.assertIn(role_list[1], roles_ref)
        roles_ref = self.identity_api.list_grants(group_id=group1['id'],
                                                  domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 2)
        self.assertIn(role_list[2], roles_ref)
        self.assertIn(role_list[3], roles_ref)
        roles_ref = self.identity_api.list_grants(user_id=user1['id'],
                                                  project_id=project1['id'])
        self.assertEquals(len(roles_ref), 2)
        self.assertIn(role_list[4], roles_ref)
        self.assertIn(role_list[5], roles_ref)
        roles_ref = self.identity_api.list_grants(group_id=group1['id'],
                                                  project_id=project1['id'])
        self.assertEquals(len(roles_ref), 2)
        self.assertIn(role_list[6], roles_ref)
        self.assertIn(role_list[7], roles_ref)

    def test_delete_role_with_user_and_group_grants(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain1['id'], 'enabled': True}
        self.identity_man.create_group({}, group1['id'], group1)
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role1['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 1)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 1)
        self.identity_api.delete_role(role1['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 0)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 0)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 0)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 0)

    def test_delete_user_with_group_project_domain_links(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain1['id'], 'enabled': True}
        self.identity_man.create_group({}, group1['id'], group1)
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        roles_ref = self.identity_api.list_grants(
            user_id=user1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 1)
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_user(user1['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.list_grants,
                          user_id=user1['id'],
                          project_id=project1['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.list_grants,
                          user_id=user1['id'],
                          domain_id=domain1['id'])
        self.assertRaises(exception.NotFound,
                          self.identity_api.check_user_in_group,
                          user1['id'],
                          group1['id'])

    def test_delete_group_with_user_project_domain_links(self):
        role1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role1['id'], role1)
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_man.create_project({}, project1['id'], project1)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id'], 'password': uuid.uuid4().hex,
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        group1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': domain1['id'], 'enabled': True}
        self.identity_man.create_group({}, group1['id'], group1)
        self.identity_api.create_grant(group_id=group1['id'],
                                       project_id=project1['id'],
                                       role_id=role1['id'])
        self.identity_api.create_grant(group_id=group1['id'],
                                       domain_id=domain1['id'],
                                       role_id=role1['id'])
        self.identity_api.add_user_to_group(user_id=user1['id'],
                                            group_id=group1['id'])
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            project_id=project1['id'])
        self.assertEquals(len(roles_ref), 1)
        roles_ref = self.identity_api.list_grants(
            group_id=group1['id'],
            domain_id=domain1['id'])
        self.assertEquals(len(roles_ref), 1)
        self.identity_api.check_user_in_group(
            user_id=user1['id'],
            group_id=group1['id'])
        self.identity_api.delete_group(group1['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.list_grants,
                          group_id=group1['id'],
                          project_id=project1['id'])
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.list_grants,
                          group_id=group1['id'],
                          domain_id=domain1['id'])
        self.identity_api.get_user(user1['id'])

    def test_delete_domain_with_user_group_project_links(self):
        #TODO(chungg):add test case once expected behaviour defined
        pass

    def test_role_crud(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        role_ref = self.identity_api.get_role(role['id'])
        role_ref_dict = dict((x, role_ref[x]) for x in role_ref)
        self.assertDictEqual(role_ref_dict, role)

        role['name'] = uuid.uuid4().hex
        self.identity_api.update_role(role['id'], role)
        role_ref = self.identity_api.get_role(role['id'])
        role_ref_dict = dict((x, role_ref[x]) for x in role_ref)
        self.assertDictEqual(role_ref_dict, role)

        self.identity_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          role['id'])

    def test_update_role_404(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.update_role,
                          role['id'],
                          role)

    def test_add_user_to_project(self):
        self.identity_api.add_user_to_project(self.tenant_baz['id'],
                                              self.user_foo['id'])
        tenants = self.identity_api.get_projects_for_user(self.user_foo['id'])
        self.assertIn(self.tenant_baz['id'], tenants)

    def test_add_user_to_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.add_user_to_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.add_user_to_project,
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

    def test_remove_user_from_project(self):
        self.identity_api.add_user_to_project(self.tenant_baz['id'],
                                              self.user_foo['id'])
        self.identity_api.remove_user_from_project(self.tenant_baz['id'],
                                                   self.user_foo['id'])
        tenants = self.identity_api.get_projects_for_user(self.user_foo['id'])
        self.assertNotIn(self.tenant_baz['id'], tenants)

    def test_remove_user_from_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.remove_user_from_project,
                          uuid.uuid4().hex,
                          self.user_foo['id'])

        self.assertRaises(exception.UserNotFound,
                          self.identity_api.remove_user_from_project,
                          self.tenant_bar['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_project,
                          self.tenant_baz['id'],
                          self.user_foo['id'])

    def test_get_projects_for_user_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_projects_for_user,
                          uuid.uuid4().hex)

    def test_update_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.update_project,
                          uuid.uuid4().hex,
                          dict())

    def test_delete_project_404(self):
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.delete_project,
                          uuid.uuid4().hex)

    def test_update_user_404(self):
        user_id = uuid.uuid4().hex
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.update_user,
                          user_id,
                          {'id': user_id})

    def test_delete_user_with_project_association(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        self.identity_api.create_user(user['id'], user)
        self.identity_api.add_user_to_project(self.tenant_bar['id'],
                                              user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_projects_for_user,
                          user['id'])

    def test_delete_user_with_project_roles(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex}
        self.identity_api.create_user(user['id'], user)
        self.identity_api.add_role_to_user_and_project(
            user['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_projects_for_user,
                          user['id'])

    def test_delete_user_404(self):
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_delete_role_404(self):
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.delete_role,
                          uuid.uuid4().hex)

    def test_create_project_long_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'a' * 65,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_project, {},
                          tenant['id'],
                          tenant)

    def test_create_project_blank_name_fails(self):
        tenant = {'id': 'fake1', 'name': '',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_project, {},
                          tenant['id'],
                          tenant)

    def test_create_project_invalid_name_fails(self):
        tenant = {'id': 'fake1', 'name': None,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_project, {},
                          tenant['id'],
                          tenant)
        tenant = {'id': 'fake1', 'name': 123,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_project, {},
                          tenant['id'],
                          tenant)

    def test_update_project_blank_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant)
        tenant['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_project,
                          tenant['id'],
                          tenant)

    def test_update_project_long_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant)
        tenant['name'] = 'a' * 65
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_project,
                          tenant['id'],
                          tenant)

    def test_update_project_invalid_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1',
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_project({}, 'fake1', tenant)
        tenant['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_project,
                          tenant['id'],
                          tenant)

        tenant['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_project,
                          tenant['id'],
                          tenant)

    def test_create_user_long_name_fails(self):
        user = {'id': 'fake1', 'name': 'a' * 65,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          'fake1',
                          user)

    def test_create_user_blank_name_fails(self):
        user = {'id': 'fake1', 'name': '',
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          'fake1',
                          user)

    def test_create_user_invalid_name_fails(self):
        user = {'id': 'fake1', 'name': None,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          'fake1',
                          user)

        user = {'id': 'fake1', 'name': 123,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          'fake1',
                          user)

    def test_create_user_invalid_enabled_type(self):
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': DEFAULT_DOMAIN_ID,
                'password': uuid.uuid4().hex,
                # invalid string value
                'enabled': "true"}
        self.assertRaises(exception.ValidationError,
                          self.identity_man.create_user, {},
                          user['id'],
                          user)

    def test_update_user_long_name_fails(self):
        user = {'id': 'fake1', 'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_user({}, 'fake1', user)
        user['name'] = 'a' * 65
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake1',
                          user)

    def test_update_user_blank_name_fails(self):
        user = {'id': 'fake1', 'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_user({}, 'fake1', user)
        user['name'] = ''
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake1',
                          user)

    def test_update_user_invalid_name_fails(self):
        user = {'id': 'fake1', 'name': 'fake1',
                'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_man.create_user({}, 'fake1', user)

        user['name'] = None
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake1',
                          user)

        user['name'] = 123
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake1',
                          user)

    def test_list_users(self):
        users = self.identity_api.list_users()
        for test_user in default_fixtures.USERS:
            self.assertTrue(x for x in users if x['id'] == test_user['id'])

    def test_list_groups(self):
        group1 = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex}
        group2 = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, group1['id'], group1)
        self.identity_man.create_group({}, group2['id'], group2)
        groups = self.identity_api.list_groups()
        self.assertEquals(len(groups), 2)
        group_ids = []
        for group in groups:
            group_ids.append(group.get('id'))
        self.assertIn(group1['id'], group_ids)
        self.assertIn(group2['id'], group_ids)

    def test_list_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        self.identity_api.create_domain(domain2['id'], domain2)
        domains = self.identity_api.list_domains()
        self.assertEquals(len(domains), 3)
        domain_ids = []
        for domain in domains:
            domain_ids.append(domain.get('id'))
        self.assertIn(DEFAULT_DOMAIN_ID, domain_ids)
        self.assertIn(domain1['id'], domain_ids)
        self.assertIn(domain2['id'], domain_ids)

    def test_list_projects(self):
        projects = self.identity_api.list_projects()
        self.assertEquals(len(projects), 3)
        project_ids = []
        for project in projects:
            project_ids.append(project.get('id'))
        self.assertIn(self.tenant_bar['id'], project_ids)
        self.assertIn(self.tenant_baz['id'], project_ids)

    def test_list_roles(self):
        roles = self.identity_api.list_roles()
        for test_role in default_fixtures.ROLES:
            self.assertTrue(x for x in roles if x['id'] == test_role['id'])

    def test_delete_project_with_role_assignments(self):
        tenant = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_api.create_project(tenant['id'], tenant)
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], tenant['id'], 'member')
        self.identity_api.delete_project(tenant['id'])
        self.assertRaises(exception.NotFound,
                          self.identity_api.get_project,
                          tenant['id'])

    def test_delete_role_check_role_grant(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        alt_role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        self.identity_api.create_role(alt_role['id'], alt_role)
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], role['id'])
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'], alt_role['id'])
        self.identity_api.delete_role(role['id'])
        roles_ref = self.identity_api.get_roles_for_user_and_project(
            self.user_foo['id'], self.tenant_bar['id'])
        self.assertNotIn(role['id'], roles_ref)
        self.assertIn(alt_role['id'], roles_ref)

    def test_create_project_doesnt_modify_passed_in_dict(self):
        new_project = {'id': 'tenant_id', 'name': uuid.uuid4().hex,
                       'domain_id': DEFAULT_DOMAIN_ID}
        original_project = new_project.copy()
        self.identity_man.create_project({}, 'tenant_id', new_project)
        self.assertDictEqual(original_project, new_project)

    def test_create_user_doesnt_modify_passed_in_dict(self):
        new_user = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'password': uuid.uuid4().hex,
                    'domain_id': DEFAULT_DOMAIN_ID}
        original_user = new_user.copy()
        self.identity_man.create_user({}, 'user_id', new_user)
        self.assertDictEqual(original_user, new_user)

    def test_update_user_enable(self):
        user = {'id': 'fake1', 'name': 'fake1', 'enabled': True,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_api.create_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)

        user['enabled'] = False
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], user['enabled'])

        # If not present, enabled field should not be updated
        del user['enabled']
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], False)

        user['enabled'] = True
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], user['enabled'])

        del user['enabled']
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)

        # Integers are valid Python's booleans. Explicitly test it.
        user['enabled'] = 0
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], False)

        # Any integers other than 0 are interpreted as True
        user['enabled'] = -42
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)

    def test_update_user_enable_fails(self):
        user = {'id': 'fake1', 'name': 'fake1', 'enabled': True,
                'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_api.create_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)

        # Strings are not valid boolean values
        user['enabled'] = "false"
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user, 'fake1', user)

    def test_update_project_enable(self):
        tenant = {'id': 'fake1', 'name': 'fake1', 'enabled': True,
                  'domain_id': DEFAULT_DOMAIN_ID}
        self.identity_api.create_project('fake1', tenant)
        tenant_ref = self.identity_api.get_project('fake1')
        self.assertEqual(tenant_ref['enabled'], True)

        tenant['enabled'] = False
        self.identity_api.update_project('fake1', tenant)
        tenant_ref = self.identity_api.get_project('fake1')
        self.assertEqual(tenant_ref['enabled'], tenant['enabled'])

        tenant['enabled'] = True
        self.identity_api.update_project('fake1', tenant)
        tenant_ref = self.identity_api.get_project('fake1')
        self.assertEqual(tenant_ref['enabled'], tenant['enabled'])

    def test_add_user_to_group(self):
        domain = self._get_domain_fixture()
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
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
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        self.assertRaises(exception.GroupNotFound,
                          self.identity_api.add_user_to_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.add_user_to_group,
                          uuid.uuid4().hex,
                          new_group['id'])

    def test_check_user_in_group(self):
        domain = self._get_domain_fixture()
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        self.identity_api.check_user_in_group(new_user['id'], new_group['id'])

    def test_check_user_not_in_group(self):
        new_group = {
            'id': uuid.uuid4().hex,
            'domain_id': CONF.identity.default_domain_id,
            'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.check_user_in_group,
                          uuid.uuid4().hex,
                          new_group['id'])

    def test_list_users_in_group(self):
        domain = self._get_domain_fixture()
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        self.identity_api.add_user_to_group(new_user['id'],
                                            new_group['id'])
        user_refs = self.identity_api.list_users_in_group(new_group['id'])
        found = False
        for x in user_refs:
            if (x['id'] == new_user['id']):
                found = True
        self.assertTrue(found)

    def test_remove_user_from_group(self):
        domain = self._get_domain_fixture()
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
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
        new_user = {'id': uuid.uuid4().hex, 'name': 'new_user',
                    'password': uuid.uuid4().hex, 'enabled': True,
                    'domain_id': domain['id']}
        self.identity_man.create_user({}, new_user['id'], new_user)
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                     'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, new_group['id'], new_group)
        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_group,
                          new_user['id'],
                          uuid.uuid4().hex)

        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          new_group['id'])

        self.assertRaises(exception.NotFound,
                          self.identity_api.remove_user_from_group,
                          uuid.uuid4().hex,
                          uuid.uuid4().hex)

    def test_group_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain['id'], domain)
        group = {'id': uuid.uuid4().hex, 'domain_id': domain['id'],
                 'name': uuid.uuid4().hex}
        self.identity_man.create_group({}, group['id'], group)
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

    def test_create_duplicate_group_name_fails(self):
        group1 = {'id': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                  'name': uuid.uuid4().hex}
        group2 = {'id': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                  'name': group1['name']}
        self.identity_man.create_group({}, group1['id'], group1)
        self.assertRaises(exception.Conflict,
                          self.identity_man.create_group, {},
                          group2['id'], group2)

    def test_create_duplicate_group_name_in_different_domains(self):
        new_domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(new_domain['id'], new_domain)
        group1 = {'id': uuid.uuid4().hex, 'domain_id': DEFAULT_DOMAIN_ID,
                  'name': uuid.uuid4().hex}
        group2 = {'id': uuid.uuid4().hex, 'domain_id': new_domain['id'],
                  'name': group1['name']}
        self.identity_man.create_group({}, group1['id'], group1)
        self.identity_man.create_group({}, group2['id'], group2)

    def test_move_group_between_domains(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        group = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': domain1['id']}
        self.identity_man.create_group({}, group['id'], group)
        group['domain_id'] = domain2['id']
        self.identity_api.update_group(group['id'], group)

    def test_move_group_between_domains_with_clashing_names_fails(self):
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        domain2 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain2['id'], domain2)
        # First, create a group in domain1
        group1 = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex,
                  'domain_id': domain1['id']}
        self.identity_man.create_group({}, group1['id'], group1)
        # Now create a group in domain2 with a potentially clashing
        # name - which should work since we have domain separation
        group2 = {'id': uuid.uuid4().hex,
                  'name': group1['name'],
                  'domain_id': domain2['id']}
        self.identity_man.create_group({}, group2['id'], group2)
        # Now try and move group1 into the 2nd domain - which should
        # fail since the names clash
        group1['domain_id'] = domain2['id']
        self.assertRaises(exception.Conflict,
                          self.identity_api.update_group,
                          group1['id'],
                          group1)

    def test_project_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.identity_api.create_domain(domain['id'], domain)
        project = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                   'domain_id': domain['id']}
        self.identity_man.create_project({}, project['id'], project)
        project_ref = self.identity_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        project['name'] = uuid.uuid4().hex
        self.identity_api.update_project(project['id'], project)
        project_ref = self.identity_api.get_project(project['id'])
        self.assertDictContainsSubset(project, project_ref)

        self.identity_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.identity_api.get_project,
                          project['id'])

    def test_domain_crud(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                  'enabled': True}
        self.identity_api.create_domain(domain['id'], domain)
        domain_ref = self.identity_api.get_domain(domain['id'])
        self.assertDictEqual(domain_ref, domain)

        domain['name'] = uuid.uuid4().hex
        self.identity_api.update_domain(domain['id'], domain)
        domain_ref = self.identity_api.get_domain(domain['id'])
        self.assertDictEqual(domain_ref, domain)

        self.identity_api.delete_domain(domain['id'])
        self.assertRaises(exception.DomainNotFound,
                          self.identity_api.get_domain,
                          domain['id'])

    def test_user_crud(self):
        user = {'domain_id': CONF.identity.default_domain_id,
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex, 'password': 'passw0rd'}
        self.identity_api.create_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        del user['password']
        user_ref_dict = dict((x, user_ref[x]) for x in user_ref)
        self.assertDictContainsSubset(user, user_ref_dict)

        user['password'] = uuid.uuid4().hex
        self.identity_api.update_user(user['id'], user)
        user_ref = self.identity_api.get_user(user['id'])
        del user['password']
        user_ref_dict = dict((x, user_ref[x]) for x in user_ref)
        self.assertDictContainsSubset(user, user_ref_dict)

        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          user['id'])

    def test_list_user_projects(self):
        domain = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain['id'], domain)
        user1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                 'password': uuid.uuid4().hex, 'domain_id': domain['id'],
                 'enabled': True}
        self.identity_man.create_user({}, user1['id'], user1)
        user_projects = self.identity_api.list_user_projects(user1['id'])
        self.assertEquals(len(user_projects), 0)
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=self.tenant_bar['id'],
                                       role_id=self.role_member['id'])
        self.identity_api.create_grant(user_id=user1['id'],
                                       project_id=self.tenant_baz['id'],
                                       role_id=self.role_member['id'])
        user_projects = self.identity_api.list_user_projects(user1['id'])
        self.assertEquals(len(user_projects), 2)


class TokenTests(object):
    def _create_token_id(self):
        # Token must start with MII here otherwise it fails the asn1 test
        # and is not hashed in a SQL backend.
        token_id = "MII"
        for i in range(1, 20):
            token_id += uuid.uuid4().hex
        return token_id

    def test_token_crud(self):
        token_id = self._create_token_id()
        data = {'id': token_id, 'a': 'b',
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        expires = data_ref.pop('expires')
        data_ref.pop('user_id')
        self.assertTrue(isinstance(expires, datetime.datetime))
        data_ref.pop('id')
        data.pop('id')
        self.assertDictEqual(data_ref, data)

        new_data_ref = self.token_api.get_token(token_id)
        expires = new_data_ref.pop('expires')
        self.assertTrue(isinstance(expires, datetime.datetime))
        new_data_ref.pop('user_id')
        new_data_ref.pop('id')

        self.assertEquals(new_data_ref, data)

        self.token_api.delete_token(token_id)
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.get_token, token_id)
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.delete_token, token_id)

    def create_token_sample_data(self, tenant_id=None, trust_id=None):
        token_id = self._create_token_id()
        data = {'id': token_id, 'a': 'b',
                'user': {'id': 'testuserid'}}
        if tenant_id is not None:
            data['tenant'] = {'id': tenant_id, 'name': tenant_id}
        if tenant_id is NULL_OBJECT:
            data['tenant'] = None
        if trust_id is not None:
            data['trust_id'] = trust_id
        new_token = self.token_api.create_token(token_id, data)
        return new_token['id']

    def test_token_list(self):
        tokens = self.token_api.list_tokens('testuserid')
        self.assertEquals(len(tokens), 0)
        token_id1 = self.create_token_sample_data()
        tokens = self.token_api.list_tokens('testuserid')
        self.assertEquals(len(tokens), 1)
        self.assertIn(token_id1, tokens)
        token_id2 = self.create_token_sample_data()
        tokens = self.token_api.list_tokens('testuserid')
        self.assertEquals(len(tokens), 2)
        self.assertIn(token_id2, tokens)
        self.assertIn(token_id1, tokens)
        self.token_api.delete_token(token_id1)
        tokens = self.token_api.list_tokens('testuserid')
        self.assertIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)
        self.token_api.delete_token(token_id2)
        tokens = self.token_api.list_tokens('testuserid')
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id1, tokens)

        # tenant-specific tokens
        tenant1 = uuid.uuid4().hex
        tenant2 = uuid.uuid4().hex
        token_id3 = self.create_token_sample_data(tenant_id=tenant1)
        token_id4 = self.create_token_sample_data(tenant_id=tenant2)
        # test for existing but empty tenant (LP:1078497)
        token_id5 = self.create_token_sample_data(tenant_id=NULL_OBJECT)
        tokens = self.token_api.list_tokens('testuserid')
        self.assertEquals(len(tokens), 3)
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)
        self.assertIn(token_id5, tokens)
        tokens = self.token_api.list_tokens('testuserid', tenant2)
        self.assertEquals(len(tokens), 1)
        self.assertNotIn(token_id1, tokens)
        self.assertNotIn(token_id2, tokens)
        self.assertNotIn(token_id3, tokens)
        self.assertIn(token_id4, tokens)

    def test_token_list_trust(self):
        trust_id = uuid.uuid4().hex
        token_id5 = self.create_token_sample_data(trust_id=trust_id)
        tokens = self.token_api.list_tokens('testuserid', trust_id=trust_id)
        self.assertEquals(len(tokens), 1)
        self.assertIn(token_id5, tokens)

    def test_get_token_404(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.get_token,
                          uuid.uuid4().hex)
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.get_token,
                          None)

    def test_delete_token_404(self):
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.delete_token,
                          uuid.uuid4().hex)

    def test_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)
        self.assertRaises(exception.TokenNotFound,
                          self.token_api.get_token, token_id)

    def test_null_expires_token(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'id_hash': token_id, 'a': 'b', 'expires': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        self.assertIsNotNone(data_ref['expires'])
        new_data_ref = self.token_api.get_token(token_id)

        # MySQL doesn't store microseconds, so discard them before testing
        data_ref['expires'] = data_ref['expires'].replace(microsecond=0)
        new_data_ref['expires'] = new_data_ref['expires'].replace(
            microsecond=0)

        self.assertEqual(data_ref, new_data_ref)

    def check_list_revoked_tokens(self, token_ids):
        revoked_ids = [x['id'] for x in self.token_api.list_revoked_tokens()]
        for token_id in token_ids:
            self.assertIn(token_id, revoked_ids)

    def delete_token(self):
        token_id = uuid.uuid4().hex
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        self.token_api.delete_token(token_id)
        self.assertRaises(
            exception.TokenNotFound,
            self.token_api.get_token,
            data_ref['id'])
        self.assertRaises(
            exception.TokenNotFound,
            self.token_api.delete_token,
            data_ref['id'])
        return token_id

    def test_list_revoked_tokens_returns_empty_list(self):
        revoked_ids = [x['id'] for x in self.token_api.list_revoked_tokens()]
        self.assertEqual(revoked_ids, [])

    def test_list_revoked_tokens_for_single_token(self):
        self.check_list_revoked_tokens([self.delete_token()])

    def test_list_revoked_tokens_for_multiple_tokens(self):
        self.check_list_revoked_tokens([self.delete_token()
                                        for x in xrange(2)])

    def test_flush_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() - datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)

        token_id = uuid.uuid4().hex
        expire_time = timeutils.utcnow() + datetime.timedelta(minutes=1)
        data = {'id_hash': token_id, 'id': token_id, 'a': 'b',
                'expires': expire_time,
                'trust_id': None,
                'user': {'id': 'testuserid'}}
        data_ref = self.token_api.create_token(token_id, data)
        data_ref.pop('user_id')
        self.assertDictEqual(data_ref, data)

        self.token_api.flush_expired_tokens()
        tokens = self.token_api.list_tokens('testuserid')
        self.assertEqual(len(tokens), 1)
        self.assertIn(token_id, tokens)


class TrustTests(object):
    def create_sample_trust(self, new_id):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        trust_data = (self.trust_api.create_trust
                      (new_id,
                       {'trustor_user_id': self.trustor['id'],
                       'trustee_user_id': self.user_two['id'],
                       'project_id': self.tenant_bar['id'],
                       'expires_at': timeutils.
                        parse_isotime('2031-02-18T18:10:00Z'),
                       'impersonation': True},
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
        self.assertEquals(new_id, trust_data['id'])
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
        self.assertEquals(new_id, trust_data['id'])

    def test_create_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)

        self.assertEquals(new_id, trust_data['id'])
        self.assertEquals(self.trustee['id'], trust_data['trustee_user_id'])
        self.assertEquals(self.trustor['id'], trust_data['trustor_user_id'])
        self.assertTrue(timeutils.normalize_time(trust_data['expires_at']) >
                        timeutils.utcnow())

        self.assertEquals([{'id': 'member'},
                           {'id': 'other'},
                           {'id': 'browser'}], trust_data['roles'])

    def test_list_trust_by_trustee(self):
        for i in range(0, 3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustee(self.trustee['id'])
        self.assertEqual(len(trusts), 3)
        self.assertEqual(trusts[0]["trustee_user_id"], self.trustee['id'])
        trusts = self.trust_api.list_trusts_for_trustee(self.trustor['id'])
        self.assertEqual(len(trusts), 0)

    def test_list_trust_by_trustor(self):
        for i in range(0, 3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts_for_trustor(self.trustor['id'])
        self.assertEqual(len(trusts), 3)
        self.assertEqual(trusts[0]["trustor_user_id"], self.trustor['id'])
        trusts = self.trust_api.list_trusts_for_trustor(self.trustee['id'])
        self.assertEqual(len(trusts), 0)

    def test_list_trusts(self):
        for i in range(0, 3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 3)


class CommonHelperTests(test.TestCase):
    def test_format_helper_raises_malformed_on_missing_key(self):
        with self.assertRaises(exception.MalformedEndpoint):
            core.format_url("http://%(foo)s/%(bar)s", {"foo": "1"})

    def test_format_helper_raises_malformed_on_wrong_type(self):
        with self.assertRaises(exception.MalformedEndpoint):
            core.format_url("http://%foo%s", {"foo": "1"})

    def test_format_helper_raises_malformed_on_incomplete_format(self):
        with self.assertRaises(exception.MalformedEndpoint):
            core.format_url("http://%(foo)", {"foo": "1"})


class CatalogTests(object):
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
        self.assertDictEqual(res, new_service)

        # list
        services = self.catalog_api.list_services()
        self.assertIn(service_id, [x['id'] for x in services])

        # delete
        self.catalog_api.delete_service(service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.delete_service, {}, service_id)
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.get_service, {}, service_id)

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
                          self.catalog_man.get_endpoint, {}, endpoint['id'])
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_man.delete_endpoint, {}, endpoint['id'])

    def test_get_service_404(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.get_service,
                          {},
                          uuid.uuid4().hex)

    def test_delete_service_404(self):
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.delete_service,
                          {},
                          uuid.uuid4().hex)

    def test_create_endpoint_404(self):
        endpoint = {
            'id': uuid.uuid4().hex,
            'service_id': uuid.uuid4().hex,
        }
        self.assertRaises(exception.ServiceNotFound,
                          self.catalog_man.create_endpoint,
                          {},
                          endpoint['id'],
                          endpoint)

    def test_get_endpoint_404(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_man.get_endpoint,
                          {},
                          uuid.uuid4().hex)

    def test_delete_endpoint_404(self):
        self.assertRaises(exception.EndpointNotFound,
                          self.catalog_man.delete_endpoint,
                          {},
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
            'region': "0" * 255,
            'service_id': service['id'],
            'interface': 'public',
            'url': uuid.uuid4().hex,
        }
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())


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
                          self.policy_man.update_policy,
                          {},
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
                          self.policy_man.delete_policy, {}, ref['id'])
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_man.get_policy, {}, ref['id'])
        res = self.policy_api.list_policies()
        self.assertFalse(len([x for x in res if x['id'] == ref['id']]))

    def test_get_policy_404(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_man.get_policy,
                          {},
                          uuid.uuid4().hex)

    def test_update_policy_404(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_man.update_policy,
                          {},
                          uuid.uuid4().hex,
                          {})

    def test_delete_policy_404(self):
        self.assertRaises(exception.PolicyNotFound,
                          self.policy_man.delete_policy,
                          {},
                          uuid.uuid4().hex)
