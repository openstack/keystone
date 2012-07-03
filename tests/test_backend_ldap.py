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

import uuid

from keystone.common.ldap import fakeldap
from keystone import config
from keystone import exception
from keystone.identity.backends import ldap as identity_ldap
from keystone import test

import default_fixtures
import test_backend


CONF = config.CONF


def clear_database():
    db = fakeldap.FakeShelve().get_instance()
    db.clear()


class LDAPIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
        super(LDAPIdentity, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)

    def test_delete_tenant_404(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.delete_tenant,
                          uuid.uuid4().hex)

    def test_delete_user_404(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_rename_duplicate_role_name_fails(self):
        role1 = {'id': 'fake1',
                'name': 'fake1name'}
        role2 = {'id': 'fake2',
                'name': 'fake2name'}
        self.identity_api.create_role('fake1', role1)
        self.identity_api.create_role('fake2', role2)
        role1['name'] = 'fake2name'
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.update_role,
                          'fake1',
                          role1)

    def test_rename_duplicate_user_name_fails(self):
        user1 = {'id': 'fake1',
                 'name': 'fake1',
                 'password': 'fakepass',
                 'tenants': ['bar']}
        user2 = {'id': 'fake2',
                 'name': 'fake2',
                 'password': 'fakepass',
                 'tenants': ['bar']}
        self.identity_api.create_user('fake1', user1)
        self.identity_api.create_user('fake2', user2)
        user2['name'] = 'fake1'
        self.assertRaises(exception.ValidationError,
                          self.identity_api.update_user,
                          'fake2',
                          user2)

    def test_delete_user_with_tenant_association(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.delete_user,
                          uuid.uuid4().hex)

    def test_remove_user_from_tenant(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.remove_user_from_tenant,
                          self.tenant_bar['id'],
                          self.user_foo['id'])

    def test_remove_user_from_tenant_404(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.remove_user_from_tenant,
                          self.tenant_bar['id'],
                          self.user_foo['id'])

    def test_remove_role_from_user_and_tenant(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.remove_role_from_user_and_tenant,
                          self.tenant_bar['id'],
                          self.user_foo['id'],
                          'useless')

    def test_role_crud(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        role_ref = self.identity_api.get_role(role['id'])
        role_ref_dict = dict((x, role_ref[x]) for x in role_ref)
        self.assertDictEqual(role_ref_dict, role)

        self.assertRaises(exception.NotImplemented,
                          self.identity_api.update_role,
                          role['id'],
                          role)

        self.identity_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          role['id'])

    def test_update_role_404(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.update_role,
                          uuid.uuid4().hex,
                          {})

    def test_get_tenant_users_404(self):
        self.assertRaises(exception.NotImplemented,
                          self.identity_api.get_tenant_users,
                          tenant_id=uuid.uuid4().hex)

    def test_build_tree(self):
        """Regression test for building the tree names
        """
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])

        user_api = identity_ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEquals(user_api.tree_dn, "ou=Users,%s" % CONF.ldap.suffix)

