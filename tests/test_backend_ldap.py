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

    def test_role_crud(self):
        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_role(role['id'], role)
        role_ref = self.identity_api.get_role(role['id'])
        role_ref_dict = dict((x, role_ref[x]) for x in role_ref)
        self.assertDictEqual(role_ref_dict, role)
        self.identity_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          role['id'])

    def test_build_tree(self):
        """Regression test for building the tree names
        """
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])

        user_api = identity_ldap.UserApi(CONF)
        self.assertTrue(user_api)
        self.assertEquals(user_api.tree_dn, "ou=Users,%s" % CONF.ldap.suffix)

    def test_configurable_allowed_user_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        self.identity_api = identity_ldap.Identity()

        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        self.identity_api.create_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['id'], 'fake1')

        user['password'] = 'fakepass2'
        self.identity_api.update_user('fake1', user)

        self.identity_api.delete_user('fake1')
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'fake1')

    def test_configurable_forbidden_user_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.user_allow_create = False
        CONF.ldap.user_allow_update = False
        CONF.ldap.user_allow_delete = False
        self.identity_api = identity_ldap.Identity()

        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass1',
                'tenants': ['bar']}
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_user,
                          'fake1',
                          user)

        self.user_foo['password'] = 'fakepass2'
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_user,
                          self.user_foo['id'],
                          self.user_foo)

        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.delete_user,
                          self.user_foo['id'])

    def test_configurable_allowed_tenant_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        self.identity_api = identity_ldap.Identity()

        tenant = {'id': 'fake1', 'name': 'fake1', 'enabled': True}
        self.identity_api.create_tenant('fake1', tenant)
        tenant_ref = self.identity_api.get_tenant('fake1')
        self.assertEqual(tenant_ref['id'], 'fake1')

        tenant['enabled'] = 'False'
        self.identity_api.update_tenant('fake1', tenant)

        self.identity_api.delete_tenant('fake1')
        self.assertRaises(exception.TenantNotFound,
                          self.identity_api.get_tenant,
                          'fake1')

    def test_configurable_forbidden_tenant_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.tenant_allow_create = False
        CONF.ldap.tenant_allow_update = False
        CONF.ldap.tenant_allow_delete = False
        self.identity_api = identity_ldap.Identity()

        tenant = {'id': 'fake1', 'name': 'fake1'}
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_tenant,
                          'fake1',
                          tenant)

        self.tenant_bar['enabled'] = 'False'
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_tenant,
                          self.tenant_bar['id'],
                          self.tenant_bar)
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.delete_tenant,
                          self.tenant_bar['id'])

    def test_configurable_allowed_role_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        self.identity_api = identity_ldap.Identity()

        role = {'id': 'fake1', 'name': 'fake1'}
        self.identity_api.create_role('fake1', role)
        role_ref = self.identity_api.get_role('fake1')
        self.assertEqual(role_ref['id'], 'fake1')

        role['name'] = 'fake2'
        self.identity_api.update_role('fake1', role)

        self.identity_api.delete_role('fake1')
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          'fake1')

    def test_configurable_forbidden_role_actions(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.role_allow_create = False
        CONF.ldap.role_allow_update = False
        CONF.ldap.role_allow_delete = False
        self.identity_api = identity_ldap.Identity()

        role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.create_role,
                          role['id'],
                          role)

        self.role_member['name'] = uuid.uuid4().hex
        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.update_role,
                          self.role_member['id'],
                          self.role_member)

        self.assertRaises(exception.ForbiddenAction,
                          self.identity_api.delete_role,
                          self.role_member['id'])

    def test_user_filter(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        user_ref = self.identity_api.get_user(self.user_foo['id'])
        self.user_foo.pop('password')
        self.assertDictEqual(user_ref, self.user_foo)

        CONF.ldap.user_filter = '(CN=DOES_NOT_MATCH)'
        self.identity_api = identity_ldap.Identity()
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          self.user_foo['id'])

    def test_tenant_filter(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        tenant_ref = self.identity_api.get_tenant(self.tenant_bar['id'])
        self.assertDictEqual(tenant_ref, self.tenant_bar)

        CONF.ldap.tenant_filter = '(CN=DOES_NOT_MATCH)'
        self.identity_api = identity_ldap.Identity()
        self.assertRaises(exception.TenantNotFound,
                          self.identity_api.get_tenant,
                          self.tenant_bar['id'])

    def test_role_filter(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        role_ref = self.identity_api.get_role(self.role_member['id'])
        self.assertDictEqual(role_ref, self.role_member)

        CONF.ldap.role_filter = '(CN=DOES_NOT_MATCH)'
        self.identity_api = identity_ldap.Identity()
        self.assertRaises(exception.RoleNotFound,
                          self.identity_api.get_role,
                          self.role_member['id'])

    def test_dumb_member(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.use_dumb_member = True
        CONF.ldap.dumb_member = 'cn=dumb,cn=example,cn=com'
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user,
                          'dumb')

    def test_user_attribute_mapping(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.user_name_attribute = 'sn'
        CONF.ldap.user_mail_attribute = 'email'
        CONF.ldap.user_enabled_attribute = 'enabled'
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        user_ref = self.identity_api.get_user(self.user_two['id'])
        self.assertEqual(user_ref['id'], self.user_two['id'])
        self.assertEqual(user_ref['name'], self.user_two['name'])
        self.assertEqual(user_ref['email'], self.user_two['email'])
        self.assertEqual(user_ref['enabled'], self.user_two['enabled'])

        CONF.ldap.user_name_attribute = 'email'
        CONF.ldap.user_mail_attribute = 'sn'
        self.identity_api = identity_ldap.Identity()
        user_ref = self.identity_api.get_user(self.user_two['id'])
        self.assertEqual(user_ref['id'], self.user_two['id'])
        self.assertEqual(user_ref['name'], self.user_two['email'])
        self.assertEqual(user_ref['email'], self.user_two['name'])
        self.assertEqual(user_ref['enabled'], self.user_two['enabled'])

    def test_user_attribute_ignore(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.user_attribute_ignore = ['name', 'email', 'password',
                                           'tenant_id', 'enabled', 'tenants']
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        user_ref = self.identity_api.get_user(self.user_two['id'])
        self.assertEqual(user_ref['id'], self.user_two['id'])
        self.assertNotIn('name', user_ref)
        self.assertNotIn('email', user_ref)
        self.assertNotIn('password', user_ref)
        self.assertNotIn('tenant_id', user_ref)
        self.assertNotIn('enabled', user_ref)
        self.assertNotIn('tenants', user_ref)

    def test_tenant_attribute_mapping(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.tenant_name_attribute = 'ou'
        CONF.ldap.tenant_desc_attribute = 'desc'
        CONF.ldap.tenant_enabled_attribute = 'enabled'
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        tenant_ref = self.identity_api.get_tenant(self.tenant_baz['id'])
        self.assertEqual(tenant_ref['id'], self.tenant_baz['id'])
        self.assertEqual(tenant_ref['name'], self.tenant_baz['name'])
        self.assertEqual(
            tenant_ref['description'],
            self.tenant_baz['description'])
        self.assertEqual(tenant_ref['enabled'], self.tenant_baz['enabled'])

        CONF.ldap.tenant_name_attribute = 'desc'
        CONF.ldap.tenant_desc_attribute = 'ou'
        self.identity_api = identity_ldap.Identity()
        tenant_ref = self.identity_api.get_tenant(self.tenant_baz['id'])
        self.assertEqual(tenant_ref['id'], self.tenant_baz['id'])
        self.assertEqual(tenant_ref['name'], self.tenant_baz['description'])
        self.assertEqual(tenant_ref['description'], self.tenant_baz['name'])
        self.assertEqual(tenant_ref['enabled'], self.tenant_baz['enabled'])

    def test_tenant_attribute_ignore(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.tenant_attribute_ignore = ['name',
                                             'description',
                                             'enabled']
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        tenant_ref = self.identity_api.get_tenant(self.tenant_baz['id'])
        self.assertEqual(tenant_ref['id'], self.tenant_baz['id'])
        self.assertNotIn('name', tenant_ref)
        self.assertNotIn('description', tenant_ref)
        self.assertNotIn('enabled', tenant_ref)

    def test_role_attribute_mapping(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.role_name_attribute = 'ou'
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        role_ref = self.identity_api.get_role(self.role_member['id'])
        self.assertEqual(role_ref['id'], self.role_member['id'])
        self.assertEqual(role_ref['name'], self.role_member['name'])

        CONF.ldap.role_name_attribute = 'sn'
        self.identity_api = identity_ldap.Identity()
        role_ref = self.identity_api.get_role(self.role_member['id'])
        self.assertEqual(role_ref['id'], self.role_member['id'])
        self.assertNotIn('name', role_ref)

    def test_role_attribute_ignore(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.role_attribute_ignore = ['name']
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        role_ref = self.identity_api.get_role(self.role_member['id'])
        self.assertEqual(role_ref['id'], self.role_member['id'])
        self.assertNotIn('name', role_ref)

    def test_user_enable_attribute_mask(self):
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_ldap.conf')])
        CONF.ldap.user_enabled_attribute = 'enabled'
        CONF.ldap.user_enabled_mask = 2
        CONF.ldap.user_enabled_default = 512
        clear_database()
        self.identity_api = identity_ldap.Identity()
        user = {'id': 'fake1', 'name': 'fake1', 'enabled': True}
        self.identity_api.create_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)

        user['enabled'] = False
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], False)

        user['enabled'] = True
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['enabled'], True)
