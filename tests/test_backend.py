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
import uuid

from keystone import exception


class IdentityTests(object):
    def test_authenticate_bad_user(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=self.user_foo['id'] + 'WRONG',
                          tenant_id=self.tenant_bar['id'],
                          password=self.user_foo['password'])

    def test_authenticate_bad_password(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=self.user_foo['id'],
                          tenant_id=self.tenant_bar['id'],
                          password=self.user_foo['password'] + 'WRONG')

    def test_authenticate_invalid_tenant(self):
        self.assertRaises(AssertionError,
                          self.identity_api.authenticate,
                          user_id=self.user_foo['id'],
                          tenant_id=self.tenant_bar['id'] + 'WRONG',
                          password=self.user_foo['password'])

    def test_authenticate_no_tenant(self):
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
                user_id=self.user_foo['id'],
                password=self.user_foo['password'])
        # NOTE(termie): the password field is left in user_foo to make it easier
        #               to authenticate in tests, but should not be returned by
        #               the api
        self.user_foo.pop('password')
        self.assertDictEquals(user_ref, self.user_foo)
        self.assert_(tenant_ref is None)
        self.assert_(not metadata_ref)

    def test_authenticate(self):
        user_ref, tenant_ref, metadata_ref = self.identity_api.authenticate(
                user_id=self.user_foo['id'],
                tenant_id=self.tenant_bar['id'],
                password=self.user_foo['password'])
        # NOTE(termie): the password field is left in user_foo to make it easier
        #               to authenticate in tests, but should not be returned by
        #               the api
        self.user_foo.pop('password')
        self.assertDictEquals(user_ref, self.user_foo)
        self.assertDictEquals(tenant_ref, self.tenant_bar)
        self.assertDictEquals(metadata_ref, self.metadata_foobar)

    def test_password_hashed(self):
        user_ref = self.identity_api._get_user(self.user_foo['id'])
        self.assertNotEqual(user_ref['password'], self.user_foo['password'])


    def test_get_tenant_bad_tenant(self):
        tenant_ref = self.identity_api.get_tenant(
                tenant_id=self.tenant_bar['id'] + 'WRONG')
        self.assert_(tenant_ref is None)

    def test_get_tenant(self):
        tenant_ref = self.identity_api.get_tenant(tenant_id=self.tenant_bar['id'])
        self.assertDictEquals(tenant_ref, self.tenant_bar)

    def test_get_tenant_by_name_bad_tenant(self):
        tenant_ref = self.identity_api.get_tenant(
                tenant_id=self.tenant_bar['name'] + 'WRONG')
        self.assert_(tenant_ref is None)

    def test_get_tenant_by_name(self):
        tenant_ref = self.identity_api.get_tenant_by_name(
                tenant_name=self.tenant_bar['name'])
        self.assertDictEquals(tenant_ref, self.tenant_bar)

    def test_get_user_bad_user(self):
        user_ref = self.identity_api.get_user(
                user_id=self.user_foo['id'] + 'WRONG')
        self.assert_(user_ref is None)

    def test_get_user(self):
        user_ref = self.identity_api.get_user(user_id=self.user_foo['id'])
        # NOTE(termie): the password field is left in user_foo to make it easier
        #               to authenticate in tests, but should not be returned by
        #               the api
        self.user_foo.pop('password')
        self.assertDictEquals(user_ref, self.user_foo)

    def test_get_metadata_bad_user(self):
        metadata_ref = self.identity_api.get_metadata(
                user_id=self.user_foo['id'] + 'WRONG',
                tenant_id=self.tenant_bar['id'])
        self.assert_(metadata_ref is None)

    def test_get_metadata_bad_tenant(self):
        metadata_ref = self.identity_api.get_metadata(
                user_id=self.user_foo['id'],
                tenant_id=self.tenant_bar['id'] + 'WRONG')
        self.assert_(metadata_ref is None)

    def test_get_metadata(self):
        metadata_ref = self.identity_api.get_metadata(
                user_id=self.user_foo['id'],
                tenant_id=self.tenant_bar['id'])
        self.assertDictEquals(metadata_ref, self.metadata_foobar)

    def test_get_role(self):
        role_ref = self.identity_api.get_role(
                role_id=self.role_keystone_admin['id'])
        self.assertDictEquals(role_ref, self.role_keystone_admin)

    def test_create_duplicate_user_id_fails(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass',
                'tenants': ['bar',]}
        self.identity_api.create_user('fake1', user)
        user['name'] = 'fake2'
        self.assertRaises(Exception,
                          self.identity_api.create_user,
                          'fake1',
                          user)

    def test_create_duplicate_user_name_fails(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass',
                'tenants': ['bar',]}
        self.identity_api.create_user('fake1', user)
        user['id'] = 'fake2'
        self.assertRaises(Exception,
                          self.identity_api.create_user,
                          'fake2',
                          user)

    def test_rename_duplicate_user_name_fails(self):
        user1 = {'id': 'fake1',
                 'name': 'fake1',
                 'password': 'fakepass',
                 'tenants': ['bar',]}
        user2 = {'id': 'fake2',
                 'name': 'fake2',
                 'password': 'fakepass',
                 'tenants': ['bar',]}
        self.identity_api.create_user('fake1', user1)
        self.identity_api.create_user('fake2', user2)
        user2['name'] = 'fake1'
        self.assertRaises(Exception,
                          self.identity_api.update_user,
                          'fake2',
                          user2)

    def test_update_user_id_does_nothing(self):
        user = {'id': 'fake1',
                'name': 'fake1',
                'password': 'fakepass',
                'tenants': ['bar',]}
        self.identity_api.create_user('fake1', user)
        user['id'] = 'fake2'
        self.identity_api.update_user('fake1', user)
        user_ref = self.identity_api.get_user('fake1')
        self.assertEqual(user_ref['id'], 'fake1')
        user_ref = self.identity_api.get_user('fake2')
        self.assert_(user_ref is None)

    def test_create_duplicate_tenant_id_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake1'}
        self.identity_api.create_tenant('fake1', tenant)
        tenant['name'] = 'fake2'
        self.assertRaises(Exception,
                          self.identity_api.create_tenant,
                          'fake1',
                          tenant)

    def test_create_duplicate_tenant_name_fails(self):
        tenant = {'id': 'fake1', 'name': 'fake'}
        self.identity_api.create_tenant('fake1', tenant)
        tenant['id'] = 'fake2'
        self.assertRaises(Exception,
                          self.identity_api.create_tenant,
                          'fake1',
                          tenant)

    def test_rename_duplicate_tenant_name_fails(self):
        tenant1 = {'id': 'fake1', 'name': 'fake1'}
        tenant2 = {'id': 'fake2', 'name': 'fake2'}
        self.identity_api.create_tenant('fake1', tenant1)
        self.identity_api.create_tenant('fake2', tenant2)
        tenant2['name'] = 'fake1'
        self.assertRaises(Exception,
                          self.identity_api.update_tenant,
                          'fake2',
                          tenant2)

    def test_update_tenant_id_does_nothing(self):
        tenant = {'id': 'fake1', 'name': 'fake1'}
        self.identity_api.create_tenant('fake1', tenant)
        tenant['id'] = 'fake2'
        self.identity_api.update_tenant('fake1', tenant)
        tenant_ref = self.identity_api.get_tenant('fake1')
        self.assertEqual(tenant_ref['id'], 'fake1')
        tenant_ref = self.identity_api.get_tenant('fake2')
        self.assert_(tenant_ref is None)


class TokenTests(object):
    def test_token_crud(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'a': 'b'}
        data_ref = self.token_api.create_token(token_id, data)
        expires = data_ref.pop('expires')
        self.assertTrue(isinstance(expires, datetime.datetime))
        self.assertDictEquals(data_ref, data)

        new_data_ref = self.token_api.get_token(token_id)
        expires = new_data_ref.pop('expires')
        self.assertTrue(isinstance(expires, datetime.datetime))
        self.assertEquals(new_data_ref, data)

        self.token_api.delete_token(token_id)
        self.assertRaises(exception.TokenNotFound,
                self.token_api.delete_token, token_id)
        self.assertRaises(exception.TokenNotFound,
                self.token_api.get_token, token_id)

    def test_expired_token(self):
        token_id = uuid.uuid4().hex
        expire_time =  datetime.datetime.now() - datetime.timedelta(minutes=1)
        data = {'id': token_id, 'a': 'b', 'expires': expire_time}
        data_ref = self.token_api.create_token(token_id, data)
        self.assertDictEquals(data_ref, data)
        self.assertRaises(exception.TokenNotFound,
                self.token_api.get_token, token_id)

    def test_null_expires_token(self):
        token_id = uuid.uuid4().hex
        data = {'id': token_id, 'a': 'b', 'expires': None}
        data_ref = self.token_api.create_token(token_id, data)
        self.assertDictEquals(data_ref, data)
        new_data_ref = self.token_api.get_token(token_id)
        self.assertEqual(data_ref, new_data_ref)
