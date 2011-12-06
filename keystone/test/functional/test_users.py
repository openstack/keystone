#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest2 as unittest
from keystone.test.functional import common


class UserTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(UserTest, self).setUp(*args, **kwargs)


class CreateUserTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(CreateUserTest, self).setUp(*args, **kwargs)

    def test_create_user_with_tenant(self):
        tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(tenant_id=tenant['id'],
            assert_status=201)

    def test_user_with_no_tenant(self):
        self.create_user(assert_status=201)

    def test_create_user_disabled_tenant(self):
        tenant = self.create_tenant(tenant_enabled=False).json['tenant']
        self.create_user(tenant_id=tenant['id'], assert_status=403)

    def test_create_user_again(self):
        user_name = common.unique_str()
        self.create_user(user_name)
        self.create_user(user_name, assert_status=409)

    def test_create_users_with_duplicate_emails(self):
        email = common.unique_email()
        self.create_user(user_email=email)
        self.create_user(user_email=email, assert_status=409)

    def test_create_user_with_empty_password(self):
        self.create_user(user_password='', assert_status=400)

    def test_create_user_with_empty_username(self):
        self.create_user(user_name='', assert_status=400)

    def test_create_user_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.create_user(assert_status=403)

    def test_create_user_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_user(assert_status=403)

    def test_create_user_missing_token(self):
        self.admin_token = ''
        self.create_user(assert_status=401)

    def test_create_user_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_user(assert_status=401)

    def test_create_user_xml_missing_name(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
        '<user xmlns="http://docs.openstack.org/identity/api/v2.0" '
              'enabled="true" email="john.smith@example.org" '
              'name="" id="u1000"/>')
        self.post_user(as_xml=data, assert_status=400)


class GetUserTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(GetUserTest, self).setUp(*args, **kwargs)

        self.user = self.create_user().json['user']

    def test_get_user(self):
        self.fetch_user(self.user['id'])

    def test_query_user(self):
        self.fetch_user_by_name(self.user['name'])

    def test_get_user_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_user(self.user['id'], assert_status=403)

    def test_query_user_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_user_by_name(self.user['name'], assert_status=403)

    def test_get_user_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_user(self.user['id'], assert_status=403)

    def test_query_user_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_user_by_name(self.user['name'], assert_status=403)

    def test_get_user_using_missing_token(self):
        self.admin_token = ''
        self.fetch_user(self.user['id'], assert_status=401)

    def test_query_user_using_missing_token(self):
        self.admin_token = ''
        self.fetch_user_by_name(self.user['name'], assert_status=401)

    def test_get_user_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_user(self.user['id'], assert_status=401)

    def test_query_user_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_user_by_name(self.user['name'], assert_status=401)

    def test_get_disabled_user(self):
        self.disable_user(self.user['id'])
        user = self.fetch_user(self.user['id']).json['user']
        self.assertFalse(user['enabled'])

    def test_query_disabled_user(self):
        self.disable_user(self.user['id'])
        self.fetch_user_by_name(self.user['name'])


class DeleteUserTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(DeleteUserTest, self).setUp(*args, **kwargs)

        self.user = self.create_user().json['user']

    def test_user_delete(self):
        self.remove_user(self.user['id'], assert_status=204)

    def test_user_delete_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.remove_user(self.user['id'], assert_status=403)

    def test_user_delete_missing_token(self):
        self.admin_token = ''
        self.remove_user(self.user['id'], assert_status=401)

    def test_user_delete_invalid_token(self):
        self.admin_token = common.unique_str()
        self.remove_user(self.user['id'], assert_status=401)


class GetAllUsersTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(GetAllUsersTest, self).setUp(*args, **kwargs)

        for _x in range(0, 3):
            self.create_user()

    def test_list_users(self):
        self.list_users(assert_status=200)

    def test_list_users_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.list_users(assert_status=403)

    def test_list_users_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.list_users(assert_status=403)

    def test_list_users_missing_token(self):
        self.admin_token = ''
        self.list_users(assert_status=401)

    def test_list_users_invalid_token(self):
        self.admin_token = common.unique_str()
        self.list_users(assert_status=401)


class UpdateUserTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(UpdateUserTest, self).setUp(*args, **kwargs)

        self.user = self.create_user().json['user']

    def test_update_user_email(self):
        new_user_email = common.unique_email()
        self.update_user(self.user['id'], user_name=self.user['name'],
                         user_email=new_user_email)
        r = self.fetch_user(self.user['id'])
        self.assertTrue(r.json['user']['email'], new_user_email)

    def test_update_user_name(self):
        new_user_name = common.unique_str()
        new_user_email = common.unique_email()
        self.update_user(self.user['id'], user_name=new_user_name,
            user_email=new_user_email)
        r = self.fetch_user(self.user['id'])
        self.assertTrue(r.json['user']['name'], new_user_name)

    def test_enable_disable_user(self):
        self.assertFalse(self.disable_user(self.user['id']).\
            json['user']['enabled'])
        self.assertFalse(self.fetch_user(self.user['id']).\
            json['user']['enabled'])
        self.assertTrue(self.enable_user(self.user['id']).\
            json['user']['enabled'])
        self.assertTrue(self.fetch_user(self.user['id']).\
            json['user']['enabled'])

    def test_update_user_bad_request(self):
        data = '{"user_bad": { "bad": "%s"}}' % (common.unique_email(),)
        self.post_user_for_update(
            self.user['id'], assert_status=400, body=data, headers={
            "Content-Type": "application/json"})

    def test_update_user_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.update_user(self.user['id'], assert_status=403)

    def test_update_user_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.update_user(self.user['id'], user_email=common.unique_email(),
            assert_status=403)

    def test_update_user_invalid_token(self):
        self.admin_token = common.unique_str()
        self.update_user(self.user['id'], assert_status=401)

    def test_update_user_missing_token(self):
        self.admin_token = ''
        self.update_user(self.user['id'], assert_status=401)


class TestUpdateConflict(UserTest):
    def setUp(self, *args, **kwargs):
        super(TestUpdateConflict, self).setUp(*args, **kwargs)

        self.users = {}
        for x in range(0, 2):
            self.users[x] = self.create_user().json['user']

    def test_update_user_email_conflict(self):
        """Replace the second user's email with that of the first"""
        self.update_user(user_id=self.users[1]['id'],
                user_name=self.users[1]['name'],
            user_email=self.users[0]['email'], assert_status=409)


class SetPasswordTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(SetPasswordTest, self).setUp(*args, **kwargs)
        self.user = self.create_user().json['user']

    def test_update_user_password(self):
        new_password = common.unique_str()
        r = self.update_user_password(self.user['id'], new_password)
        self.assertEqual(r.json['user']['password'], new_password)

    def test_update_disabled_users_password(self):
        self.disable_user(self.user['id'])

        new_password = common.unique_str()
        r = self.update_user_password(self.user['id'], new_password)
        self.assertEqual(r.json['user']['password'], new_password)

    def test_user_password_bad_request(self):
        data = '{"user_bad": { "password": "p@ssword"}}'
        self.put_user_password(self.user['id'], body=data, assert_status=400,
            headers={
                "Content-Type": "application/json"})

    def test_user_password_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.update_user_password(self.user['id'], assert_status=403)

    def test_user_password_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.update_user_password(self.user['id'], assert_status=403)

    def test_user_password_invalid_token(self):
        self.admin_token = common.unique_str()
        self.update_user_password(self.user['id'], assert_status=401)

    def test_user_password_missing_token(self):
        self.admin_token = ''
        self.update_user_password(self.user['id'], assert_status=401)


class SetEnabledTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(SetEnabledTest, self).setUp(*args, **kwargs)
        self.user = self.create_user().json['user']

    def test_user_enabled_bad_request(self):
        data = '{"user_bad": { "enabled": true}}'
        self.put_user_enabled(self.user['id'], body=data, assert_status=400,
            headers={
                "Content-Type": "application/json"})

    def test_user_enabled_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.disable_user(self.user['id'], assert_status=403)

    def test_user_enabled_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.disable_user(self.user['id'], assert_status=403)


class TenantUpdateTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(TenantUpdateTest, self).setUp(*args, **kwargs)
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user().json['user']

    def test_update_user_tenant(self):
        r = self.update_user_tenant(self.user['id'], self.tenant['id'])
        self.assertEqual(r.json['user']['tenantId'], self.tenant['id'])

    def test_update_user_tenant_using_invalid_tenant(self):
        self.update_user_tenant(self.user['id'], assert_status=404)

    def test_update_user_tenant_using_disabled_tenant(self):
        disabled_tenant = self.create_tenant(
            tenant_enabled=False).json['tenant']
        self.assertIsNotNone(disabled_tenant['id'])
        self.update_user_tenant(self.user['id'], disabled_tenant['id'],
            assert_status=403)

    def test_update_user_tenant_using_missing_token(self):
        self.admin_token = ''
        self.update_user_tenant(self.user['id'], self.tenant['id'],
            assert_status=401)

    def test_update_user_tenant_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.update_user_tenant(self.user['id'], self.tenant['id'],
            assert_status=401)

    def test_update_user_tenant_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.update_user_tenant(self.user['id'], self.tenant['id'],
            assert_status=403)

    def test_update_user_tenant_using_exp_admin_token(self):
        self.admin_token = self.expired_admin_token
        self.update_user_tenant(self.user['id'], self.tenant['id'],
            assert_status=403)


class AddUserTest(UserTest):
    def setUp(self, *args, **kwargs):
        super(AddUserTest, self).setUp(*args, **kwargs)
        self.tenant = self.create_tenant().json['tenant']

    def test_add_user_tenant(self):
        self.create_user(tenant_id=self.tenant['id'], assert_status=201)

    def test_add_user_tenant_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.create_user(assert_status=403)

    def test_add_user_tenant_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_user(assert_status=403)

    def test_add_user_tenant_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_user(assert_status=401)

    def test_add_user_tenant_missing_token(self):
        self.admin_token = ''
        self.create_user(assert_status=401)

    def test_add_user_tenant_disabled_tenant(self):
        self.tenant = self.create_tenant(tenant_enabled=False).json['tenant']
        self.create_user(tenant_id=self.tenant['id'], assert_status=403)


if __name__ == '__main__':
    unittest.main()
