# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
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


class ValidateToken(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(ValidateToken, self).setUp(*args, **kwargs)

        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user_with_known_password(
            tenant_id=self.tenant['id']).json['user']
        self.role = self.create_role().json['role']
        self.role_ref = self.grant_role_to_user(self.user['id'],
            self.role['id'], self.tenant['id']).json['roleRef']
        self.token = self.authenticate(self.user['name'],
            self.user['password'], self.tenant['id']).json['auth']['token']

    def test_validate_token_true(self):
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200)

        self.assertIsNotNone(r.json['auth']['user']["roleRefs"])
        self.assertEqual(r.json['auth']['user']["roleRefs"][0]['id'],
            self.role_ref['id'])

    def test_validate_token_true_using_service_token(self):
        self.admin_token = self.service_admin_token
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200)

        self.assertIsNotNone(r.json['auth']['user']["roleRefs"])
        self.assertEqual(r.json['auth']['user']["roleRefs"][0]['id'],
            self.role_ref['id'])

    def test_validate_token_true_xml(self):
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200, headers={'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag, '{%s}auth' % self.xmlns)

        user = r.xml.find('{%s}user' % self.xmlns)
        self.assertIsNotNone(user)

        roleRefs = user.find('{%s}roleRefs' % self.xmlns)
        self.assertIsNotNone(roleRefs)

        roleRef = roleRefs.find('{%s}roleRef' % self.xmlns)
        self.assertIsNotNone(roleRef)
        self.assertEqual(self.role_ref['id'], roleRef.get("id"))

    def test_validate_token_expired(self):
        self.get_token(self.expired_admin_token, assert_status=403)

    def test_validate_token_expired_xml(self):
        self.get_token(self.expired_admin_token, assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_validate_token_invalid(self):
        self.get_token(common.unique_str(), assert_status=401)

    def test_validate_token_invalid_xml(self):
        self.get_token(common.unique_str(), assert_status=401, headers={
            'Accept': 'application/xml'})


if __name__ == '__main__':
    unittest.main()
