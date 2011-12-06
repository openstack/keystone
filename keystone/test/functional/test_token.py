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
            self.role['id'], self.tenant['id'])
        self.token = self.authenticate(self.user['name'],
            self.user['password'], self.tenant['id']).json['access']['token']

    def test_validate_token_true(self):
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200)

        self.assertIsNotNone(r.json['access']['user']["roles"])
        self.assertEqual(r.json['access']['user']["roles"][0]['id'],
            self.role['id'])
        self.assertEqual(r.json['access']['user']["roles"][0]['name'],
            self.role['name'])
        self.assertIsNotNone(r.json['access']['user']['id'], self.user['id'])
        self.assertIsNotNone(r.json['access']['user']['name'],
            self.user['name'])

    def test_validate_token_true_using_service_token(self):
        self.admin_token = self.service_admin_token
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200)

        self.assertIsNotNone(r.json['access']['user']["roles"])
        self.assertEqual(r.json['access']['user']["roles"][0]['id'],
            self.role['id'])
        self.assertEqual(r.json['access']['user']["roles"][0]['name'],
            self.role['name'])

    def test_validate_token_true_xml(self):
        r = self.get_token_belongsto(self.token['id'], self.tenant['id'],
            assert_status=200, headers={'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag, '{%s}access' % self.xmlns)

        user = r.xml.find('{%s}user' % self.xmlns)
        self.assertIsNotNone(user)
        self.assertEqual(self.user['id'], user.get('id'))
        self.assertEqual(self.user['name'], user.get('name'))

        roles = user.find('{%s}roles' % self.xmlns)
        self.assertIsNotNone(roles)

        role = roles.find('{%s}role' % self.xmlns)
        self.assertIsNotNone(role)
        self.assertEqual(self.role['id'], role.get("id"))
        self.assertEqual(self.role['name'], role.get("name"))

    def test_validate_token_expired(self):
        self.get_token(self.expired_admin_token, assert_status=404)

    def test_validate_token_expired_xml(self):
        self.get_token(self.expired_admin_token, assert_status=404, headers={
            'Accept': 'application/xml'})

    def test_validate_token_invalid(self):
        self.get_token(common.unique_str(), assert_status=404)

    def test_validate_token_invalid_xml(self):
        self.get_token(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


class CheckToken(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(CheckToken, self).setUp(*args, **kwargs)
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user_with_known_password(
            tenant_id=self.tenant['id']).json['user']
        self.token = self.authenticate(self.user['name'],
        self.user['password'], self.tenant['id']).json['access']['token']

    def test_validate_token_true(self):
        self.check_token_belongs_to(self.token['id'], self.tenant['id'],
            assert_status=200)

    def test_validate_token_true_using_service_token(self):
        self.admin_token = self.service_admin_token
        self.check_token_belongs_to(self.token['id'], self.tenant['id'],
            assert_status=200)

    def test_validate_token_expired(self):
        self.check_token(self.expired_admin_token, assert_status=404)

    def test_validate_token_expired_xml(self):
        self.check_token(self.expired_admin_token, assert_status=404, headers={
            'Accept': 'application/xml'})

    def test_validate_token_invalid(self):
        self.check_token(common.unique_str(), assert_status=404)


class TokenEndpointTest(unittest.TestCase):
    def _noop_validate_admin_token(self, admin_token):
        pass

    class FakeDtoken(object):
        expires = 'now'
        tenant_id = 1
        id = 2

        def _fake_token_get(self, token_id):
            return self.FakeDtoken()

        def _fake_missing_token_get(self, token_id):
            return None

    class FakeEndpoint(object):
        service = 'foo'

        def _fake_tenant_get_all_endpoints(self, tenant_id):
            return [self.FakeEndpoint()]

        def _fake_exploding_tenant_get_all_endpoints(self, tenant_id):
            raise Exception("boom")

        def setUp(self):
            self.stubout = stubout.StubOutForTesting()

            self.identity = service.IdentityService()
            # The downside of python "private" methods ... you
            # have to do stuff like this to stub them out.
            self.stubout.SmartSet(self.identity,
                                  "_IdentityService__validate_admin_token",
                                  self._noop_validate_admin_token)

        def tearDown(self):
            self.stubout.SmartUnsetAll()
            self.stubout.UnsetAll()

        def test_endpoints_from_good_token(self):
            """Happy Day scenario."""
            self.stubout.SmartSet(keystone.backends.api.TOKEN,
                                  'get', self._fake_token_get)

            self.stubout.SmartSet(keystone.backends.api.BaseTenantAPI,
                                  'get_all_endpoints',
                                  self._fake_tenant_get_all_endpoints)

            auth_data = self.identity.get_endpoints_for_token("admin token",
                                                              "token id")
            self.assertEquals(auth_data.base_urls[0].service, 'foo')
            self.assertEquals(len(auth_data.base_urls), 1)

        def test_endpoints_from_bad_token(self):
            self.stubout.SmartSet(keystone.backends.api.TOKEN,
                                  'get', self._fake_missing_token_get)

            self.assertRaises(fault.ItemNotFoundFault,
                              self.identity.get_endpoints_for_token,
                              "admin token", "token id")

        def test_bad_endpoints(self):
            self.stubout.SmartSet(keystone.backends.api.TOKEN,
                                  'get', self._fake_token_get)

            self.stubout.SmartSet(keystone.backends.api.TENANT,
                'get_all_endpoints',
                self._fake_exploding_tenant_get_all_endpoints)

            endpoints = self.identity.get_endpoints_for_token("admin token",
                                                              "token id")
            self.assertEquals(endpoints.base_urls, [])


if __name__ == '__main__':
    unittest.main()
