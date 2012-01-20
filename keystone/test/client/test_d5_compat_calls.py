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


class D5_AuthenticationTest(common.FunctionalTestCase):
    """ Tests the functionality of the D5 compat module """
    use_server = True

    def setUp(self, *args, **kwargs):
        super(D5_AuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        self.services = self.fixture_create_service()
        self.endpoint_templates = self.create_endpoint_template(
                name=self.services['name'],
                type=self.services['type']).\
                json['OS-KSCATALOG:endpointTemplate']
        self.create_endpoint_for_tenant(self.tenant['id'],
        self.endpoint_templates['id'])

    def test_validate_unscoped_token(self):
        """Admin should be able to validate a user's token"""
        # Authenticate as user to get a token
        self.service_token = self.post_token(as_json={
            'passwordCredentials': {
                'username': self.user['name'],
                'password': self.user['password']}}).\
            json['auth']['token']['id']

        # In the real world, the service user would then pass his/her token
        # to some service that depends on keystone, which would then need to
        # use keystone to validate the provided token.

        # Admin independently validates the user token
        r = self.get_token(self.service_token)
        self.assertEqual(r.json['auth']['token']['id'], self.service_token)
        self.assertTrue(r.json['auth']['token']['expires'])
        self.assertEqual(r.json['auth']['user']['username'],
            self.user['name'])
        self.assertEqual(r.json['auth']['user']['roleRefs'], [])

    def test_validate_scoped_token(self):
        """Admin should be able to validate a user's scoped token"""
        # Authenticate as user to get a token
        self.service_token = self.post_token(as_json={
            'passwordCredentials': {
                'tenantId': self.tenant['id'],
                'username': self.user['name'],
                'password': self.user['password']}}).\
            json['auth']['token']['id']

        # In the real world, the service user would then pass his/her token
        # to some service that depends on keystone, which would then need to
        # use keystone to validate the provided token.

        # Admin independently validates the user token
        r = self.get_token(self.service_token)
        self.assertEqual(r.json['auth']['token']['id'], self.service_token)
        self.assertEqual(r.json['auth']['token']['tenantId'],
            self.tenant['id'])
        self.assertTrue(r.json['auth']['token']['expires'])
        self.assertEqual(r.json['auth']['user']['username'],
            self.user['name'])
        self.assertEqual(r.json['auth']['user']['roleRefs'], [])

    def test_authenticate_for_a_tenant(self):
        r = self.authenticate_D5(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200)

        self.assertIsNotNone(r.json['auth']['token'])
        service_catalog = r.json['auth']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials xmlns="%s" tenantId="%s"'
            ' username="%s" password="%s" '
            '/>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}auth' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_for_a_tenant_on_admin_api(self):
        r = self.authenticate_D5(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200, request_type='admin')

        self.assertIsNotNone(r.json['auth']['token'])
        self.assertIsNotNone(r.json['auth']['serviceCatalog'])
        service_catalog = r.json['auth']['serviceCatalog']
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml_on_admin_api(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials xmlns="%s" tenantId="%s"'
            ' username="%s" password="%s" '
            '/>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200,
                request_type='admin')

        self.assertEquals(r.xml.tag, '{%s}auth' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_user_disabled(self):
        self.disable_user(self.user['id'])
        self.authenticate_D5(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=403)

    def test_authenticate_user_wrong(self):
        data = {"passwordCredentials": {
                    "username-field-completely-wrong": self.user['name'],
                    "password": self.user['password'],
                    "tenantId": self.tenant['id']}}
        self.post_token(as_json=data, assert_status=400)

    def test_authenticate_user_wrong_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<passwordCredentials '
            'xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'usernamefieldcompletelywrong="%s" '
            'password="%s" '
            'tenantId="%s"/>') % (
                self.user['name'], self.user['password'], self.tenant['id'])

        self.post_token(as_xml=data, assert_status=400)

    def check_urls_for_regular_user(self, service_catalog):
        self.assertIsNotNone(service_catalog)
        for k in service_catalog.keys():
            endpoints = service_catalog[k]
            for endpoint in endpoints:
                for key in endpoint:
                    #Checks whether adminURL is not present.
                    self.assertNotEquals(key, 'adminURL')

if __name__ == '__main__':
    unittest.main()
