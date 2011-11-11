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


class AuthenticationTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(AuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        self.services = self.create_service().json['OS-KSADM:service']
        self.endpoint_templates = self.create_endpoint_template(
            name=self.services['name'], \
            type=self.services['type']).\
            json['OS-KSCATALOG:endpointTemplate']
        self.create_endpoint_for_tenant(self.tenant['id'],
        self.endpoint_templates['id'])

    def test_authenticate_for_a_tenant(self):
        r = self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200)

        self.assertIsNotNone(r.json['access']['token'])
        service_catalog = r.json['access']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_for_a_tenant_on_admin_api(self):
        r = self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200, request_type='admin')

        self.assertIsNotNone(r.json['access']['token'])
        self.assertIsNotNone(r.json['access']['serviceCatalog'])
        service_catalog = r.json['access']['serviceCatalog']
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml_on_admin_api(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200,
                request_type='admin')

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_user_disabled(self):
        self.disable_user(self.user['id'])
        self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=403)

    def test_authenticate_user_wrong(self):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username-field-completely-wrong": self.user['name'],
                    "password": self.user['password']},
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


class AuthenticationUsingTokenTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(AuthenticationUsingTokenTest, self).setUp(*args, **kwargs)
        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])
            self.token = self.authenticate(self.user['name'],
                self.user['password']).json['access']['token']['id']

    def test_authenticate_for_a_tenant_using_token(self):
        r = self.authenticate_using_token(self.token,
            self.tenant['id'], assert_status=200)

        self.assertIsNotNone(r.json['access']['token'])
        service_catalog = r.json['access']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<token id="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.token)
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_for_a_tenant_on_admin_api(self):
        r = self.authenticate_using_token(self.token,
            self.tenant['id'], request_type='admin')

        self.assertIsNotNone(r.json['access']['token'])
        self.assertIsNotNone(r.json['access']['serviceCatalog'])
        service_catalog = r.json['access']['serviceCatalog']
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml_on_admin_api(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<token id="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.token)
        r = self.post_token(as_xml=data, assert_status=200,
                request_type='admin')

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)


class UnScopedAuthenticationTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(UnScopedAuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

    def test_authenticate(self):
        r = self.authenticate(self.user['name'], self.user['password'],\
            assert_status=200)

        self.assertIsNotNone(r.json['access']['token'])
        service_catalog = r.json['access']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" >'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.user['name'],
            self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)

    def test_authenticate_on_admin_api(self):
        r = self.authenticate(self.user['name'], self.user['password'],
            assert_status=200, request_type='admin')

        self.assertIsNotNone(r.json['access']['token'])
        self.assertIsNotNone(r.json['access']['serviceCatalog'])
        service_catalog = r.json['access']['serviceCatalog']
        self.check_urls_for_regular_user(service_catalog)

    def test_authenticate_for_a_tenant_xml_on_admin_api(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data,
            assert_status=200, request_type='admin')

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_regular_user_xml(service_catalog)


class AdminUserAuthenticationTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(AdminUserAuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.role = self.get_role_by_name('Admin').json['role']
        self.grant_global_role_to_user(self.user['id'], self.role['id'])
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

    def test_authenticate(self):
        r = self.authenticate(self.user['name'], self.user['password'],\
            assert_status=200)

        self.assertIsNotNone(r.json['access']['token'])
        service_catalog = r.json['access']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_admin_user(service_catalog)

    def test_authenticate_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" >'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.user['name'],
            self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_admin_user_xml(service_catalog)

    def test_authenticate_for_a_tenant(self):
        r = self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200)

        self.assertIsNotNone(r.json['access']['token'])
        service_catalog = r.json['access']['serviceCatalog']
        self.assertIsNotNone(service_catalog)
        self.check_urls_for_admin_user(service_catalog)

    def test_authenticate_for_a_tenant_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<auth xmlns="%s" tenantId="%s">'
            '<passwordCredentials username="%s" password="%s" '
            '/> </auth>') % (
            self.xmlns, self.tenant['id'],
            self.user['name'], self.user['password'])
        r = self.post_token(as_xml=data, assert_status=200)

        self.assertEquals(r.xml.tag, '{%s}access' % self.xmlns)
        service_catalog = r.xml.find('{%s}serviceCatalog' % self.xmlns)
        self.check_urls_for_admin_user_xml(service_catalog)


class LegacyAuthenticationTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(LegacyAuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

    def test_authenticate_legacy(self):
        r = self.service_request(version='1.0', assert_status=204, headers={
            "X-Auth-User": self.user['name'],
            "X-Auth-Key": self.user['password']})

        self.assertIsNotNone(r.getheader('x-auth-token'))
        for service in self.services.values():
            self.assertIsNotNone(r.getheader('x-' + service['name']))


class MultiTokenTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(MultiTokenTest, self).setUp(*args, **kwargs)

        self.tenants = {}
        self.users = {}
        for x in range(0, 2):
            self.tenants[x] = self.create_tenant().json['tenant']

            password = common.unique_str()
            self.users[x] = self.create_user(user_password=password,
                tenant_id=self.tenants[x]['id']).json['user']
            self.users[x]['password'] = password

    def test_unassigned_user(self):
        self.authenticate(self.users[1]['name'], self.users[1]['password'],
            self.tenants[0]['id'], assert_status=401)


if __name__ == '__main__':
    unittest.main()
