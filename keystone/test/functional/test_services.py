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


class ServicesTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(ServicesTest, self).setUp(*args, **kwargs)

    def tearDown(self, *args, **kwargs):
        super(ServicesTest, self).tearDown(*args, **kwargs)


class GetServicesTest(ServicesTest):
    def test_get_services_using_keystone_admin_token_json(self):
        services = self.list_services(assert_status=200).\
            json['OS-KSADM:services']

        self.assertTrue(len(services))

    def test_get_services_using_keystone_admin_token_xml(self):
        r = self.list_services(assert_status=200, headers={
            'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag, "{%s}services" % self.xmlns_ksadm)
        services = r.xml.findall("{%s}service" % self.xmlns_ksadm)
        self.assertTrue(len(services))

    def test_get_services_using_service_admin_token(self):
        self.admin_token = self.service_admin_token
        services = self.list_services(assert_status=200).\
            json['OS-KSADM:services']

        self.assertTrue(len(services))

    def test_get_services_using_service_admin_token_xml(self):
        self.admin_token = self.service_admin_token
        r = self.get_services(assert_status=200, headers={
            'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag, "{%s}services" % self.xmlns_ksadm)
        services = r.xml.findall("{%s}service" % self.xmlns_ksadm)
        self.assertTrue(len(services))

    def test_get_services_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.list_services(assert_status=403)

    def test_get_services_using_missing_token(self):
        self.admin_token = ''
        self.list_services(assert_status=401)

    def test_get_services_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.list_services(assert_status=403)

    def test_get_services_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.list_services(assert_status=401)


class GetServiceTest(ServicesTest):
    def setUp(self, *args, **kwargs):
        super(ServicesTest, self).setUp(*args, **kwargs)

        self.service = self.create_service().json['OS-KSADM:service']

    def test_service_get_json(self):
        service = self.fetch_service(service_id=self.service['id'],
            assert_status=200).json['OS-KSADM:service']

        self.assertIsNotNone(service['id'])
        self.assertIsNotNone(service['description'])

    def test_service_get_xml(self):
        service = self.fetch_service(service_id=self.service['id'],
            assert_status=200, headers={'Accept': 'application/xml'}).xml

        self.assertEqual(service.tag, '{%s}service' % self.xmlns_ksadm)
        self.assertIsNotNone(service.get('id'))
        self.assertIsNotNone(service.get('description'))

    def test_get_service_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_service(service_id=self.service['id'], assert_status=403)

    def test_get_service_using_missing_token(self):
        self.admin_token = ''
        self.fetch_service(service_id=self.service['id'], assert_status=401)

    def test_get_service_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_service(service_id=self.service['id'], assert_status=403)

    def test_get_service_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_service(service_id=self.service['id'], assert_status=401)


class GetServiceByNameTest(ServicesTest):
    def setUp(self, *args, **kwargs):
        super(GetServiceByNameTest, self).setUp(*args, **kwargs)
        self.service = self.create_service().json['OS-KSADM:service']

    def test_service_get_json(self):
        service = self.fetch_service_by_name(service_name=self.service['name'],
            assert_status=200).json['OS-KSADM:service']

        self.assertIsNotNone(service['id'])
        self.assertIsNotNone(service['name'])
        self.assertIsNotNone(service['description'])

    def test_service_get_xml(self):
        service = self.fetch_service_by_name(service_name=self.service['name'],
            assert_status=200, headers={'Accept': 'application/xml'}).xml

        self.assertEqual(service.tag, '{%s}service' % self.xmlns_ksadm)
        self.assertIsNotNone(service.get('id'))
        self.assertIsNotNone(service.get('name'))
        self.assertIsNotNone(service.get('description'))

    def test_get_service_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_service_by_name(
            service_name=self.service['name'], assert_status=403)

    def test_get_service_using_missing_token(self):
        self.admin_token = ''
        self.fetch_service_by_name(
            service_name=self.service['name'], assert_status=401)

    def test_get_service_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_service_by_name(
            service_name=self.service['name'], assert_status=403)

    def test_get_service_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_service_by_name(
            service_name=self.service['name'], assert_status=401)


class CreateServiceTest(ServicesTest):
    def test_service_create_json(self):
        name = common.unique_str()
        type = common.unique_str()
        description = common.unique_str()

        service = self.create_service(service_name=name, service_type=type,
            service_description=description,
            assert_status=201).json['OS-KSADM:service']

        self.assertIsNotNone(service.get('id'))
        self.assertEqual(name, service.get('name'))
        self.assertEqual(type, service.get('type'))
        self.assertEqual(description, service.get('description'))

    def test_service_create_xml(self):
        name = common.unique_str()
        type = common.unique_str()
        description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<service xmlns="%s" name="%s" type="%s" description="%s"/>') % (
                self.xmlns_ksadm, name, type, description)
        r = self.post_service(as_xml=data, assert_status=201)
        self.assertEqual(r.xml.tag, "{%s}service" % self.xmlns_ksadm)
        self.assertIsNotNone(r.xml.get('id'))
        self.assertEqual(name, r.xml.get('name'))
        self.assertEqual(type, r.xml.get('type'))
        self.assertEqual(description, r.xml.get('description'))

    def test_service_create_duplicate_json(self):
        service_name = common.unique_str()
        self.create_service(service_name=service_name, assert_status=201)
        self.create_service(service_name=service_name, assert_status=409)

    def test_service_create_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.create_service(assert_status=403)

    def test_service_create_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_service(assert_status=403)

    def test_service_create_json_using_missing_token(self):
        self.admin_token = ''
        self.create_service(assert_status=401)

    def test_service_create_json_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_service(assert_status=401)

    def test_service_create_json_missing_name(self):
        self.create_service(service_name='', assert_status=400)

    def test_service_create_json_missing_type(self):
        self.create_service(service_type='', assert_status=400)

    def test_service_create_xml_using_missing_name(self):
        name = ''
        type = common.unique_str()
        description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<service xmlns="%s" name="%s" type="%s" description="%s"/>') % (
                self.xmlns_ksadm, name, type, description)
        self.post_service(as_xml=data, assert_status=400)

    def test_service_create_xml_using_empty_type(self):
        name = common.unique_str()
        type = ''
        description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<service xmlns="%s" name="%s" type="%s" description="%s"/>') % (
                self.xmlns_ksadm, name, type, description)
        self.post_service(as_xml=data, assert_status=400)


class DeleteServiceTest(ServicesTest):
    def setUp(self, *args, **kwargs):
        super(DeleteServiceTest, self).setUp(*args, **kwargs)

        self.service = self.create_service().json['OS-KSADM:service']

    def test_service_delete(self):
        self.remove_service(self.service['id'], assert_status=204)
        self.get_service(self.service['id'], assert_status=404)

    def test_delete_service_with_dependencies(self):
        role_id = self.service['name'] + ':' + common.unique_str()
        role = self.create_role(role_id, service_id=self.service['id'],
            assert_status=201).json['role']

        tenant = self.create_tenant().json['tenant']
        user = self.create_user(tenant_id=tenant['id']).json['user']

        self.grant_role_to_user(user['id'], role['id'], tenant['id'])
        self.create_endpoint_template(name=self.service['name'],
            type=self.service['type'])
        self.remove_service(self.service['id'], assert_status=204)

    def test_service_delete_json_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.remove_service(self.service['id'], assert_status=403)

    def test_service_delete_json_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.remove_service(self.service['id'], assert_status=403)

    def test_service_delete_json_using_missing_token(self):
        self.admin_token = ''
        self.remove_service(self.service['id'], assert_status=401)

    def test_service_delete_json_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.remove_service(self.service['id'], assert_status=401)


if __name__ == '__main__':
    unittest.main()
