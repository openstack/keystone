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


class EndpointTemplatesTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(EndpointTemplatesTest, self).setUp(*args, **kwargs)

        self.service = self.create_service().json['OS-KSADM:service']

        self.endpoint_template = self.create_endpoint_template(
            name=self.service['name'], \
            type=self.service['type']).\
            json['OS-KSCATALOG:endpointTemplate']

        admin_token = self.admin_token
        self.admin_token = self.service_admin_token
        self.my_service = self.create_service().json['OS-KSADM:service']
        self.admin_token = admin_token


class CreateEndpointTemplatesTest(EndpointTemplatesTest):
    def test_create_endpoint_template(self):
        endpoint_template = self.create_endpoint_template(
            name=self.service['name'],
            type=self.service['type'],
            assert_status=201).\
            json['OS-KSCATALOG:endpointTemplate']

        self.assertIsNotNone(endpoint_template['id'], endpoint_template)
        self.assertIsNotNone(endpoint_template['name'], endpoint_template)
        self.assertIsNotNone(endpoint_template['type'], endpoint_template)

    def test_create_endpoint_template_with_empty_name(self):
        self.create_endpoint_template(
            name=self.service['name'],
            type='',
            assert_status=400)

    def test_create_endpoint_template_with_empty_type(self):
        self.create_endpoint_template(
            name='',
            type=self.service['type'],
            assert_status=400)

    def test_create_endpoint_template_xml(self):
        region = common.unique_str()
        public_url = common.unique_url()
        admin_url = common.unique_url()
        internal_url = common.unique_url()
        enabled = True
        is_global = True

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate xmlns="%s" region="%s" name="%s" '
            'type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>'
            ) % (self.xmlns_kscatalog, region, self.service['name'],
                self.service['type'], public_url, admin_url, internal_url,
                enabled, is_global)
        r = self.post_endpoint_template(as_xml=data, assert_status=201)

        self.assertEqual(r.xml.tag,
            '{%s}endpointTemplate' % self.xmlns_kscatalog)

        self.assertIsNotNone(r.xml.get("id"))
        self.assertEqual(r.xml.get("name"), self.service['name'])
        self.assertEqual(r.xml.get("type"), self.service['type'])
        self.assertEqual(r.xml.get("region"), region)
        self.assertEqual(r.xml.get("publicURL"), public_url)
        self.assertEqual(r.xml.get("adminURL"), admin_url)
        self.assertEqual(r.xml.get("internalURL"), internal_url)
        self.assertEqual(r.xml.get("enabled"), str(enabled).lower())
        self.assertEqual(r.xml.get("global"), str(is_global).lower())

    def test_create_endpoint_template_xml_using_empty_type(self):
        region = common.unique_str()
        public_url = common.unique_url()
        admin_url = common.unique_url()
        internal_url = common.unique_url()
        enabled = True
        is_global = True

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate xmlns="%s" region="%s" name="%s" '
            'type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>'
            ) % (self.xmlns_kscatalog, region, self.service['name'],
                '', public_url, admin_url, internal_url,
                enabled, is_global)
        self.post_endpoint_template(as_xml=data, assert_status=400)

    def test_create_endpoint_template_xml_using_empty_name(self):
        region = common.unique_str()
        public_url = common.unique_url()
        admin_url = common.unique_url()
        internal_url = common.unique_url()
        enabled = True
        is_global = True

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate xmlns="%s" region="%s" name="%s" '
            'type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>'
            ) % (self.xmlns_kscatalog, region, '',
                self.service['type'], public_url, admin_url, internal_url,
                enabled, is_global)
        self.post_endpoint_template(as_xml=data, assert_status=400)

    def test_delete_endpoint_template_that_has_dependencies(self):
        tenant = self.create_tenant().json['tenant']

        self.create_endpoint_for_tenant(tenant['id'],
            self.endpoint_template['id'], assert_status=201)

        self.remove_endpoint_template(self.endpoint_template['id'],
            assert_status=204)

    def test_create_endpoint_template_using_service_admin_token(self):
        self.admin_token = self.service_admin_token
        endpoint_template = self.create_endpoint_template(
            name=self.my_service['name'],
            type=self.my_service['type'],
            assert_status=201).\
            json['OS-KSCATALOG:endpointTemplate']

        self.assertIsNotNone(endpoint_template['id'])
        self.assertEqual(endpoint_template['name'], self.my_service['name'])
        self.assertEqual(endpoint_template['type'], self.my_service['type'])


class GetEndpointTemplatesTest(EndpointTemplatesTest):
    def test_get_endpoint_templates(self):
        r = self.list_endpoint_templates(assert_status=200)
        self.assertIsNotNone(r.json['OS-KSCATALOG:endpointTemplates'])

    def test_get_endpoint_templates_using_service_admin_token(self):
        self.admin_token = self.service_admin_token
        r = self.list_endpoint_templates(assert_status=200)
        self.assertIsNotNone(r.json['OS-KSCATALOG:endpointTemplates'])

    def test_get_endpoint_templates_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.list_endpoint_templates(assert_status=403)

    def test_get_endpoint_templates_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.list_endpoint_templates(assert_status=403)

    def test_get_endpoint_templates_using_missing_auth_token(self):
        self.admin_token = ''
        self.list_endpoint_templates(assert_status=401)

    def test_get_endpoint_templates_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.list_endpoint_templates(assert_status=401)

    def test_get_endpoint_templates_xml(self):
        r = self.get_endpoint_templates(assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag,
            "{%s}endpointTemplates" % self.xmlns_kscatalog)

    def test_get_endpoint_templates_xml_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_endpoint_templates(assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_endpoint_templates(assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_missing_auth_token(self):
        self.admin_token = ''
        self.get_endpoint_templates(assert_status=401, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_endpoint_templates(assert_status=401, headers={
            'Accept': 'application/xml'})


class GetEndpointTemplatesByServiceTest(EndpointTemplatesTest):
    def test_get_endpoint_templates(self):
        r = self.list_endpoint_templates(
            service_id=self.service['id'], assert_status=200)
        self.assertIsNotNone(r.json['OS-KSCATALOG:endpointTemplates'])
        self.assertEquals(len(r.json['OS-KSCATALOG:endpointTemplates']), 1)
        self.assertEquals(r.json['OS-KSCATALOG:endpointTemplates'][0]['name'],
            self.service['name'])
        self.assertEquals(r.json['OS-KSCATALOG:endpointTemplates'][0]['type'],
            self.service['type'])

    def test_get_endpoint_templates_using_service_admin_token(self):
        self.admin_token = self.service_admin_token
        r = self.list_endpoint_templates(service_id=self.service['id'],
            assert_status=200)
        self.assertIsNotNone(r.json['OS-KSCATALOG:endpointTemplates'])
        self.assertEquals(len(r.json['OS-KSCATALOG:endpointTemplates']), 1)
        self.assertEquals(r.json['OS-KSCATALOG:endpointTemplates'][0]['name'],
            self.service['name'])
        self.assertEquals(
            r.json['OS-KSCATALOG:endpointTemplates'][0]['type'],
            self.service['type'])

    def test_get_endpoint_templates_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.list_endpoint_templates(
            service_id=self.service['id'], assert_status=403)

    def test_get_endpoint_templates_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.list_endpoint_templates(
            service_id=self.service['id'], assert_status=403)

    def test_get_endpoint_templates_using_missing_auth_token(self):
        self.admin_token = ''
        self.list_endpoint_templates(service_id=self.service['id'],
            assert_status=401)

    def test_get_endpoint_templates_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.list_endpoint_templates(service_id=self.service['id'],
            assert_status=401)

    def test_get_endpoint_templates_xml(self):
        r = self.get_endpoint_templates_by_service(
            service_id=self.service['id'],
            assert_status=200, headers={'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag,
            "{%s}endpointTemplates" % self.xmlns_kscatalog)
        endpoint_template = r.xml.find(
            '{%s}endpointTemplate' % self.xmlns_kscatalog)
        self.assertIsNotNone(endpoint_template)
        self.assertEqual(endpoint_template.get('name'), self.service['name'])
        self.assertEqual(endpoint_template.get('type'), self.service['type'])

    def test_get_endpoint_templates_xml_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_endpoint_templates_by_service(
            service_id=self.service['id'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_endpoint_templates_by_service(
            service_id=self.service['id'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_missing_auth_token(self):
        self.admin_token = ''
        self.get_endpoint_templates_by_service(
            service_id=self.service['id'], assert_status=401, headers={
            'Accept': 'application/xml'})

    def test_get_endpoint_templates_xml_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_endpoint_templates_by_service(
            service_id=self.service['id'], assert_status=401, headers={
            'Accept': 'application/xml'})


class GetEndpointTemplateTest(EndpointTemplatesTest):
    def test_get_endpoint(self):
        r = self.fetch_endpoint_template(self.endpoint_template['id'])
        self.assertIsNotNone(r.json['OS-KSCATALOG:endpointTemplate'])

#    def test_get_endpoint_using_service_admin_token(self):
#        self.admin_token = service_admin_token
#        r = self.fetch_endpoint_template(self.endpoint_template['id'])
#        self.assertIsNotNone(r.json['endpointTemplate'])

    def test_get_endpoint_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.fetch_endpoint_template(self.endpoint_template['id'],
            assert_status=403)

    def test_get_endpoint_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.fetch_endpoint_template(self.endpoint_template['id'],
            assert_status=403)

    def test_get_endpoint_using_missing_auth_token(self):
        self.admin_token = ''
        self.fetch_endpoint_template(self.endpoint_template['id'],
            assert_status=401)

    def test_get_endpoint_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.fetch_endpoint_template(self.endpoint_template['id'],
            assert_status=401)

    def test_get_endpoint_xml(self):
        r = self.get_endpoint_template(self.endpoint_template['id'],
            headers={'Accept': 'application/xml'}, assert_status=200)

        self.assertEqual(r.xml.tag,
            "{%s}endpointTemplate" % self.xmlns_kscatalog)

    def test_non_existent_get_endpoint(self):
        self.fetch_endpoint_template('99999999',
            assert_status=404)


class UpdateEndpointTemplateTest(EndpointTemplatesTest):
    def test_update_endpoint(self):
        self.update_endpoint_template(self.endpoint_template['id'],
            name=self.service['name'], type=self.service['type'],
            assert_status=201)
#       self.assertIsNotNone(r.json['endpointTemplate'].get('enabled'), r.json)

    def test_update_endpoint_with_empty_name(self):
        self.update_endpoint_template(self.endpoint_template['id'],
            name='', type=self.service['type'],
            assert_status=400)

    def test_update_endpoint_with_empty_type(self):
        self.update_endpoint_template(self.endpoint_template['id'],
            name=self.service['name'], type='',
            assert_status=400)

    def test_update_endpoint_xml(self):
        region = common.unique_str()
        public_url = common.unique_url()
        admin_url = common.unique_url()
        internal_url = common.unique_url()
        enabled = True
        is_global = True

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" '
            'region="%s" name="%s" type="%s"'
            ' publicURL="%s" adminURL="%s"'
            ' internalURL="%s" enabled="%s" global="%s"/>') % (
                self.xmlns_kscatalog, region,
                self.service['name'], self.service['type'],
                public_url, admin_url, internal_url,
                enabled, is_global)
        r = self.put_endpoint_template(self.endpoint_template['id'],
            as_xml=data, assert_status=201, headers={
                'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag,
            '{%s}endpointTemplate' % self.xmlns_kscatalog)

        self.assertIsNotNone(r.xml.get("id"))
        self.assertEqual(r.xml.get("name"), self.service['name'])
        self.assertEqual(r.xml.get("type"), self.service['type'])
        self.assertEqual(r.xml.get("region"), region)
        self.assertEqual(r.xml.get("publicURL"), public_url)
        self.assertEqual(r.xml.get("adminURL"), admin_url)
        self.assertEqual(r.xml.get("internalURL"), internal_url)
        self.assertEqual(r.xml.get("enabled"), str(enabled).lower())
        self.assertEqual(r.xml.get("global"), str(is_global).lower())

#    def test_update_endpoint_using_service_admin_token(self):
#        self.admin_token = service_admin_token
#        region = common.unique_str()
#        public_url = common.unique_url()
#        admin_url = common.unique_url()
#        internal_url = common.unique_url()
#        enabled = True
#        is_global = True
#
#        r = self.update_endpoint_template(self.endpoint_template['id'],
#            region, self.service['id'], public_url, admin_url, internal_url,
#            enabled, is_global, assert_status=201)
#
#        endpoint_template = r.json.get('endpointTemplate')
#
#        self.assertIsNotNone(endpoint_template.get("id"), r.json)
#        self.assertEqual(endpoint_template.get("serviceId"),
#            self.service['id'])
#        self.assertEqual(endpoint_template.get("region"), region)
#        self.assertEqual(endpoint_template.get("publicURL"), public_url)
#        self.assertEqual(endpoint_template.get("adminURL"), admin_url)
#        self.assertEqual(endpoint_template.get("internalURL"), internal_url)
#        self.assertEqual(endpoint_template.get("enabled"),
#            str(enabled).lower())
#        self.assertEqual(endpoint_template.get("global"),
#            str(is_global).lower())

#    def test_update_endpoint_xml_using_service_admin_token(self):
#        self.admin_token = service_admin_token
#
#        self.test_update_endpoint_xml()

    def test_update_endpoint_template_with_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.update_endpoint_template(self.endpoint_template['id'],
            assert_status=403)

    def test_update_endpoint_template_with_missing_token(self):
        self.admin_token = ''
        self.update_endpoint_template(self.endpoint_template['id'],
            assert_status=401)

    def test_update_endpoint_template_with_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.update_endpoint_template(self.endpoint_template['id'],
            assert_status=403)

    def test_update_endpoint_template_with_invalid_token(self):
        self.admin_token = common.unique_str()
        self.update_endpoint_template(self.endpoint_template['id'],
            assert_status=401)

    def test_update_invalid_endpoint_template(self):
        self.update_endpoint_template(assert_status=404)


class CreateEndpointRefsTest(EndpointTemplatesTest):

    def setUp(self, *args, **kwargs):
        super(CreateEndpointRefsTest, self).setUp(*args, **kwargs)
        self.tenant = self.create_tenant().json['tenant']

    def test_endpoint_create_json_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'], assert_status=403)

    def test_endpoint_create_json_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'], assert_status=403)

    def test_endpoint_create_json_using_missing_token(self):
        self.admin_token = ''
        self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'], assert_status=401)

    def test_endpoint_create_json_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'], assert_status=401)

    def test_endpoint_create_json(self):
        endpoint = self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'], assert_status=201).json['endpoint']
        self.assertEqual(str(endpoint["name"]), str(self.service['name']))
        self.assertEqual(str(endpoint["type"]), str(self.service['type']))
        self.assertEqual(endpoint["region"], self.endpoint_template["region"])
        self.assertEqual(endpoint["publicURL"],
            self.endpoint_template["publicURL"])
        self.assertEqual(endpoint["adminURL"],
            self.endpoint_template["adminURL"])
        self.assertEqual(endpoint["internalURL"],
            self.endpoint_template["internalURL"])

#    def test_endpoint_create_using_service_admin_token(self):
#        self.admin_token = service_admin_token
#        self.create_endpoint_template(assert_status=201)

    def test_endpoint_create_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" id="%s">'
            '</endpointTemplate>') % (self.xmlns_kscatalog,
            self.endpoint_template["id"])
        r = self.post_tenant_endpoint(self.tenant['id'],
            as_xml=data, assert_status=201,
            headers={'Accept': 'application/xml'})

        self.assertEqual(r.xml.tag,
            '{%s}endpoint' % self.xmlns)

        self.assertIsNotNone(r.xml.get("id"))
        self.assertEqual(r.xml.get("name"), self.service['name'])
        self.assertEqual(r.xml.get("type"), self.service['type'])
        self.assertEqual(r.xml.get("region"), self.endpoint_template["region"])
        self.assertEqual(r.xml.get("publicURL"),
            self.endpoint_template["publicURL"])
        self.assertEqual(r.xml.get("adminURL"),
            self.endpoint_template["adminURL"])
        self.assertEqual(r.xml.get("internalURL"),
            self.endpoint_template["internalURL"])

    def test_endpoint_create_xml_using_expired_token(self):
        self.admin_token = self.expired_admin_token
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" '
            'region="%s" name="%s"'
            ' type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>') % (
                self.xmlns_kscatalog,
                common.unique_str(),
                self.service['name'],
                self.service['type'], common.unique_url(),
                common.unique_url(), common.unique_url(), True, True)
        self.post_endpoint_template(as_xml=data, assert_status=403, headers={
                'Accept': 'application/xml'})

    def test_endpoint_create_xml_using_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" '
            'region="%s" name="%s" type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>') % (
                self.xmlns_kscatalog, common.unique_str(),
                self.service['name'],
                self.service['type'], common.unique_url(),
                common.unique_url(), common.unique_url(), True, True)
        self.post_endpoint_template(as_xml=data, assert_status=403, headers={
                'Accept': 'application/xml'})

    def test_endpoint_create_xml_using_missing_token(self):
        self.admin_token = ''
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" '
            'region="%s" name="%s" type="%s"  publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>') % (
                self.xmlns_kscatalog,
                common.unique_str(),
                self.service['name'], self.service['type'],
                common.unique_url(),
                common.unique_url(), common.unique_url(), True, True)
        self.post_endpoint_template(as_xml=data, assert_status=401, headers={
                'Accept': 'application/xml'})

    def test_endpoint_create_xml_using_invalid_token(self):
        self.admin_token = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<endpointTemplate '
            'xmlns="%s" '
            'region="%s" name="%s" type="%s" publicURL="%s" adminURL="%s" '
            'internalURL="%s" enabled="%s" global="%s"/>') % (
                self.xmlns_kscatalog, common.unique_str(),
                self.service['name'],
                self.service['type'], common.unique_url(),
                common.unique_url(), common.unique_url(), True, True)
        self.post_endpoint_template(as_xml=data, assert_status=401, headers={
                'Accept': 'application/xml'})


class GetEndPointTest(EndpointTemplatesTest):
    def setUp(self, *args, **kwargs):
        super(GetEndPointTest, self).setUp(*args, **kwargs)

        self.tenant = self.create_tenant().json['tenant']

    def test_get_tenant_endpoint_xml(self):
        self.get_tenant_endpoints(self.tenant['id'], assert_status=200,
            headers={"Accept": "application/xml"})

    def test_get_tenant_endpoint_xml_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_tenant_endpoints(self.tenant['id'], assert_status=403,
            headers={"Accept": "application/xml"})

    def test_get_tenant_endpoint_xml_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_tenant_endpoints(self.tenant['id'], assert_status=403,
            headers={"Accept": "application/xml"})

    def test_get_tenant_endpoint_xml_using_missing_auth_token(self):
        self.admin_token = ''
        self.get_tenant_endpoints(self.tenant['id'], assert_status=401,
            headers={"Accept": "application/xml"})

    def test_get_tenant_endpoint_xml_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_tenant_endpoints(self.tenant['id'], assert_status=401,
            headers={"Accept": "application/xml"})

    def test_get_tenant_endpoint_json(self):
        r = self.get_tenant_endpoints(self.tenant['id'], assert_status=200)
        self.assertIsNotNone(r.json.get('endpoints'), r.json)

    def test_get_tenant_endpoint_json_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_tenant_endpoints(self.tenant['id'], assert_status=403)

    def test_get_endpoint_json_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_tenant_endpoints(self.tenant['id'], assert_status=403)

    def test_get_endpoint_json_using_missing_auth_token(self):
        self.admin_token = ''
        self.get_tenant_endpoints(self.tenant['id'], assert_status=401)

    def test_get_endpoint_json_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_tenant_endpoints(self.tenant['id'], assert_status=401)


class DeleteEndpointsTest(EndpointTemplatesTest):
    def setUp(self, *args, **kwargs):
        super(DeleteEndpointsTest, self).setUp(*args, **kwargs)

        self.tenant = self.create_tenant().json['tenant']
        self.create_endpoint_for_tenant(self.tenant['id'],
            self.endpoint_template['id'])

    def test_delete_endpoint(self):
        self.delete_tenant_endpoint(self.tenant['id'],
            self.endpoint_template['id'], assert_status=204)

    def test_delete_endpoint_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.delete_tenant_endpoint(self.tenant['id'],
            self.endpoint_template['id'], assert_status=403)

    def test_delete_endpoint_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.delete_tenant_endpoint(self.tenant['id'],
            self.endpoint_template['id'], assert_status=403)

    def test_delete_endpoint_using_missing_auth_token(self):
        self.admin_token = ''
        self.delete_tenant_endpoint(self.tenant['id'],
            self.endpoint_template['id'], assert_status=401)

    def test_delete_endpoint_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.delete_tenant_endpoint(self.tenant['id'],
            self.endpoint_template['id'], assert_status=401)


class GetEndPointsForTokenTest(EndpointTemplatesTest):
    def setUp(self, *args, **kwargs):
        super(GetEndPointsForTokenTest, self).setUp(*args, **kwargs)
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
        r = self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200)
        self.token = r.json['access']['token']['id']

    def test_get_token_endpoints_xml(self):
        self.get_token_endpoints(self.token, assert_status=200,
            headers={"Accept": "application/xml"})

    def test_get_token_endpoints_xml_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_token_endpoints(self.token, assert_status=403,
            headers={"Accept": "application/xml"})

    def test_get_token_endpoints_xml_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_token_endpoints(self.token, assert_status=403,
            headers={"Accept": "application/xml"})

    def test_get_token_endpoints_xml_using_missing_auth_token(self):
        self.admin_token = ''
        self.get_token_endpoints(self.token, assert_status=401,
            headers={"Accept": "application/xml"})

    def test_get_token_endpoints_xml_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_token_endpoints(self.token, assert_status=401,
            headers={"Accept": "application/xml"})

    def test_get_token_endpoints_json(self):
        r = self.get_token_endpoints(self.token, assert_status=200)
        self.assertIsNotNone(r.json.get('endpoints'), r.json)

    def test_get_token_endpoints_json_using_expired_auth_token(self):
        self.admin_token = self.expired_admin_token
        self.get_token_endpoints(self.token, assert_status=403)

    def test_get_token_endpoints_json_using_disabled_auth_token(self):
        self.admin_token = self.disabled_admin_token
        self.get_token_endpoints(self.token, assert_status=403)

    def test_get_token_endpoints_json_using_missing_auth_token(self):
        self.admin_token = ''
        self.get_token_endpoints(self.token, assert_status=401)

    def test_get_token_endpoints_json_using_invalid_auth_token(self):
        self.admin_token = common.unique_str()
        self.get_token_endpoints(self.token, assert_status=401)


if __name__ == '__main__':
    unittest.main()
