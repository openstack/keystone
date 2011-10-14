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


class TenantTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(TenantTest, self).setUp(*args, **kwargs)

    def tearDown(self, *args, **kwargs):
        super(TenantTest, self).tearDown(*args, **kwargs)


class CreateTenantTest(TenantTest):

    def test_create_tenant(self):
        self.create_tenant(assert_status=201)

    def test_create_tenant_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true" name="%s"> '
            '<description>A description...</description> '
            '</tenant>') % (common.unique_str(),)
        self.post_tenant(as_xml=data, assert_status=201, headers={
            'Accept': 'application/xml'})

    def test_create_tenant_again(self):
        tenant = self.create_tenant().json['tenant']
        self.create_tenant(tenant_name=tenant['name'], assert_status=409)

    def test_create_tenant_again_xml(self):
        tenant = self.create_tenant().json['tenant']

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true" id="%s"> '
            '<description>A description...</description> '
            '</tenant>') % (tenant['name'],)

        self.create_tenant(tenant_name=tenant['name'], as_xml=data,
            assert_status=409)

    def test_create_tenant_expired_token(self):
        self.admin_token = self.expired_admin_token
        self.create_tenant(assert_status=403)

    def test_create_tenant_expired_token_xml(self):
        self.admin_token = self.expired_admin_token
        data = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
            enabled="true" name="%s"> \
            <description>A description...</description> \
            </tenant>' % (common.unique_str())

        self.post_tenant(as_xml=data, assert_status=403)

    def test_create_tenant_missing_token(self):
        self.admin_token = ''
        self.create_tenant(assert_status=401)

    def test_create_tenant_missing_token_xml(self):
        self.admin_token = ''
        data = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
            enabled="true" name="%s"> \
            <description>A description...</description> \
            </tenant>' % (common.unique_str())

        self.post_tenant(as_xml=data, assert_status=401)

    def test_create_tenant_disabled_token(self):
        self.admin_token = self.disabled_admin_token
        self.create_tenant(assert_status=403)

    def test_create_tenant_disabled_token_xml(self):
        self.admin_token = self.disabled_admin_token
        data = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
            enabled="true" name="%s"> \
            <description>A description...</description> \
            </tenant>' % (common.unique_str())

        self.post_tenant(as_xml=data, assert_status=403)

    def test_create_tenant_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_tenant(assert_status=401)

    def test_create_tenant_invalid_token_xml(self):
        self.admin_token = common.unique_str()
        data = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
            enabled="true" name="%s"> \
            <description>A description...</description> \
            </tenant>' % (common.unique_str())

        self.post_tenant(as_xml=data, assert_status=401)


class GetTenantsTest(TenantTest):

    def test_get_tenants_using_admin_token(self):
        self.list_tenants(assert_status=200)

    def test_get_tenants_using_admin_token_xml(self):
        self.get_tenants(assert_status=200, headers={
            'Accept': 'application/xml'})

    def test_get_tenants_using_admin_token_xml_on_service_api(self):
        self.get_tenants(assert_status=200, headers={
            'Accept': 'application/xml'}, request_type='service')

    def test_get_tenants_using_user_token(self):
        tenant = self.create_tenant().json['tenant']
        user = self.create_user_with_known_password(tenant_id=tenant['id']).\
            json['user']
        token = self.authenticate(user['name'], user['password'],
            tenant['id']).json['access']['token']
        self.service_token = token['id']
        tenants = self.service_request(method='GET', path='/tenants',
            assert_status=200).json['tenants']['values']
        self.assertTrue(len(tenants) == 1)
        self.assertIn(tenant['id'], [tenant['id'] for tenant in tenants])

    def test_get_tenants_using_user_token_xml(self):
        tenant = self.create_tenant().json['tenant']
        user = self.create_user_with_known_password(tenant_id=tenant['id']).\
            json['user']
        token = self.authenticate(user['name'], user['password'],
            tenant['id']).json['access']['token']
        self.service_token = token['id']

        r = self.service_request(method='GET', path='/tenants',
            assert_status=200, headers={'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag, '{%s}tenants' % self.xmlns)
        xml_tenant = r.xml.find('{%s}tenant' % self.xmlns)
        self.assertEqual(tenant['id'], xml_tenant.get('id'))

    def test_get_tenants_exp_token(self):
        self.admin_token = self.expired_admin_token
        self.list_tenants(assert_status=403)

    def test_get_tenants_exp_token_xml(self):
        self.admin_token = self.expired_admin_token
        self.get_tenants(assert_status=403, headers={
            'Accept': 'application/xml'})


class GetTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(TenantTest, self).setUp(*args, **kwargs)

        self.tenant = self.create_tenant().json['tenant']

    def test_get_tenant(self):
        self.fetch_tenant(self.tenant['id'], assert_status=200)

    def test_get_tenant_xml(self):
        self.fetch_tenant(self.tenant['id'], assert_status=200, headers={
            "Accept": "application/xml"})

    def test_get_tenant_not_found(self):
        self.fetch_tenant(assert_status=404)

    def test_get_tenant_not_found_xml(self):
        self.get_tenant(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


class UpdateTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(UpdateTenantTest, self).setUp(*args, **kwargs)
        self.tenant = self.create_tenant().json['tenant']

    def test_update_tenant(self):
        new_description = common.unique_str()
        updated_tenant = self.update_tenant(self.tenant['id'],
            tenant_description=new_description, assert_status=200).\
            json['tenant']
        self.assertEqual(updated_tenant['description'], new_description)

    def test_update_tenant_xml(self):
        new_description = common.unique_str()

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
             '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
             'enabled="false"> '
             '<description>%s</description> '
             '</tenant>') % (new_description,)
        r = self.put_tenant(self.tenant['id'], as_xml=data, assert_status=200)

        self.assertEqual(r.xml.tag, "{%s}tenant" % self.xmlns)

        description = r.xml.find("{%s}description" % self.xmlns)
        self.assertEqual(description.text, new_description)
        self.assertEqual(r.xml.get('id'), self.tenant['id'])
        self.assertEqual(r.xml.get('enabled'), 'false')

    def test_update_tenant_bad(self):
        data = '{"tenant": { "description_bad": "A NEW description...",\
                "enabled":true  }}'
        self.put_tenant(self.tenant['id'], as_json=data, assert_status=400)

    def test_update_tenant_bad_xml(self):
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
             enabled="true"> \
             <description_bad>A NEW description...</description> \
             </tenant>'
        self.put_tenant(self.tenant['id'], as_xml=data, assert_status=400)

    def test_update_tenant_not_found(self):
        self.update_tenant(assert_status=404)

    def test_update_tenant_not_found_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true"> '
            '<description>A NEW description...</description> '
            '</tenant>')
        self.put_tenant(common.unique_str(), as_xml=data, assert_status=404)


class DeleteTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(TenantTest, self).setUp(*args, **kwargs)

        self.tenant = self.create_tenant().json['tenant']

    def test_delete_tenant(self):
        self.remove_tenant(self.tenant['id'], assert_status=204)

    def test_delete_tenant_xml(self):
        self.delete_tenant(self.tenant['id'], assert_status=204, headers={
            'Accept': 'application/xml'})

    def test_delete_tenant_not_found(self):
        self.remove_tenant(common.unique_str(), assert_status=404)

    def test_delete_tenant_not_found_xml(self):
        self.delete_tenant(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


if __name__ == '__main__':
    unittest.main()
