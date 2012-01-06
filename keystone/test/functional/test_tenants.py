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
    def _assertValidTenant(self, tenant):
        self.assertIsNotNone(tenant.get('id'))
        self.assertIsNotNone(tenant.get('name'))
        self.assertIsNotNone(tenant.get('enabled'))
        self.assertRaises(ValueError, int, tenant.get('id'))
        self.assertTrue(0 < len(tenant.get('id')) < 256,
                        "ID must be between 1 and 255 characters long")
        self.assertFalse('/' in tenant.get('id'),
                        "ID cannot contain / character")

    def _assertValidJsonTenant(self, tenant):
        self._assertValidTenant(tenant)
        # TODO(dolph): this is still a valid assertion in some cases
        # self.assertIsNotNone(tenant.get('description'))
        self.assertIn(tenant.get('enabled'), [True, False], tenant)

    def _assertValidXmlTenant(self, xml):
        self.assertEquals(xml.tag, '{%s}tenant' % self.xmlns)
        self._assertValidTenant(xml)
        # TODO(zns): this is still a valid assertion in some cases
        # description = xml.find('{%s}description' % self.xmlns)
        # self.assertIsNotNone(description)
        self.assertIn(xml.get('enabled'), ['true', 'false'])
        return xml

    def assertValidJsonTenantResponse(self, response):
        tenant = response.json.get('tenant')
        self._assertValidJsonTenant(tenant)
        return tenant

    def assertValidXmlTenantResponse(self, response):
        return self._assertValidXmlTenant(response.xml)

    def _assertValidTenantList(self, tenants):
        pass

    def _assertValidXmlTenantList(self, xml):
        self.assertEquals(xml.tag, '{%s}tenants' % self.xmlns)
        tenants = xml.findall('{%s}tenant' % self.xmlns)

        self._assertValidTenantList(tenants)
        for tenant in tenants:
            self._assertValidXmlTenant(tenant)
        return tenants

    def _assertValidJsonTenantList(self, tenants):
        self._assertValidTenantList(tenants)
        for tenant in tenants:
            self._assertValidJsonTenant(tenant)
        return tenants

    def assertValidXmlTenantListResponse(self, response):
        return self._assertValidXmlTenantList(response.xml)

    def assertValidJsonTenantListResponse(self, response):
        tenants = response.json.get('tenants')
        self.assertIsNotNone(tenants)
        return self._assertValidJsonTenantList(tenants)

    def setUp(self, *args, **kwargs):
        super(TenantTest, self).setUp(*args, **kwargs)

    def tearDown(self, *args, **kwargs):
        super(TenantTest, self).tearDown(*args, **kwargs)


class CreateTenantTest(TenantTest):
    def test_create_tenant(self):
        name = common.unique_str()
        description = common.unique_str()
        response = self.create_tenant(tenant_name=name,
            tenant_description=description, assert_status=201)
        tenant = self.assertValidJsonTenantResponse(response)
        self.assertEqual(name, tenant.get('name'))
        self.assertEqual(description, tenant.get('description'))

    def test_create_tenant_blank_name(self):
        self.create_tenant(tenant_name='', assert_status=400)

    def test_create_tenant_xml(self):
        name = common.unique_str()
        description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true" name="%s"> '
            '<description>%s</description> '
            '</tenant>') % (name, description)
        response = self.post_tenant(as_xml=data, assert_status=201, headers={
            'Accept': 'application/xml'})
        tenant = self.assertValidXmlTenantResponse(response)
        self.assertEqual(name, tenant.get('name'))
        self.assertEqual(description,
            tenant.find('{%s}description' % self.xmlns).text)

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
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.create_tenant(assert_status=403)

    def test_create_tenant_expired_token_xml(self):
        self.fixture_create_expired_token()
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
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.create_tenant(assert_status=403)

    def test_create_tenant_disabled_token_xml(self):
        self.fixture_create_disabled_user_and_token()
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

    def test_create_tenant_missing_name_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true" name="%s"> '
            '<description>A description...</description> '
            '</tenant>') % ('',)
        self.post_tenant(as_xml=data, assert_status=400, headers={
            'Accept': 'application/xml'})


class GetTenantsTest(TenantTest):
    def test_get_tenants_using_admin_token(self):
        response = self.list_tenants(assert_status=200)
        self.assertValidJsonTenantListResponse(response)

    def test_get_tenants_using_admin_token_xml(self):
        response = self.get_tenants(assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertValidXmlTenantListResponse(response)

    def test_get_tenants_using_admin_token_xml_on_service_api(self):
        response = self.create_tenant()
        tenant = self.assertValidJsonTenantResponse(response)
        role = self.create_role().json['role']
        user = self.create_user_with_known_password(tenant_id=tenant['id']).\
            json['user']
        self.grant_role_to_user(user_id=user['id'],
            role_id=role['id'], tenant_id=tenant['id'])

        # find the admin role
        admin_role = self.get_role_by_name('Admin').json['role']

        # grant global admin to user
        self.grant_global_role_to_user(user_id=user['id'],
            role_id=admin_role['id'])

        # authenticate as our new admin
        self.service_token = self.authenticate(user['name'],
            user['password']).json['access']['token']['id']

        # make a service call with our admin token
        response = self.get_tenants(assert_status=200, headers={
            'Accept': 'application/xml'}, request_type='service')
        tenants = self.assertValidXmlTenantListResponse(response)
        self.assertEquals(len(tenants), 1)
        self.assertIn(tenant['id'], [t.get('id') for t in tenants])

    def test_get_tenants_using_user_token(self):
        response = self.create_tenant()
        tenant = self.assertValidJsonTenantResponse(response)
        user = self.create_user_with_known_password(tenant_id=tenant['id']).\
            json['user']
        token = self.authenticate(user['name'], user['password'],
            tenant['id']).json['access']['token']
        tmp = self.service_token
        self.service_token = token['id']
        response = self.service_request(method='GET', path='/tenants',
            assert_status=200)
        self.service_token = tmp
        tenants = self.assertValidJsonTenantListResponse(response)
        self.assertTrue(len(tenants) == 1)
        self.assertIn(tenant['id'], [t['id'] for t in tenants])

    def test_get_tenants_using_user_token_xml(self):
        response = self.create_tenant()
        tenant = self.assertValidJsonTenantResponse(response)
        user = self.create_user_with_known_password(tenant_id=tenant['id']).\
            json['user']
        token = self.authenticate(user['name'], user['password'],
            tenant['id']).json['access']['token']
        tmp = self.service_token
        self.service_token = token['id']
        response = self.service_request(method='GET', path='/tenants',
            assert_status=200, headers={'Accept': 'application/xml'})
        self.service_token = tmp
        tenants = self.assertValidXmlTenantListResponse(response)
        self.assertIn(tenant['id'], [t.get('id') for t in tenants])

    def test_get_tenants_exp_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.list_tenants(assert_status=403)

    def test_get_tenants_exp_token_xml(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_tenants(assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_tenants_blank(self):
        # Create user with no default tenant set
        self.nodefaultuser = self.create_user_with_known_password()\
                                            .json['user']
        response = self.authenticate(self.nodefaultuser['name'],
                              self.nodefaultuser['password'],
                              tenant_id=None, assert_status=200)
        token_id = response.json['access']['token']['id']
        response = self.get_tenants(request_type='service', use_token=token_id)
        self.assertTrue(len(response.json['tenants']) == 0,
                        "No tenants should be returned")

    def test_get_tenants_default_and_role(self):
        """ Validates that the GET /tenants call returns tenants that are
        assigned to the user by role AND by default tenant setting """
        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()
        other_tenant = self.create_tenant().json['tenant']
        role = self.create_role().json['role']
        self.grant_role_to_user(self.tenant_user['id'], role['id'],
                                other_tenant['id'])

        response = self.authenticate(self.tenant_user['name'],
                              self.tenant_user['password'],
                              tenant_id=None, assert_status=200)
        token_id = response.json['access']['token']['id']
        response = self.get_tenants(request_type='service', use_token=token_id)
        tenants = response.json['tenants']
        second_tenant = [tenant for tenant in tenants
                          if tenant['id'] == other_tenant['id']]
        self.assertTrue(len(second_tenant) > 0,
                        "Tenants with roles assigned should be returned")

        default_tenant = [tenant for tenant in tenants
                          if tenant['id'] == self.tenant['id']]
        self.assertTrue(len(default_tenant) > 0,
                        "Default tenant should be returned")

    def test_get_tenants_does_not_return_default(self):
        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()
        other_tenant = self.create_tenant().json['tenant']
        role = self.create_role().json['role']
        self.grant_role_to_user(self.tenant_user['id'], role['id'],
                                other_tenant['id'])

        # Authenticate scoped to the non-default tenant
        response = self.authenticate(self.tenant_user['name'],
                              self.tenant_user['password'],
                              tenant_id=other_tenant['id'],
                              assert_status=200)
        token_id = response.json['access']['token']['id']
        response = self.get_tenants(request_type='service', use_token=token_id)
        tenants = response.json['tenants']
        second_tenant = [tenant for tenant in tenants
                          if tenant['id'] == other_tenant['id']]
        self.assertTrue(len(second_tenant) > 0,
                        "Tenants with roles assigned should be returned")

        default_tenant = [tenant for tenant in tenants
                          if tenant['id'] == self.tenant['id']]
        self.assertTrue(len(default_tenant) == 0,
                        "Default tenant should not be returned")


class GetTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(GetTenantTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()

    def test_get_tenant(self):
        response = self.fetch_tenant(self.tenant['id'], assert_status=200)
        tenant = self.assertValidJsonTenantResponse(response)
        self.assertEquals(self.tenant['id'], tenant['id'])
        self.assertEquals(self.tenant['name'], tenant['name'])
        self.assertFalse('description' in tenant)
        self.assertEquals(self.tenant['enabled'], tenant['enabled'])

    def test_get_tenant_xml(self):
        response = self.fetch_tenant(self.tenant['id'], assert_status=200,
                                     headers={"Accept": "application/xml"})
        tenant = self.assertValidXmlTenantResponse(response)
        self.assertEquals(self.tenant['id'], tenant.get('id'))
        self.assertEquals(self.tenant['name'], tenant.get('name'))
        self.assertEquals(str(self.tenant['enabled']).lower(),
            tenant.get('enabled'))

    def test_get_tenant_not_found(self):
        self.fetch_tenant(assert_status=404)

    def test_get_tenant_not_found_xml(self):
        self.get_tenant(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


class GetTenantUsersTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(GetTenantUsersTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()
        self.fixture_create_normal_user()

        role = self.create_role().json['role']
        self.grant_role_to_user(self.user['id'], role['id'], self.tenant['id'])

    def test_list_tenant_users(self):
        user = self.list_tenant_users(self.tenant['id'],
            assert_status=200).json['users'][0]
        self.assertEquals(user['name'], self.user['name'])

    def test_list_tenant_users_xml(self):
        response = self.list_tenant_users(self.tenant['id'],
            assert_status=200, headers={
            "Accept": "application/xml"})
        self.assertEquals(response.xml.tag, '{%s}users' % self.xmlns)
        users = response.xml.findall('{%s}user' % self.xmlns)
        for user in users:
            self.assertEqual(user.get('name'), self.user['name'])

    def test_list_tenant_users_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.list_tenant_users(self.tenant['id'], assert_status=403)

    def test_list_tenant_users_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.list_tenant_users(self.tenant['id'], assert_status=403)

    def test_list_tenant_users_missing_token(self):
        self.admin_token = ''
        self.list_tenant_users(self.tenant['id'], assert_status=401)

    def test_list_tenant_users_invalid_token(self):
        self.admin_token = common.unique_str()
        self.list_tenant_users(self.tenant['id'], assert_status=401)


class GetTenantUsersByRoleTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(GetTenantUsersByRoleTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()
        self.fixture_create_normal_user()

        self.role = self.create_role().json['role']
        self.grant_role_to_user(self.user['id'],
            self.role['id'], self.tenant['id'])

    def test_list_tenant_users(self):
        user = self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=200).json['users'][0]
        self.assertEquals(user['name'], self.user['name'])

    def test_list_tenant_users_xml(self):
        response = self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=200, headers={
            "Accept": "application/xml"})
        self.assertEquals(response.xml.tag, '{%s}users' % self.xmlns)
        users = response.xml.findall('{%s}user' % self.xmlns)
        for user in users:
            self.assertEqual(user.get('name'), self.user['name'])

    def test_list_tenant_users_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=403)

    def test_list_tenant_users_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=403)

    def test_list_tenant_users_missing_token(self):
        self.admin_token = ''
        self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=401)

    def test_list_tenant_users_invalid_token(self):
        self.admin_token = common.unique_str()
        self.list_tenant_users(self.tenant['id'],
            self.role['id'], assert_status=401)


class GetTenantByNameTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(GetTenantByNameTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()

    def test_get_tenant(self):
        response = self.fetch_tenant_by_name(self.tenant['name'],
                                             assert_status=200)
        tenant = self.assertValidJsonTenantResponse(response)
        self.assertEquals(self.tenant['id'], tenant['id'])
        self.assertEquals(self.tenant['name'], tenant['name'])
        self.assertEquals(self.tenant['enabled'], tenant['enabled'])

    def test_get_tenant_data(self):
        tenant = self.fixture_create_tenant(name=common.unique_str(),
                                            description=common.unique_str(),
                                            enabled=True)
        response = self.fetch_tenant_by_name(tenant['name'], assert_status=200)
        returned = self.assertValidJsonTenantResponse(response)
        self.assertEquals(returned['id'], tenant['id'])
        self.assertEquals(returned['name'], tenant['name'])
        self.assertEquals(returned['description'], tenant['description'])
        self.assertEquals(returned['enabled'], tenant['enabled'])

    def test_get_tenant_xml(self):
        response = self.fetch_tenant_by_name(
            self.tenant['name'], assert_status=200, headers={
            "Accept": "application/xml"})
        tenant = self.assertValidXmlTenantResponse(response)

        self.assertEquals(self.tenant['id'], tenant.get('id'))
        self.assertEquals(self.tenant['name'], tenant.get('name'))
        self.assertEquals(str(self.tenant['enabled']).lower(),
            tenant.get('enabled'))

    def test_get_tenant_not_found(self):
        self.fetch_tenant_by_name(assert_status=404)

    def test_get_tenant_not_found_xml(self):
        self.fetch_tenant_by_name(
            common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


class UpdateTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(UpdateTenantTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()

    def test_update_tenant(self):
        new_tenant_name = common.unique_str()
        new_description = common.unique_str()
        response = self.update_tenant(self.tenant['id'],
            tenant_name=new_tenant_name, tenant_enabled=False,
            tenant_description=new_description, assert_status=200)
        updated_tenant = self.assertValidJsonTenantResponse(response)
        self.assertEqual(updated_tenant['name'], new_tenant_name)
        self.assertEqual(updated_tenant['description'], new_description)
        self.assertEqual(updated_tenant['enabled'], False)

    def test_update_tenant_xml(self):
        new_tenant_name = common.unique_str()
        new_description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
             '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
             'name="%s" '
             'enabled="false"> '
             '<description>%s</description> '
             '</tenant>') % (new_tenant_name, new_description,)
        response = self.post_tenant_for_update(
            self.tenant['id'], as_xml=data, assert_status=200)
        updated = self.assertValidXmlTenantResponse(response)

        self.assertEqual(updated.get('id'), self.tenant['id'])
        self.assertEqual(updated.get('name'), new_tenant_name)
        description = updated.find("{%s}description" % self.xmlns)
        self.assertEqual(description.text, new_description)
        self.assertEqual(updated.get('enabled'), 'false')

    def test_update_tenant_bad(self):
        data = '{"tenant": { "description_bad": "A NEW description...",\
                "enabled":true  }}'
        self.post_tenant_for_update(
            self.tenant['id'], as_json=data, assert_status=400)

    def test_update_tenant_bad_xml(self):
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <tenant xmlns="http://docs.openstack.org/identity/api/v2.0" \
             enabled="true"> \
             <description_bad>A NEW description...</description> \
             </tenant>'
        self.post_tenant_for_update(
            self.tenant['id'], as_xml=data, assert_status=400)

    def test_update_tenant_not_found(self):
        self.update_tenant(assert_status=404)

    def test_update_tenant_not_found_xml(self):
        data = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<tenant xmlns="http://docs.openstack.org/identity/api/v2.0" '
            'enabled="true"> '
            '<description>A NEW description...</description> '
            '</tenant>')
        self.post_tenant_for_update(
            common.unique_str(), as_xml=data, assert_status=404)


class DeleteTenantTest(TenantTest):
    def setUp(self, *args, **kwargs):
        super(DeleteTenantTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()

    def test_delete_tenant(self):
        self.remove_tenant(self.tenant['id'], assert_status=204)
        self.get_tenant(self.tenant['id'], assert_status=404)
        self.update_tenant(self.tenant['id'], assert_status=404)

    def test_delete_tenant_xml(self):
        self.delete_tenant(self.tenant['id'], assert_status=204, headers={
            'Accept': 'application/xml'})
        self.get_tenant(self.tenant['id'], assert_status=404)
        self.update_tenant(self.tenant['id'], assert_status=404)

    def test_delete_tenant_not_found(self):
        self.remove_tenant(common.unique_str(), assert_status=404)

    def test_delete_tenant_not_found_xml(self):
        self.delete_tenant(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})


if __name__ == '__main__':
    unittest.main()
