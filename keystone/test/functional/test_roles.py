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


class RolesTest(common.FunctionalTestCase):
    expected_roles = ['Admin', 'Member', 'KeystoneServiceAdmin']

    def setUp(self, *args, **kwargs):
        super(RolesTest, self).setUp(*args, **kwargs)

    def tearDown(self, *args, **kwargs):
        super(RolesTest, self).tearDown(*args, **kwargs)


class CreateRolesTest(RolesTest):
    def test_create_role(self):
        self.create_role(assert_status=201)

    def test_create_role_using_blank_name(self):
        self.create_role(role_name='', assert_status=400)

    def test_create_role_using_service_token(self):
        user = self.create_user_with_known_password().json['user']
        self.admin_token = self.authenticate(user['name'],
                            user['password']).json['access']['token']['id']
        self.create_role(assert_status=401)

    def test_create_roles_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.create_role(assert_status=403)

    def test_create_roles_using_missing_token(self):
        self.admin_token = ''
        self.create_role(assert_status=401)

    def test_create_roles_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.create_role(assert_status=403)

    def test_create_roles_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.create_role(assert_status=401)

    def test_create_role_mapped_to_a_service(self):
        service = self.create_service().json['OS-KSADM:service']
        role_name = service['name'] + ':' + common.unique_str()
        role = self.create_role(role_name=role_name,
            service_id=service['id']).json['role']
        self.assertEqual(role_name, role['name'])
        self.assertEqual(service['id'], role['serviceId'])

    def test_create_role_mapped_to_a_service_xml(self):
        service = self.create_service().json['OS-KSADM:service']
        name = service['name'] + ':' + common.unique_str()
        description = common.unique_str()

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<role xmlns="%s" name="%s" description="%s" serviceId="%s"/>') % (
                self.xmlns, name, description, service['id'])
        id = self.post_role(assert_status=201, as_xml=data).xml.get('id')
        self.assertIsNotNone(id)

        role = self.fetch_role(id, assert_status=200).json['role']
        self.assertEqual(role['name'], name)
        self.assertEqual(role['description'], description)
        self.assertEqual(role['serviceId'], service['id'])

    def test_create__service_role_using_incorrect_role_name(self):
        """ test_create_role_mapped_to_a_service_using_incorrect_role_name """
        self.create_role(common.unique_str(), service_id=common.unique_str(),
            assert_status=400)

    def test_create_role_using_empty_name_xml(self):
        name = ''
        description = common.unique_str()
        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<role xmlns="%s" name="%s" description="%s" />') % (
                self.xmlns, name, description)
        self.post_role(assert_status=400, as_xml=data)


class DeleteRoleTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(DeleteRoleTest, self).setUp(*args, **kwargs)

        self.role = self.create_role().json['role']

    def test_delete_roles_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.delete_role(self.role['id'], assert_status=403)

    def test_delete_roles_using_missing_token(self):
        self.admin_token = ''
        self.delete_role(self.role['id'], assert_status=401)

    def test_delete_roles_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.delete_role(self.role['id'], assert_status=403)

    def test_delete_roles_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.delete_role(self.role['id'], assert_status=401)

    def test_create_and_delete_role_that_has_references(self):
        tenant = self.create_tenant().json['tenant']
        user = self.create_user(tenant_id=tenant['id']).json['user']
        self.grant_role_to_user(user['id'], self.role['id'], tenant['id'])
        self.remove_role(self.role['id'], assert_status=204)

    def test_create_role_mapped_to_a_service(self):
        service = self.create_service().json['OS-KSADM:service']
        role_name = service['name'] + ':' + common.unique_str()
        role = self.create_role(role_name=role_name,
            service_id=service['id']).json['role']
        self.assertEqual(service['id'], role['serviceId'])

    def test_create_role_mapped_to_a_service_xml(self):
        service = self.create_service().json['OS-KSADM:service']
        name = service['name'] + ':' + common.unique_str()
        description = common.unique_str()

        data = ('<?xml version="1.0" encoding="UTF-8"?> '
            '<role xmlns="%s" name="%s" description="%s" serviceId="%s"/>') % (
                self.xmlns, name, description, service['id'])
        role_id = self.post_role(assert_status=201, as_xml=data).xml.get('id')

        role = self.fetch_role(role_id, assert_status=200).json['role']
        self.assertEqual(role['id'], role_id)
        self.assertEqual(role['serviceId'], service['id'])

    def test_create_service_role_using_incorrect_role_name(self):
        """ Formerly:
            test_create_role_mapped_to_a_service_using_incorrect_role_name"""
        self.create_role(common.unique_str(), service_id=common.unique_str(),
            assert_status=400)


class GetRolesByServiceTest(common.FunctionalTestCase):
    def setUp(self, *args, **kwargs):
        super(GetRolesByServiceTest, self).setUp(*args, **kwargs)
        service = self.create_service().json['OS-KSADM:service']
        role_name = service['name'] + ':' + common.unique_str()
        role = self.create_role(role_name=role_name,
            service_id=service['id']).json['role']
        self.service_id = service['id']

    def tearDown(self, *args, **kwargs):
        super(GetRolesByServiceTest, self).tearDown(*args, **kwargs)

    def test_get_roles(self):
        r = self.list_roles(assert_status=200, service_id=self.service_id)
        self.assertTrue(len(r.json['roles']))

    def test_get_roles_xml(self):
        r = self.get_roles_by_service(assert_status=200, headers={
            'Accept': 'application/xml'}, service_id=self.service_id,)
        self.assertEquals(r.xml.tag, '{%s}roles' % self.xmlns)
        roles = r.xml.findall('{%s}role' % self.xmlns)

        for role in roles:
            self.assertIsNotNone(role.get('id'))

    def test_get_roles_exp_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_roles_by_service(
            service_id=self.service_id, assert_status=403)

    def test_get_roles_exp_token_xml(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_roles_by_service(
            service_id=self.service_id, assert_status=403, headers={
            'Accept': 'application/xml'})


class GetRolesTest(RolesTest):
    def test_get_roles(self):
        r = self.list_roles(assert_status=200)
        self.assertTrue(len(r.json['roles']))

    def test_get_roles_xml(self):
        r = self.get_roles(assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertEquals(r.xml.tag, '{%s}roles' % self.xmlns)
        roles = r.xml.findall('{%s}role' % self.xmlns)

        for role in roles:
            self.assertIsNotNone(role.get('id'))

    def test_get_roles_exp_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_roles(assert_status=403)

    def test_get_roles_exp_token_xml(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_roles(assert_status=403, headers={
            'Accept': 'application/xml'})


class GetRoleTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(GetRoleTest, self).setUp(*args, **kwargs)
        self.role = self.create_role().json['role']

    def test_get_role(self):
        role = self.fetch_role(self.role['id'], assert_status=200).json['role']
        self.assertEqual(role['id'], self.role['id'])
        self.assertEqual(role['name'], self.role['name'])
        self.assertEqual(role['description'], self.role['description'])
        self.assertEqual(role.get('serviceId'), self.role.get('serviceId'))

    def test_get_role_xml(self):
        r = self.get_role(self.role['id'], assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag, '{%s}role' % self.xmlns)
        self.assertEqual(r.xml.get('id'), self.role['id'])
        self.assertEqual(r.xml.get('name'), self.role['name'])
        self.assertEqual(r.xml.get('description'), self.role['description'])
        self.assertEqual(r.xml.get('serviceId'), self.role.get('serviceId'))

    def test_get_role_bad(self):
        self.fetch_role(common.unique_str(), assert_status=404)

    def test_get_role_xml_bad(self):
        self.get_role(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})

    def test_get_role_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.fetch_role(self.role['id'], assert_status=403)

    def test_get_role_xml_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_role(self.role['id'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.fetch_role(self.role['id'], assert_status=403)

    def test_get_role_xml_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.get_role(self.role['id'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_missing_token(self):
        self.admin_token = ''
        self.fetch_role(self.role['id'], assert_status=401)

    def test_get_role_xml_using_missing_token(self):
        self.admin_token = ''
        self.get_role(self.role['id'], assert_status=401, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_role(self.role['id'], assert_status=401)

    def test_get_role_xml_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.get_role(self.role['id'], assert_status=401, headers={
            'Accept': 'application/xml'})


class GetRoleByNameTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(GetRoleByNameTest, self).setUp(*args, **kwargs)

        self.role = self.create_role().json['role']

    def test_get_role(self):
        role = self.fetch_role_by_name(
                self.role['name'], assert_status=200).json['role']
        self.assertEqual(role['id'], self.role['id'])
        self.assertEqual(role['name'], self.role['name'])
        self.assertEqual(role['description'], self.role['description'])
        self.assertEqual(role.get('serviceId'), self.role.get('serviceId'))

    def test_get_role_xml(self):
        r = self.get_role_by_name(self.role['name'],
            assert_status=200, headers={
            'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag, '{%s}role' % self.xmlns)
        self.assertEqual(r.xml.get('id'), self.role['id'])
        self.assertEqual(r.xml.get('name'), self.role['name'])
        self.assertEqual(r.xml.get('description'), self.role['description'])
        self.assertEqual(r.xml.get('serviceId'), self.role.get('serviceId'))

    def test_get_role_bad(self):
        self.fetch_role_by_name(common.unique_str(), assert_status=404)

    def test_get_role_xml_bad(self):
        self.get_role_by_name(common.unique_str(), assert_status=404, headers={
            'Accept': 'application/xml'})

    def test_get_role_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.fetch_role_by_name(self.role['name'], assert_status=403)

    def test_get_role_xml_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_role_by_name(self.role['name'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.fetch_role_by_name(self.role['name'], assert_status=403)

    def test_get_role_xml_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.get_role_by_name(self.role['name'], assert_status=403, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_missing_token(self):
        self.admin_token = ''
        self.fetch_role_by_name(self.role['name'], assert_status=401)

    def test_get_role_xml_using_missing_token(self):
        self.admin_token = ''
        self.get_role_by_name(self.role['name'], assert_status=401, headers={
            'Accept': 'application/xml'})

    def test_get_role_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.fetch_role_by_name(self.role['name'], assert_status=401)

    def test_get_role_xml_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.get_role_by_name(self.role['name'], assert_status=401, headers={
            'Accept': 'application/xml'})


class CreateRoleAssignmentTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(CreateRoleAssignmentTest, self).setUp(*args, **kwargs)

        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()

        self.role = self.create_role().json['role']

    def test_grant_role(self):
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=201)

#    def test_grant_role_json_using_service_admin_token(self):
#        tenant = self.create_tenant().json['tenant']
#        service_admin = self.create_user_with_known_password().json['user']
#        self.grant_role_to_user(service_admin['id'], 'KeystoneServiceAdmin',
#            tenant['id'], assert_status=201)
#
#        service_admin_token_id = self.authenticate(service_admin['name'],
#            service_admin['password']).json['auth']['token']['id']
#
#        user = self.create_user().json['user']
#
#        role = self.create_role().json['role']
#        self.admin_token = service_admin_token_id
#        self.grant_role_to_user(user['id'], role['id'], tenant['id'],
#            assert_status=201)

    def test_grant_role_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=403)

    def test_grant_role_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=403)

    def test_grant_role_using_missing_token(self):
        self.admin_token = ''
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=401)

    def test_grant_role_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=401)

    def test_grant_global_role_json(self):
        self.grant_global_role_to_user(
            self.tenant_user['id'], self.role['id'], assert_status=201)


class GetRoleAssignmentsTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(GetRoleAssignmentsTest, self).setUp(*args, **kwargs)
        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()

        self.role = self.create_role().json['role']
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'])

    def test_get_role_assignments(self):
        r = self.get_user_roles(self.tenant_user['id'], assert_status=200)
        self.assertIsNotNone(r.json['roles'])

    def test_get_roler_assignments_xml(self):
        r = self.get_user_roles(self.tenant_user['id'], assert_status=200,
            headers={'Accept': 'application/xml'})
        self.assertEqual(r.xml.tag, "{%s}roles" % self.xmlns)

    def test_get_role_assignments_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_user_roles(self.tenant_user['id'], assert_status=403)

    def test_get_role_assignments_xml_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.get_user_roles(self.tenant_user['id'], assert_status=403,
                            headers={'Accept': 'application/xml'})

    def test_get_role_assignments_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.get_user_roles(self.tenant_user['id'], assert_status=403)

    def test_get_role_assignments_xml_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.get_user_roles(self.tenant_user['id'], assert_status=403,
                            headers={'Accept': 'application/xml'})

    def test_get_role_assignments_using_missing_token(self):
        self.admin_token = ''
        self.get_user_roles(self.tenant_user['id'], assert_status=401)

    def test_get_role_assignments_xml_using_missing_token(self):
        self.admin_token = ''
        self.get_user_roles(self.tenant_user['id'], assert_status=401,
                            headers={'Accept': 'application/xml'})

    def test_get_role_assignments_json_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.get_user_roles(self.tenant_user['id'], assert_status=401)

    def test_get_role_assignments_xml_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.get_user_roles(self.tenant_user['id'], assert_status=401,
                            headers={'Accept': 'application/xml'})


class DeleteRoleAssignmentsTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(DeleteRoleAssignmentsTest, self).setUp(*args, **kwargs)

        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()

        self.role = self.create_role().json['role']
        self.grant_role_to_user(self.tenant_user['id'], self.role['id'],
            self.tenant['id'])
        self.roles = self.get_user_roles(self.tenant_user['id']).\
            json['roles']

    def test_delete_role_assignment(self):
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=204)

    def test_delete_role_assignment_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=403)

    def test_delete_role_assignment_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=403)

    def test_delete_role_assignment_using_missing_token(self):
        self.admin_token = ''
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=401)

    def test_delete_role_assignment_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            self.tenant['id'], assert_status=401)


class DeleteGlobalRoleAssignmentsTest(RolesTest):
    def setUp(self, *args, **kwargs):
        super(DeleteGlobalRoleAssignmentsTest, self).setUp(*args, **kwargs)

        self.fixture_create_normal_tenant()
        self.fixture_create_tenant_user()

        self.role = self.create_role().json['role']
        self.grant_global_role_to_user(self.tenant_user['id'], self.role['id'])
        self.roles = self.get_user_roles(self.tenant_user['id']).\
            json['roles']

    def test_delete_role_assignment(self):
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            None, assert_status=204)

    def test_delete_role_assignment_using_expired_token(self):
        self.fixture_create_expired_token()
        self.admin_token = self.expired_admin_token
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            None, assert_status=403)

    def test_delete_role_assignment_using_disabled_token(self):
        self.fixture_create_disabled_user_and_token()
        self.admin_token = self.disabled_admin_token
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            None, assert_status=403)

    def test_delete_role_assignment_using_missing_token(self):
        self.admin_token = ''
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            None, assert_status=401)

    def test_delete_role_assignment_using_invalid_token(self):
        self.admin_token = common.unique_str()
        self.delete_user_role(self.tenant_user['id'], self.role['id'],
            None, assert_status=401)

if __name__ == '__main__':
    unittest.main()
