# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

import test_v3


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test domains, projects, users, groups, credential & role CRUD"""

    def setUp(self):
        super(IdentityTestCase, self).setUp()

        self.group_id = uuid.uuid4().hex
        self.group = self.new_group_ref(
            domain_id=self.domain_id)
        self.group['id'] = self.group_id
        self.identity_api.create_group(self.group_id, self.group)

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.identity_api.create_credential(
            self.credential_id,
            self.credential)

    # domain crud tests

    def test_create_domain(self):
        """POST /domains"""
        ref = self.new_domain_ref()
        r = self.post(
            '/domains',
            body={'domain': ref})
        return self.assertValidDomainResponse(r, ref)

    def test_list_domains(self):
        """GET /domains"""
        r = self.get('/domains')
        self.assertValidDomainListResponse(r, ref=self.domain)

    def test_list_domains_xml(self):
        """GET /domains (xml data)"""
        r = self.get('/domains', content_type='xml')
        self.assertValidDomainListResponse(r, ref=self.domain)

    def test_get_domain(self):
        """GET /domains/{domain_id}"""
        r = self.get('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id})
        self.assertValidDomainResponse(r, self.domain)

    def test_update_domain(self):
        """PATCH /domains/{domain_id}"""
        ref = self.new_domain_ref()
        del ref['id']
        r = self.patch('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id},
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

    def test_disable_domain(self):
        """PATCH /domains/{domain_id} (set enabled=False)"""
        self.domain['enabled'] = False
        r = self.patch('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id},
            body={'domain': {'enabled': False}})
        self.assertValidDomainResponse(r, self.domain)

        # check that the project and user are still enabled
        # FIXME(gyee): are these tests still valid since user should not
        # be able to authenticate into a disabled domain
        #r = self.get('/projects/%(project_id)s' % {
        #    'project_id': self.project_id})
        #self.assertValidProjectResponse(r, self.project)
        #self.assertTrue(r.body['project']['enabled'])

        #r = self.get('/users/%(user_id)s' % {
        #    'user_id': self.user['id']})
        #self.assertValidUserResponse(r, self.user)
        #self.assertTrue(r.body['user']['enabled'])

        # TODO(dolph): assert that v2 & v3 auth return 401

    def test_delete_domain(self):
        """DELETE /domains/{domain_id}"""
        self.delete('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id})

    # project crud tests

    def test_list_projects(self):
        """GET /projects"""
        r = self.get('/projects')
        self.assertValidProjectListResponse(r, ref=self.project)

    def test_list_projects_xml(self):
        """GET /projects (xml data)"""
        r = self.get('/projects', content_type='xml')
        self.assertValidProjectListResponse(r, ref=self.project)

    def test_create_project(self):
        """POST /projects"""
        ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post(
            '/projects',
            body={'project': ref})
        self.assertValidProjectResponse(r, ref)

    def test_get_project(self):
        """GET /projects/{project_id}"""
        r = self.get(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id})
        self.assertValidProjectResponse(r, self.project)

    def test_update_project(self):
        """PATCH /projects/{project_id}"""
        ref = self.new_project_ref(domain_id=self.domain_id)
        del ref['id']
        r = self.patch(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id},
            body={'project': ref})
        self.assertValidProjectResponse(r, ref)

    def test_delete_project(self):
        """DELETE /projects/{project_id}"""
        self.delete(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id})

    # user crud tests

    def test_create_user(self):
        """POST /users"""
        ref = self.new_user_ref(domain_id=self.domain_id)
        r = self.post(
            '/users',
            body={'user': ref})
        return self.assertValidUserResponse(r, ref)

    def test_list_users(self):
        """GET /users"""
        r = self.get('/users')
        self.assertValidUserListResponse(r, ref=self.user)

    def test_list_users_xml(self):
        """GET /users (xml data)"""
        r = self.get('/users', content_type='xml')
        self.assertValidUserListResponse(r, ref=self.user)

    def test_get_user(self):
        """GET /users/{user_id}"""
        r = self.get('/users/%(user_id)s' % {
            'user_id': self.user['id']})
        self.assertValidUserResponse(r, self.user)

    def test_add_user_to_group(self):
        """PUT /groups/{group_id}/users/{user_id}"""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_check_user_in_group(self):
        """HEAD /groups/{group_id}/users/{user_id}"""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        self.head('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_list_users_in_group(self):
        """GET /groups/{group_id}/users"""
        r = self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        r = self.get('/groups/%(group_id)s/users' % {
            'group_id': self.group_id})
        self.assertValidUserListResponse(r, ref=self.user)
        self.assertIn('/groups/%(group_id)s/users' % {
            'group_id': self.group_id}, r.body['links']['self'])

    def test_remove_user_from_group(self):
        """DELETE /groups/{group_id}/users/{user_id}"""
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user['id']})

    def test_update_user(self):
        """PATCH /users/{user_id}"""
        user = self.new_user_ref(domain_id=self.domain_id)
        del user['id']
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body={'user': user})
        self.assertValidUserResponse(r, user)

    def test_delete_user(self):
        """DELETE /users/{user_id}"""
        self.delete('/users/%(user_id)s' % {
            'user_id': self.user['id']})

    # group crud tests

    def test_create_group(self):
        """POST /groups"""
        ref = self.new_group_ref(domain_id=self.domain_id)
        r = self.post(
            '/groups',
            body={'group': ref})
        return self.assertValidGroupResponse(r, ref)

    def test_list_groups(self):
        """GET /groups"""
        r = self.get('/groups')
        self.assertValidGroupListResponse(r, ref=self.group)

    def test_list_groups_xml(self):
        """GET /groups (xml data)"""
        r = self.get('/groups', content_type='xml')
        self.assertValidGroupListResponse(r, ref=self.group)

    def test_get_group(self):
        """GET /groups/{group_id}"""
        r = self.get('/groups/%(group_id)s' % {
            'group_id': self.group_id})
        self.assertValidGroupResponse(r, self.group)

    def test_update_group(self):
        """PATCH /groups/{group_id}"""
        group = self.new_group_ref(domain_id=self.domain_id)
        del group['id']
        r = self.patch('/groups/%(group_id)s' % {
            'group_id': self.group_id},
            body={'group': group})
        self.assertValidGroupResponse(r, group)

    def test_delete_group(self):
        """DELETE /groups/{group_id}"""
        self.delete('/groups/%(group_id)s' % {
            'group_id': self.group_id})

    # credential crud tests

    def test_list_credentials(self):
        """GET /credentials"""
        r = self.get('/credentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_list_credentials_xml(self):
        """GET /credentials (xml data)"""
        r = self.get('/credentials', content_type='xml')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_create_credential(self):
        """POST /credentials"""
        ref = self.new_credential_ref(user_id=self.user['id'])
        r = self.post(
            '/credentials',
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_get_credential(self):
        """GET /credentials/{credential_id}"""
        r = self.get(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id})
        self.assertValidCredentialResponse(r, self.credential)

    def test_update_credential(self):
        """PATCH /credentials/{credential_id}"""
        ref = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        del ref['id']
        r = self.patch(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id},
            body={'credential': ref})
        self.assertValidCredentialResponse(r, ref)

    def test_delete_credential(self):
        """DELETE /credentials/{credential_id}"""
        self.delete(
            '/credentials/%(credential_id)s' % {
                'credential_id': self.credential_id})

    # role crud tests

    def test_create_role(self):
        """POST /roles"""
        ref = self.new_role_ref()
        r = self.post(
            '/roles',
            body={'role': ref})
        return self.assertValidRoleResponse(r, ref)

    def test_list_roles(self):
        """GET /roles"""
        r = self.get('/roles')
        self.assertValidRoleListResponse(r, ref=self.role)

    def test_list_roles_xml(self):
        """GET /roles (xml data)"""
        r = self.get('/roles', content_type='xml')
        self.assertValidRoleListResponse(r, ref=self.role)

    def test_get_role(self):
        """GET /roles/{role_id}"""
        r = self.get('/roles/%(role_id)s' % {
            'role_id': self.role_id})
        self.assertValidRoleResponse(r, self.role)

    def test_update_role(self):
        """PATCH /roles/{role_id}"""
        ref = self.new_role_ref()
        del ref['id']
        r = self.patch('/roles/%(role_id)s' % {
            'role_id': self.role_id},
            body={'role': ref})
        self.assertValidRoleResponse(r, ref)

    def test_delete_role(self):
        """DELETE /roles/{role_id}"""
        self.delete('/roles/%(role_id)s' % {
            'role_id': self.role_id})

    def test_crud_user_project_role_grants(self):
        collection_url = (
            '/projects/%(project_id)s/users/%(user_id)s/roles' % {
                'project_id': self.project['id'],
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url)
        self.head(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role)
        self.assertIn(collection_url, r.body['links']['self'])

        # FIXME(gyee): this test is no longer valid as user
        # have no role in the project. Can't get a scoped token
        #self.delete(member_url)
        #r = self.get(collection_url)
        #self.assertValidRoleListResponse(r, expected_length=0)
        #self.assertIn(collection_url, r.body['links']['self'])

    def test_crud_user_domain_role_grants(self):
        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domain_id,
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url)
        self.head(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role)
        self.assertIn(collection_url, r.body['links']['self'])

        self.delete(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, expected_length=0)
        self.assertIn(collection_url, r.body['links']['self'])

    def test_crud_group_project_role_grants(self):
        collection_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                'project_id': self.project_id,
                'group_id': self.group_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url)
        self.head(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role)
        self.assertIn(collection_url, r.body['links']['self'])

        self.delete(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, expected_length=0)
        self.assertIn(collection_url, r.body['links']['self'])

    def test_crud_group_domain_role_grants(self):
        collection_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/roles' % {
                'domain_id': self.domain_id,
                'group_id': self.group_id})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}

        self.put(member_url)
        self.head(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, ref=self.role)
        self.assertIn(collection_url, r.body['links']['self'])

        self.delete(member_url)
        r = self.get(collection_url)
        self.assertValidRoleListResponse(r, expected_length=0)
        self.assertIn(collection_url, r.body['links']['self'])
