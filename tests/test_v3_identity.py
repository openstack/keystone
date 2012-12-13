import uuid

import test_v3


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test domains, projects, users, groups, credential & role CRUD"""

    def setUp(self):
        super(IdentityTestCase, self).setUp()

        self.domain_id = uuid.uuid4().hex
        self.domain = self.new_domain_ref()
        self.domain['id'] = self.domain_id
        self.identity_api.create_domain(
            self.domain_id,
            self.domain.copy())

        self.project_id = uuid.uuid4().hex
        self.project = self.new_project_ref(
            domain_id=self.domain_id)
        self.project['id'] = self.project_id
        self.identity_api.create_project(
            self.project_id,
            self.project.copy())

        self.user_id = uuid.uuid4().hex
        self.user = self.new_user_ref(
            domain_id=self.domain_id,
            project_id=self.project_id)
        self.user['id'] = self.user_id
        self.identity_api.create_user(
            self.user_id,
            self.user.copy())

        self.group_id = uuid.uuid4().hex
        self.group = self.new_group_ref(
            domain_id=self.domain_id)
        self.group['id'] = self.group_id
        self.identity_api.create_group(
            self.group_id,
            self.group.copy())

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user_id,
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.identity_api.create_credential(
            self.credential_id,
            self.credential.copy())

        self.role_id = uuid.uuid4().hex
        self.role = self.new_role_ref()
        self.role['id'] = self.role_id
        self.identity_api.create_role(
            self.role_id,
            self.role.copy())

    # domain validation

    def assertValidDomainListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'domains',
            self.assertValidDomain,
            ref)

    def assertValidDomainResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'domain',
            self.assertValidDomain,
            ref)

    def assertValidDomain(self, entity, ref=None):
        if ref:
            pass
        return entity

    # project validation

    def assertValidProjectListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'projects',
            self.assertValidProject,
            ref)

    def assertValidProjectResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'project',
            self.assertValidProject,
            ref)

    def assertValidProject(self, entity, ref=None):
        self.assertIsNotNone(entity.get('domain_id'))
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
        return entity

    # user validation

    def assertValidUserListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'users',
            self.assertValidUser,
            ref)

    def assertValidUserResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'user',
            self.assertValidUser,
            ref)

    def assertValidUser(self, entity, ref=None):
        self.assertIsNotNone(entity.get('domain_id'))
        self.assertIsNotNone(entity.get('email'))
        self.assertIsNone(entity.get('password'))
        if ref:
            self.assertEqual(ref['domain_id'], entity['domain_id'])
            self.assertEqual(ref['email'], entity['email'])
        return entity

    # group validation

    def assertValidGroupListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'groups',
            self.assertValidGroup,
            ref)

    def assertValidGroupResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'group',
            self.assertValidGroup,
            ref)

    def assertValidGroup(self, entity, ref=None):
        self.assertIsNotNone(entity.get('name'))
        if ref:
            self.assertEqual(ref['name'], entity['name'])
        return entity

    # credential validation

    def assertValidCredentialListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'credentials',
            self.assertValidCredential,
            ref)

    def assertValidCredentialResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'credential',
            self.assertValidCredential,
            ref)

    def assertValidCredential(self, entity, ref=None):
        self.assertIsNotNone(entity.get('user_id'))
        self.assertIsNotNone(entity.get('blob'))
        self.assertIsNotNone(entity.get('type'))
        if ref:
            self.assertEqual(ref['user_id'], entity['user_id'])
            self.assertEqual(ref['blob'], entity['blob'])
            self.assertEqual(ref['type'], entity['type'])
            self.assertEqual(ref.get('project_id'), entity.get('project_id'))
        return entity

    # role validation

    def assertValidRoleListResponse(self, resp, ref):
        return self.assertValidListResponse(
            resp,
            'roles',
            self.assertValidRole,
            ref)

    def assertValidRoleResponse(self, resp, ref):
        return self.assertValidResponse(
            resp,
            'role',
            self.assertValidRole,
            ref)

    def assertValidRole(self, entity, ref=None):
        self.assertIsNotNone(entity.get('name'))
        if ref:
            self.assertEqual(ref['name'], entity['name'])
        return entity

    # grant validation

    def assertValidGrantListResponse(self, resp, ref):
        entities = resp.body
        self.assertIsNotNone(entities)
        self.assertTrue(len(entities))
        roles_ref_ids = []
        for i, entity in enumerate(entities):
            self.assertValidEntity(entity)
            self.assertValidGrant(entity, ref)
            if ref and entity['id'] == ref['id'][0]:
                self.assertValidEntity(entity, ref)
                self.assertValidGrant(entity, ref)

    def assertValidGrant(self, entity, ref=None):
        self.assertIsNotNone(entity.get('id'))
        self.assertIsNotNone(entity.get('name'))
        if ref:
            self.assertEqual(ref['id'], entity['id'])
            self.assertEqual(ref['name'], entity['name'])
        return entity

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
        self.assertValidDomainListResponse(r, self.domain)

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

    def test_delete_domain(self):
        """DELETE /domains/{domain_id}"""
        self.delete('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id})

    # project crud tests

    def test_list_projects(self):
        """GET /projects"""
        r = self.get('/projects')
        self.assertValidProjectListResponse(r, self.project)

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
        self.assertValidUserListResponse(r, self.user)

    def test_get_user(self):
        """GET /users/{user_id}"""
        r = self.get('/users/%(user_id)s' % {
            'user_id': self.user_id})
        self.assertValidUserResponse(r, self.user)

    def test_add_user_to_group(self):
        """PUT /groups/{group_id}/users/{user_id}"""
        r = self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})

    def test_check_user_in_group(self):
        """HEAD /groups/{group_id}/users/{user_id}"""
        r = self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})
        r = self.head('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})

    def test_list_users_in_group(self):
        """GET /groups/{group_id}/users"""
        r = self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})
        r = self.get('/groups/%(group_id)s/users' % {
            'group_id': self.group_id})
        self.assertValidUserListResponse(r, self.user)

    def test_remove_user_from_group(self):
        """DELETE /groups/{group_id}/users/{user_id}"""
        r = self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})
        r = self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group_id, 'user_id': self.user_id})

    def test_update_user(self):
        """PATCH /users/{user_id}"""
        user = self.new_user_ref(domain_id=self.domain_id)
        del user['id']
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user_id},
            body={'user': user})
        self.assertValidUserResponse(r, user)

    def test_delete_user(self):
        """DELETE /users/{user_id}"""
        self.delete('/users/%(user_id)s' % {
            'user_id': self.user_id})

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
        self.assertValidGroupListResponse(r, self.group)

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
        self.assertValidCredentialListResponse(r, self.credential)

    def test_create_credential(self):
        """POST /credentials"""
        ref = self.new_credential_ref(user_id=self.user_id)
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
            user_id=self.user_id,
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
        self.assertValidRoleListResponse(r, self.role)

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

    def test_create_user_project_grant(self):
        """PUT /projects/{project_id}/users/{user_id}/roles/{role_id}"""
        self.put('/projects/%(project_id)s/users/%(user_id)s/roles/'
                 '%(role_id)s' % {
                 'project_id': self.project_id,
                 'user_id': self.user_id,
                 'role_id': self.role_id})
        self.head('/projects/%(project_id)s/users/%(user_id)s/roles/'
                  '%(role_id)s' % {
                  'project_id': self.project_id,
                  'user_id': self.user_id,
                  'role_id': self.role_id})

    def test_create_group_project_grant(self):
        """PUT /projects/{project_id}/groups/{group_id}/roles/{role_id}"""
        self.put('/projects/%(project_id)s/groups/%(group_id)s/roles/'
                 '%(role_id)s' % {
                 'project_id': self.project_id,
                 'group_id': self.group_id,
                 'role_id': self.role_id})
        self.head('/projects/%(project_id)s/groups/%(group_id)s/roles/'
                  '%(role_id)s' % {
                  'project_id': self.project_id,
                  'group_id': self.group_id,
                  'role_id': self.role_id})

    def test_create_group_domain_grant(self):
        """PUT /domains/{domain_id}/groups/{group_id}/roles/{role_id}"""
        self.put('/domains/%(domain_id)s/groups/%(group_id)s/roles/'
                 '%(role_id)s' % {
                 'domain_id': self.domain_id,
                 'group_id': self.group_id,
                 'role_id': self.role_id})
        self.head('/domains/%(domain_id)s/groups/%(group_id)s/roles/'
                  '%(role_id)s' % {
                  'domain_id': self.domain_id,
                  'group_id': self.group_id,
                  'role_id': self.role_id})

    def test_list_user_project_grants(self):
        """GET /projects/{project_id}/users/{user_id}/roles"""
        self.put('/projects/%(project_id)s/users/%(user_id)s/roles/'
                 '%(role_id)s' % {
                 'project_id': self.project_id,
                 'user_id': self.user_id,
                 'role_id': self.role_id})
        r = self.get('/projects/%(project_id)s/users/%(user_id)s/roles' % {
                     'project_id': self.project_id,
                     'user_id': self.user_id})
        self.assertValidGrantListResponse(r, self.role)

    def test_list_group_project_grants(self):
        """GET /projects/{project_id}/groups/{group_id}/roles"""
        self.put('/projects/%(project_id)s/groups/%(group_id)s/roles/'
                 '%(role_id)s' % {
                 'project_id': self.project_id,
                 'group_id': self.group_id,
                 'role_id': self.role_id})
        r = self.get('/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                     'project_id': self.project_id,
                     'group_id': self.group_id})
        self.assertValidGrantListResponse(r, self.role)

    def test_delete_group_project_grant(self):
        """DELETE /projects/{project_id}/groups/{group_id}/roles/{role_id}"""
        self.put('/projects/%(project_id)s/groups/%(group_id)s/roles/'
                 '%(role_id)s' % {
                 'project_id': self.project_id,
                 'group_id': self.group_id,
                 'role_id': self.role_id})
        self.delete('/projects/%(project_id)s/groups/%(group_id)s/roles/'
                    '%(role_id)s' % {
                    'project_id': self.project_id,
                    'group_id': self.group_id,
                    'role_id': self.role_id})
        r = self.get('/projects/%(project_id)s/groups/%(group_id)s/roles' % {
                     'project_id': self.project_id,
                     'group_id': self.group_id})
        self.assertEquals(len(r.body), 0)
