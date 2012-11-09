import uuid

import test_v3


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test domains, projects, users, credential & role CRUD"""

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
        if ref:
            pass
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
