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

from keystone import auth
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import test

import test_v3


CONF = config.CONF


def _build_auth_scope(project_id=None, project_name=None,
                      project_domain_id=None, project_domain_name=None,
                      domain_id=None, domain_name=None):
    scope_data = {}
    if project_id or project_name:
        scope_data['project'] = {}
        if project_id:
            scope_data['project']['id'] = project_id
        else:
            scope_data['project']['name'] = project_name
            if project_domain_id or project_domain_name:
                project_domain_json = {}
                if project_domain_id:
                    project_domain_json['id'] = project_domain_id
                else:
                    project_domain_json['name'] = project_domain_name
                scope_data['project']['domain'] = project_domain_json
    if domain_id or domain_name:
        scope_data['domain'] = {}
        if domain_id:
            scope_data['domain']['id'] = domain_id
        else:
            scope_data['domain']['name'] = domain_name
    return scope_data


def _build_password_auth(user_id=None, username=None,
                         user_domain_id=None, user_domain_name=None,
                         password=None):
    password_data = {'user': {}}
    if user_id:
        password_data['user']['id'] = user_id
    else:
        password_data['user']['name'] = username
        if user_domain_id or user_domain_name:
            password_data['user']['domain'] = {}
            if user_domain_id:
                password_data['user']['domain']['id'] = user_domain_id
            else:
                password_data['user']['domain']['name'] = user_domain_name
    password_data['user']['password'] = password
    return password_data


def _build_token_auth(token):
    return {'id': token}


def _build_authentication_request(token=None, user_id=None, username=None,
                                  user_domain_id=None, user_domain_name=None,
                                  password=None, project_id=None,
                                  project_name=None, project_domain_id=None,
                                  project_domain_name=None,
                                  domain_id=None, domain_name=None):
    """Build auth dictionary.

    It will create an auth dictionary based on all the arguments
    that it receives.
    """
    auth_data = {}
    auth_data['authentication'] = {'methods': []}
    if token:
        auth_data['authentication']['methods'].append('token')
        auth_data['authentication']['token'] = _build_token_auth(token)
    if user_id or username:
        auth_data['authentication']['methods'].append('password')
        auth_data['authentication']['password'] = _build_password_auth(
            user_id, username, user_domain_id, user_domain_name, password)
    if project_id or project_name or domain_id or domain_name:
        auth_data['scope'] = _build_auth_scope(project_id,
                                               project_name,
                                               project_domain_id,
                                               project_domain_name,
                                               domain_id,
                                               domain_name)
    return auth_data


class AuthTest(test_v3.RestfulTestCase):
    def assertValidTokenResponse(self, r):
        self.assertTrue(r.getheader('X-Subject-Token'))
        token = r.body

        self.assertIn('expires', token)
        self.assertIn('user', token)
        self.assertEqual(self.user['id'], token['user']['id'])
        self.assertEqual(self.user['name'], token['user']['name'])
        self.assertEqual(self.user['domain_id'], token['user']['domain']['id'])

        return token

    def assertValidUnscopedTokenResponse(self, r):
        token = self.assertValidTokenResponse(r)

        self.assertNotIn('roles', token)
        self.assertNotIn('catalog', token)
        self.assertNotIn('project', token)
        self.assertNotIn('domain', token)

        return token

    def assertValidScopedTokenResponse(self, r):
        token = self.assertValidTokenResponse(r)

        self.assertIn('catalog', token)
        self.assertIn('roles', token)
        self.assertTrue(token['roles'])
        for role in token['roles']:
            self.assertIn('id', role)
            self.assertIn('name', role)

        return token

    def assertValidProjectScopedTokenResponse(self, r):
        token = self.assertValidScopedTokenResponse(r)

        self.assertIn('project', token)
        self.assertIn('id', token['project'])
        self.assertIn('name', token['project'])
        self.assertIn('domain', token['project'])
        self.assertIn('id', token['project']['domain'])
        self.assertIn('name', token['project']['domain'])

        self.assertEqual(self.role_id, token['roles'][0]['id'])

        return token

    def assertValidDomainScopedTokenResponse(self, r):
        token = self.assertValidScopedTokenResponse(r)

        self.assertIn('domain', token)
        self.assertIn('id', token['domain'])
        self.assertIn('name', token['domain'])

        return token

    def assertEqualTokens(self, a, b):
        """Assert that two tokens are equal.

        Compare two tokens except for their ids. This also truncates
        the time in the comparison.
        """
        def normalize(token):
            del token['expires']
            del token['issued_at']
            return token

        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['expires']),
            timeutils.parse_isotime(b['expires']))
        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['issued_at']),
            timeutils.parse_isotime(b['issued_at']))
        return self.assertDictEqual(normalize(a), normalize(b))


class TestAuthInfo(test.TestCase):
    def test_missing_auth_methods(self):
        auth_data = {'authentication': {}}
        auth_data['authentication']['token'] = {'id': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_unsupported_auth_method(self):
        auth_data = {'methods': ['abc']}
        auth_data['abc'] = {'test': 'test'}
        auth_data = {'authentication': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_missing_auth_method_data(self):
        auth_data = {'methods': ['password']}
        auth_data = {'authentication': auth_data}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_project_name_no_domain(self):
        auth_data = _build_authentication_request(username='test',
                                                  password='test',
                                                  project_name='abc')
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_both_project_and_domain_in_scope(self):
        auth_data = _build_authentication_request(user_id='test',
                                                  password='test',
                                                  project_name='test',
                                                  domain_name='test')
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)


class TestTokenAPIs(AuthTest):
    def setUp(self):
        super(TestTokenAPIs, self).setUp()
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain_id,
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        self.token_data = resp.body
        self.token = resp.getheader('X-Subject-Token')
        self.headers = {'X-Subject-Token': resp.getheader('X-Subject-Token')}

    def test_default_fixture_scope_token(self):
        self.assertIsNotNone(self.get_scoped_token())

    def test_v3_v2_uuid_token_intermix(self):
        # FIXME(gyee): PKI tokens are not interchangeable because token
        # data is baked into the token itself.
        self.opt_in_group('signing', token_format='UUID')
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token = resp.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET')
        v2_token = resp.body
        self.assertEqual(v2_token['access']['user']['id'],
                         token_data['user']['id'])
        self.assertEqual(v2_token['access']['token']['expires'],
                         token_data['expires'])
        self.assertEqual(v2_token['access']['user']['roles'][0]['id'],
                         token_data['roles'][0]['id'])

    def test_v3_v2_pki_token_intermix(self):
        # FIXME(gyee): PKI tokens are not interchangeable because token
        # data is baked into the token itself.
        self.opt_in_group('signing', token_format='PKI')
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token = resp.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET')
        v2_token = resp.body
        self.assertEqual(v2_token['access']['user']['id'],
                         token_data['user']['id'])
        self.assertEqual(v2_token['access']['token']['expires'],
                         token_data['expires'])
        self.assertEqual(v2_token['access']['user']['roles'][0]['id'],
                         token_data['roles'][0]['id'])

    def test_v2_v3_uuid_token_intermix(self):
        self.opt_in_group('signing', token_format='UUID')
        body = {
            'auth': {
                'passwordCredentials': {
                    'userId': self.user['id'],
                    'password': self.user['password']
                },
                'tenantId': self.project['id']
            }}
        resp = self.admin_request(path='/v2.0/tokens',
                                  method='POST',
                                  body=body)
        v2_token_data = resp.body
        v2_token = v2_token_data['access']['token']['id']
        headers = {'X-Subject-Token': v2_token}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.body
        self.assertEqual(v2_token_data['access']['user']['id'],
                         token_data['user']['id'])
        self.assertEqual(v2_token_data['access']['token']['expires'],
                         token_data['expires'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         token_data['roles'][0]['name'])

    def test_v2_v3_pki_token_intermix(self):
        self.opt_in_group('signing', token_format='PKI')
        body = {
            'auth': {
                'passwordCredentials': {
                    'userId': self.user['id'],
                    'password': self.user['password']
                },
                'tenantId': self.project['id']
            }}
        resp = self.admin_request(path='/v2.0/tokens',
                                  method='POST',
                                  body=body)
        v2_token_data = resp.body
        v2_token = v2_token_data['access']['token']['id']
        headers = {'X-Subject-Token': v2_token}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.body
        self.assertEqual(v2_token_data['access']['user']['id'],
                         token_data['user']['id'])
        self.assertEqual(v2_token_data['access']['token']['expires'],
                         token_data['expires'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         token_data['roles'][0]['name'])

    def test_rescoping_token(self):
        expires = self.token_data['expires']
        auth_data = _build_authentication_request(
            token=self.token,
            project_id=self.project_id)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        # make sure expires stayed the same
        self.assertEqual(expires, r.body['expires'])

    def test_check_token(self):
        self.head('/auth/tokens', headers=self.headers, expected_status=204)

    def test_validate_token(self):
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidUnscopedTokenResponse(r)

    def test_revoke_token(self):
        headers = {'X-Subject-Token': self.get_scoped_token()}
        self.delete('/auth/tokens', headers=headers, expected_status=204)
        self.head('/auth/tokens', headers=headers, expected_status=401)

        # make sure we have a CRL
        r = self.get('/auth/tokens/OS-PKI/revoked')
        self.assertIn('signed', r.body)


class TestAuth(AuthTest):
    def test_unscoped_token_with_user_id(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_id(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_name(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_id(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_id_401(self):
        project_id = uuid.uuid4().hex
        project = self.new_project_ref(domain_id=self.domain_id)
        self.identity_api.create_project(project_id, project)

        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_project_id_scoped_token_with_user_domain_id(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_domain_name(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_domain_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_domain_name(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_domain_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_domain_name(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_token_with_group_role(self):
        group_id = uuid.uuid4().hex
        group = self.new_group_ref(
            domain_id=self.domain_id)
        group['id'] = group_id
        self.identity_api.create_group(group_id, group)

        # add user to group
        self.identity_api.add_user_to_group(self.user['id'], group['id'])

        # grant the domain role to group
        path = '/domains/%s/groups/%s/roles/%s' % (
            self.domain['id'], group['id'], self.role['id'])
        self.put(path=path)

        # now get a domain-scoped token
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_token_with_name(self):
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)
        # now get a domain-scoped token
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_failed(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_auth_with_id(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

        token = r.getheader('X-Subject-Token')
        headers = {'X-Subject-Token': r.getheader('X-Subject-Token')}

        # test token auth
        auth_data = _build_authentication_request(token=token)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_invalid_user_id(self):
        auth_data = _build_authentication_request(
            user_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_user_name(self):
        auth_data = _build_authentication_request(
            username=uuid.uuid4().hex,
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_domain_id(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_domain_name(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            user_domain_name=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_password(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=uuid.uuid4().hex)
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_remote_user(self):
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], self.user['id'])

    def test_remote_user_no_domain(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            password=self.user['password'])
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.ValidationError,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)
