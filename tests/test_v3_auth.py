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

import json
import nose.exc
import uuid


from keystone.common import cms
from keystone import auth
from keystone import config
from keystone import exception
from keystone import test

import test_v3


CONF = config.CONF


def _build_auth_scope(project_id=None, project_name=None,
                      project_domain_id=None, project_domain_name=None,
                      domain_id=None, domain_name=None, trust_id=None):
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
    if trust_id:
        scope_data['trust'] = {}
        scope_data['trust']['id'] = trust_id
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
                                  password=None, **kwargs):
    """Build auth dictionary.

    It will create an auth dictionary based on all the arguments
    that it receives.
    """
    auth_data = {}
    auth_data['identity'] = {'methods': []}
    if token:
        auth_data['identity']['methods'].append('token')
        auth_data['identity']['token'] = _build_token_auth(token)
    if user_id or username:
        auth_data['identity']['methods'].append('password')
        auth_data['identity']['password'] = _build_password_auth(
            user_id, username, user_domain_id, user_domain_name, password)
    if kwargs:
        auth_data['scope'] = _build_auth_scope(**kwargs)
    return {'auth': auth_data}


class TestAuthInfo(test.TestCase):
    def test_missing_auth_methods(self):
        auth_data = {'identity': {}}
        auth_data['identity']['token'] = {'id': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_unsupported_auth_method(self):
        auth_data = {'methods': ['abc']}
        auth_data['abc'] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_missing_auth_method_data(self):
        auth_data = {'methods': ['password']}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_project_name_no_domain(self):
        auth_data = _build_authentication_request(username='test',
                                                  password='test',
                                                  project_name='abc')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_both_project_and_domain_in_scope(self):
        auth_data = _build_authentication_request(user_id='test',
                                                  password='test',
                                                  project_name='test',
                                                  domain_name='test')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)


class TestTokenAPIs(test_v3.RestfulTestCase):
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

    def test_v3_pki_token_id(self):
        self.opt_in_group('signing', token_format='PKI')
        auth_data = _build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token_id = resp.getheader('X-Subject-Token')
        self.assertIn('expires_at', token_data['token'])
        token_signed = cms.cms_sign_token(json.dumps(token_data),
                                          CONF.signing.certfile,
                                          CONF.signing.keyfile)
        self.assertEqual(token_signed, token_id)

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
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token['access']['token']['expires'][:-1],
                      token_data['token']['expires_at'])
        self.assertEqual(v2_token['access']['user']['roles'][0]['id'],
                         token_data['token']['roles'][0]['id'])

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
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token['access']['token']['expires'][-1],
                      token_data['token']['expires_at'])
        self.assertEqual(v2_token['access']['user']['roles'][0]['id'],
                         token_data['token']['roles'][0]['id'])

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
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][-1],
                      token_data['token']['expires_at'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         token_data['token']['roles'][0]['name'])

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
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][-1],
                      token_data['token']['expires_at'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         token_data['token']['roles'][0]['name'])

    def test_rescoping_token(self):
        expires = self.token_data['token']['expires_at']
        auth_data = _build_authentication_request(
            token=self.token,
            project_id=self.project_id)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        # make sure expires stayed the same
        self.assertEqual(expires, r.body['token']['expires_at'])

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


class TestAuthJSON(test_v3.RestfulTestCase):
    content_type = 'json'

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
            password=self.user['password'])['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], self.user['id'])

    def test_remote_user_no_domain(self):
        auth_data = _build_authentication_request(
            username=self.user['name'],
            password=self.user['password'])['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.ValidationError,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)


class TestAuthXML(TestAuthJSON):
    content_type = 'xml'


class TestTrustAuth(test_v3.RestfulTestCase):
    def setUp(self):
        super(TestTrustAuth, self).setUp()

        # create a trustee to delegate stuff to
        self.trustee_user_id = uuid.uuid4().hex
        self.trustee_user = self.new_user_ref(domain_id=self.domain_id)
        self.trustee_user['id'] = self.trustee_user_id
        self.identity_api.create_user(self.trustee_user_id, self.trustee_user)

    def test_create_trust_400(self):
        raise nose.exc.SkipTest('Blocked by bug 1133435')
        self.post('/trusts', body={'trust': {}}, expected_status=400)

    def test_create_unscoped_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id)
        del ref['id']
        r = self.post('/trusts', body={'trust': ref})
        self.assertValidTrustResponse(r, ref)

    def test_trust_crud(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        del ref['id']
        r = self.post('/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        r = self.get(
            '/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        self.assertValidTrustResponse(r, ref)

        # validate roles on the trust
        r = self.get(
            '/trusts/%(trust_id)s/roles' % {
                'trust_id': trust['id']},
            expected_status=200)
        roles = self.assertValidRoleListResponse(r, self.role)
        self.assertIn(self.role['id'], [x['id'] for x in roles])
        self.head(
            '/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            expected_status=204)
        r = self.get(
            '/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            expected_status=200)
        self.assertValidRoleResponse(r, self.role)

        r = self.get('/trusts', expected_status=200)
        self.assertValidTrustListResponse(r, trust)

        # trusts are immutable
        self.patch(
            '/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            body={'trust': ref},
            expected_status=404)

        self.delete(
            '/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=204)

        self.get(
            '/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=404)

    def test_create_trust_trustee_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=uuid.uuid4().hex)
        del ref['id']
        self.post('/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_trustor_trustee_backwards(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=self.user_id)
        del ref['id']
        self.post('/trusts', body={'trust': ref}, expected_status=403)

    def test_create_trust_project_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=uuid.uuid4().hex,
            role_ids=[self.role_id])
        del ref['id']
        self.post('/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_role_id_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[uuid.uuid4().hex])
        del ref['id']
        self.post('/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_role_name_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[uuid.uuid4().hex])
        del ref['id']
        self.post('/trusts', body={'trust': ref}, expected_status=404)

    def test_create_expired_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            expires=dict(seconds=-1),
            role_ids=[self.role_id])
        del ref['id']
        r = self.post('/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        self.get('/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        auth_data = _build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_exercise_trust_scoped_token_without_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = _build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(r, self.trustee_user)
        self.assertEqual(r.body['token']['user']['id'],
                         self.trustee_user['id'])
        self.assertEqual(r.body['token']['user']['name'],
                         self.trustee_user['name'])
        self.assertEqual(r.body['token']['user']['domain']['id'],
                         self.domain['id'])
        self.assertEqual(r.body['token']['user']['domain']['name'],
                         self.domain['name'])
        self.assertEqual(r.body['token']['project']['id'], self.project['id'])
        self.assertEqual(r.body['token']['project']['name'],
                         self.project['name'])

    def test_exercise_trust_scoped_token_with_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = _build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(r, self.user)
        self.assertEqual(r.body['token']['user']['id'], self.user['id'])
        self.assertEqual(r.body['token']['user']['name'], self.user['name'])
        self.assertEqual(r.body['token']['user']['domain']['id'],
                         self.domain['id'])
        self.assertEqual(r.body['token']['user']['domain']['name'],
                         self.domain['name'])
        self.assertEqual(r.body['token']['project']['id'], self.project['id'])
        self.assertEqual(r.body['token']['project']['name'],
                         self.project['name'])

    def test_delete_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        self.delete('/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=204)

        self.get('/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        self.get('/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        auth_data = _build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_list_trusts(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        for i in range(0, 3):
            r = self.post('/trusts', body={'trust': ref})
            trust = self.assertValidTrustResponse(r, ref)

        r = self.get('/trusts?trustor_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.body['trusts']
        self.assertEqual(len(trusts), 3)

        r = self.get('/trusts?trustee_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.body['trusts']
        self.assertEqual(len(trusts), 0)
