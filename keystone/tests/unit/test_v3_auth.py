# Copyright 2012 OpenStack Foundation
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

import copy
import datetime
import json
import operator
import uuid

from keystoneclient.common import cms
import mock
from oslo_config import cfg
from oslo_utils import timeutils
from six.moves import http_client
from six.moves import range
from testtools import matchers
from testtools import testcase

from keystone import auth
from keystone.common import utils
from keystone import exception
from keystone.policy.backends import rules
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3

CONF = cfg.CONF


class TestAuthInfo(test_v3.AuthTestMixin, testcase.TestCase):
    def setUp(self):
        super(TestAuthInfo, self).setUp()
        auth.controllers.load_auth_methods()

    def test_missing_auth_methods(self):
        auth_data = {'identity': {}}
        auth_data['identity']['token'] = {'id': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_unsupported_auth_method(self):
        auth_data = {'methods': ['abc']}
        auth_data['abc'] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_missing_auth_method_data(self):
        auth_data = {'methods': ['password']}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_project_name_no_domain(self):
        auth_data = self.build_authentication_request(
            username='test',
            password='test',
            project_name='abc')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_both_project_and_domain_in_scope(self):
        auth_data = self.build_authentication_request(
            user_id='test',
            password='test',
            project_name='test',
            domain_name='test')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_get_method_names_duplicates(self):
        auth_data = self.build_authentication_request(
            token='test',
            user_id='test',
            password='test')['auth']
        auth_data['identity']['methods'] = ['password', 'token',
                                            'password', 'password']
        context = None
        auth_info = auth.controllers.AuthInfo.create(context, auth_data)
        self.assertEqual(['password', 'token'],
                         auth_info.get_method_names())

    def test_get_method_data_invalid_method(self):
        auth_data = self.build_authentication_request(
            user_id='test',
            password='test')['auth']
        context = None
        auth_info = auth.controllers.AuthInfo.create(context, auth_data)

        method_name = uuid.uuid4().hex
        self.assertRaises(exception.ValidationError,
                          auth_info.get_method_data,
                          method_name)


class TokenAPITests(object):
    # Why is this not just setUp? Because TokenAPITests is not a test class
    # itself. If TokenAPITests became a subclass of the testcase, it would get
    # called by the enumerate-tests-in-file code. The way the functions get
    # resolved in Python for multiple inheritance means that a setUp in this
    # would get skipped by the testrunner.
    def doSetUp(self):
        r = self.v3_authenticate_token(self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain_id,
            password=self.user['password']))
        self.v3_token_data = r.result
        self.v3_token = r.headers.get('X-Subject-Token')
        self.headers = {'X-Subject-Token': r.headers.get('X-Subject-Token')}

    def test_default_fixture_scope_token(self):
        self.assertIsNotNone(self.get_scoped_token())

    def test_v3_v2_intermix_non_default_domain_failed(self):
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password']))

        # now validate the v3 token with v2 API
        self.admin_request(
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            method='GET',
            expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_new_default_domain(self):
        # If the default_domain_id config option is changed, then should be
        # able to validate a v3 token with user in the new domain.

        # 1) Create a new domain for the user.
        new_domain = {
            'description': uuid.uuid4().hex,
            'enabled': True,
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
        }
        self.resource_api.create_domain(new_domain['id'], new_domain)

        # 2) Create user in new domain.
        new_user_password = uuid.uuid4().hex
        new_user = {
            'name': uuid.uuid4().hex,
            'domain_id': new_domain['id'],
            'password': new_user_password,
            'email': uuid.uuid4().hex,
        }
        new_user = self.identity_api.create_user(new_user)

        # 3) Update the default_domain_id config option to the new domain
        self.config_fixture.config(
            group='identity',
            default_domain_id=new_domain['id'])

        # 4) Get a token using v3 API.
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=new_user['id'],
            password=new_user_password))

        # 5) Validate token using v2 API.
        self.admin_request(
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            method='GET')

    def test_v3_v2_intermix_domain_scoped_token_failed(self):
        # grant the domain role to user
        self.put(
            path='/domains/%s/users/%s/roles/%s' % (
                self.domain['id'], self.user['id'], self.role['id']))

        # generate a domain-scoped v3 token
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id']))

        # domain-scoped tokens are not supported by v2
        self.admin_request(
            method='GET',
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_non_default_project_failed(self):
        # self.project is in a non-default domain
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.project['id']))

        # v2 cannot reference projects outside the default domain
        self.admin_request(
            method='GET',
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_non_default_user_failed(self):
        self.assignment_api.create_grant(
            self.role['id'],
            user_id=self.user['id'],
            project_id=self.default_domain_project['id'])

        # self.user is in a non-default domain
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.default_domain_project['id']))

        # v2 cannot reference projects outside the default domain
        self.admin_request(
            method='GET',
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_domain_scope_failed(self):
        self.assignment_api.create_grant(
            self.role['id'],
            user_id=self.default_domain_user['id'],
            domain_id=self.domain['id'])

        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            domain_id=self.domain['id']))

        # v2 cannot reference projects outside the default domain
        self.admin_request(
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            method='GET',
            expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_unscoped_token_intermix(self):
        r = self.v3_authenticate_token(self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password']))
        self.assertValidUnscopedTokenResponse(r)
        v3_token_data = r.result
        v3_token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        r = self.admin_request(
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token,
            method='GET')
        v2_token_data = r.result

        self.assertEqual(v2_token_data['access']['user']['id'],
                         v3_token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][:-1],
                      v3_token_data['token']['expires_at'])

    def test_v3_v2_token_intermix(self):
        # FIXME(gyee): PKI tokens are not interchangeable because token
        # data is baked into the token itself.
        r = self.v3_authenticate_token(self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id']))
        self.assertValidProjectScopedTokenResponse(r)
        v3_token_data = r.result
        v3_token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        r = self.admin_request(
            method='GET',
            path='/v2.0/tokens/%s' % v3_token,
            token=CONF.admin_token)
        v2_token_data = r.result

        self.assertEqual(v2_token_data['access']['user']['id'],
                         v3_token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][:-1],
                      v3_token_data['token']['expires_at'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         v3_token_data['token']['roles'][0]['name'])

    def test_v2_v3_unscoped_token_intermix(self):
        r = self.admin_request(
            method='POST',
            path='/v2.0/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'userId': self.default_domain_user['id'],
                        'password': self.default_domain_user['password']
                    }
                }
            })
        v2_token_data = r.result
        v2_token = v2_token_data['access']['token']['id']

        r = self.get('/auth/tokens', headers={'X-Subject-Token': v2_token})
        # FIXME(dolph): Due to bug 1476329, v2 tokens validated on v3 are
        # missing timezones, so they will not pass this assertion.
        # self.assertValidUnscopedTokenResponse(r)
        v3_token_data = r.result

        self.assertEqual(v2_token_data['access']['user']['id'],
                         v3_token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][-1],
                      v3_token_data['token']['expires_at'])

    def test_v2_v3_token_intermix(self):
        r = self.admin_request(
            path='/v2.0/tokens',
            method='POST',
            body={
                'auth': {
                    'passwordCredentials': {
                        'userId': self.default_domain_user['id'],
                        'password': self.default_domain_user['password']
                    },
                    'tenantId': self.default_domain_project['id']
                }
            })
        v2_token_data = r.result
        v2_token = v2_token_data['access']['token']['id']

        r = self.get('/auth/tokens', headers={'X-Subject-Token': v2_token})
        # FIXME(dolph): Due to bug 1476329, v2 tokens validated on v3 are
        # missing timezones, so they will not pass this assertion.
        # self.assertValidProjectScopedTokenResponse(r)
        v3_token_data = r.result

        self.assertEqual(v2_token_data['access']['user']['id'],
                         v3_token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][-1],
                      v3_token_data['token']['expires_at'])
        self.assertEqual(v2_token_data['access']['user']['roles'][0]['name'],
                         v3_token_data['token']['roles'][0]['name'])

        v2_issued_at = timeutils.parse_isotime(
            v2_token_data['access']['token']['issued_at'])
        v3_issued_at = timeutils.parse_isotime(
            v3_token_data['token']['issued_at'])

        self.assertEqual(v2_issued_at, v3_issued_at)

    def test_v2_token_deleted_on_v3(self):
        # Create a v2 token.
        body = {
            'auth': {
                'passwordCredentials': {
                    'userId': self.default_domain_user['id'],
                    'password': self.default_domain_user['password']
                },
                'tenantId': self.default_domain_project['id']
            }
        }
        r = self.admin_request(
            path='/v2.0/tokens', method='POST', body=body)
        v2_token = r.result['access']['token']['id']

        # Delete the v2 token using v3.
        resp = self.delete(
            '/auth/tokens', headers={'X-Subject-Token': v2_token})
        self.assertEqual(resp.status_code, 204)

        # Attempting to use the deleted token on v2 should fail.
        self.admin_request(
            path='/v2.0/tenants', method='GET', token=v2_token,
            expected_status=http_client.UNAUTHORIZED)

    def test_rescoping_token(self):
        expires = self.v3_token_data['token']['expires_at']

        # rescope the token
        r = self.v3_authenticate_token(self.build_authentication_request(
            token=self.v3_token,
            project_id=self.project_id))
        self.assertValidProjectScopedTokenResponse(r)

        # ensure token expiration stayed the same
        self.assertEqual(expires, r.result['token']['expires_at'])

    def test_check_token(self):
        self.head('/auth/tokens', headers=self.headers, expected_status=200)

    def test_validate_token(self):
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_token_nocatalog(self):
        v3_token = self.get_requested_token(self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id']))
        r = self.get(
            '/auth/tokens?nocatalog',
            headers={'X-Subject-Token': v3_token})
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)


class AllowRescopeScopedTokenDisabledTests(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(AllowRescopeScopedTokenDisabledTests, self).config_overrides()
        self.config_fixture.config(
            group='token',
            allow_rescope_scoped_token=False)

    def test_rescoping_v3_to_v3_disabled(self):
        self.v3_authenticate_token(
            self.build_authentication_request(
                token=self.get_scoped_token(),
                project_id=self.project_id),
            expected_status=http_client.FORBIDDEN)

    def _v2_token(self):
        body = {
            'auth': {
                "tenantId": self.default_domain_project['id'],
                'passwordCredentials': {
                    'userId': self.default_domain_user['id'],
                    'password': self.default_domain_user['password']
                }
            }}
        resp = self.admin_request(path='/v2.0/tokens',
                                  method='POST',
                                  body=body)
        v2_token_data = resp.result
        return v2_token_data

    def _v2_token_from_token(self, token):
        body = {
            'auth': {
                "tenantId": self.project['id'],
                "token": token
            }}
        self.admin_request(path='/v2.0/tokens',
                           method='POST',
                           body=body,
                           expected_status=http_client.FORBIDDEN)

    def test_rescoping_v2_to_v3_disabled(self):
        token = self._v2_token()
        self.v3_authenticate_token(
            self.build_authentication_request(
                token=token['access']['token']['id'],
                project_id=self.project_id),
            expected_status=http_client.FORBIDDEN)

    def test_rescoping_v3_to_v2_disabled(self):
        token = {'id': self.get_scoped_token()}
        self._v2_token_from_token(token)

    def test_rescoping_v2_to_v2_disabled(self):
        token = self._v2_token()
        self._v2_token_from_token(token['access']['token'])

    def test_rescoped_domain_token_disabled(self):

        self.domainA = self.new_domain_ref()
        self.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domainA['id'])
        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password']))
        # Get a domain-scoped token from the unscoped token
        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                domain_id=self.domainA['id']))
        self.v3_authenticate_token(
            self.build_authentication_request(
                token=domain_scoped_token,
                project_id=self.project_id),
            expected_status=http_client.FORBIDDEN)


class TestPKITokenAPIs(test_v3.RestfulTestCase, TokenAPITests):
    def config_overrides(self):
        super(TestPKITokenAPIs, self).config_overrides()
        self.config_fixture.config(group='token', provider='pki')

    def setUp(self):
        super(TestPKITokenAPIs, self).setUp()
        self.doSetUp()

    def verify_token(self, *args, **kwargs):
        return cms.verify_token(*args, **kwargs)

    def test_v3_token_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.v3_authenticate_token(auth_data)
        token_data = resp.result
        token_id = resp.headers.get('X-Subject-Token')
        self.assertIn('expires_at', token_data['token'])

        decoded_token = self.verify_token(token_id, CONF.signing.certfile,
                                          CONF.signing.ca_certs)
        decoded_token_dict = json.loads(decoded_token)

        token_resp_dict = json.loads(resp.body)

        self.assertEqual(decoded_token_dict, token_resp_dict)
        # should be able to validate hash PKI token as well
        hash_token_id = cms.cms_hash_token(token_id)
        headers = {'X-Subject-Token': hash_token_id}
        resp = self.get('/auth/tokens', headers=headers)
        expected_token_data = resp.result
        self.assertDictEqual(expected_token_data, token_data)

    def test_v3_v2_hashed_pki_token_intermix(self):
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id'])
        resp = self.v3_authenticate_token(auth_data)
        token_data = resp.result
        token = resp.headers.get('X-Subject-Token')

        # should be able to validate a hash PKI token in v2 too
        token = cms.cms_hash_token(token)
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token=CONF.admin_token,
                                  method='GET')
        v2_token = resp.result
        self.assertEqual(v2_token['access']['user']['id'],
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token['access']['token']['expires'][:-1],
                      token_data['token']['expires_at'])
        self.assertEqual(v2_token['access']['user']['roles'][0]['id'],
                         token_data['token']['roles'][0]['id'])


class TestPKIZTokenAPIs(TestPKITokenAPIs):
    def config_overrides(self):
        super(TestPKIZTokenAPIs, self).config_overrides()
        self.config_fixture.config(group='token', provider='pkiz')

    def verify_token(self, *args, **kwargs):
        return cms.pkiz_verify(*args, **kwargs)


class TestUUIDTokenAPIs(test_v3.RestfulTestCase, TokenAPITests):
    def config_overrides(self):
        super(TestUUIDTokenAPIs, self).config_overrides()
        self.config_fixture.config(group='token', provider='uuid')

    def setUp(self):
        super(TestUUIDTokenAPIs, self).setUp()
        self.doSetUp()

    def test_v3_token_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.v3_authenticate_token(auth_data)
        token_data = resp.result
        token_id = resp.headers.get('X-Subject-Token')
        self.assertIn('expires_at', token_data['token'])
        self.assertFalse(cms.is_asn1_token(token_id))


class TestFernetTokenAPIs(test_v3.RestfulTestCase, TokenAPITests):
    def config_overrides(self):
        super(TestFernetTokenAPIs, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

    def setUp(self):
        super(TestFernetTokenAPIs, self).setUp()
        self.doSetUp()


class TestTokenRevokeSelfAndAdmin(test_v3.RestfulTestCase):
    """Test token revoke using v3 Identity API by token owner and admin."""

    def load_sample_data(self):
        """Load Sample Data for Test Cases.

        Two domains, domainA and domainB
        Two users in domainA, userNormalA and userAdminA
        One user in domainB, userAdminB

        """
        super(TestTokenRevokeSelfAndAdmin, self).load_sample_data()
        # DomainA setup
        self.domainA = self.new_domain_ref()
        self.resource_api.create_domain(self.domainA['id'], self.domainA)

        self.userAdminA = self.new_user_ref(domain_id=self.domainA['id'])
        password = self.userAdminA['password']
        self.userAdminA = self.identity_api.create_user(self.userAdminA)
        self.userAdminA['password'] = password

        self.userNormalA = self.new_user_ref(
            domain_id=self.domainA['id'])
        password = self.userNormalA['password']
        self.userNormalA = self.identity_api.create_user(self.userNormalA)
        self.userNormalA['password'] = password

        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.userAdminA['id'],
                                         domain_id=self.domainA['id'])

    def config_overrides(self):
        super(TestTokenRevokeSelfAndAdmin, self).config_overrides()
        self.config_fixture.config(
            group='oslo_policy',
            policy_file=unit.dirs.etc('policy.v3cloudsample.json'))

    def test_user_revokes_own_token(self):
        user_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userNormalA['id'],
                password=self.userNormalA['password'],
                user_domain_id=self.domainA['id']))
        self.assertNotEmpty(user_token)
        headers = {'X-Subject-Token': user_token}

        adminA_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userAdminA['id'],
                password=self.userAdminA['password'],
                domain_name=self.domainA['name']))

        self.head('/auth/tokens', headers=headers, expected_status=200,
                  token=adminA_token)
        self.head('/auth/tokens', headers=headers, expected_status=200,
                  token=user_token)
        self.delete('/auth/tokens', headers=headers, expected_status=204,
                    token=user_token)
        # invalid X-Auth-Token and invalid X-Subject-Token
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.UNAUTHORIZED,
                  token=user_token)
        # invalid X-Auth-Token and invalid X-Subject-Token
        self.delete('/auth/tokens', headers=headers,
                    expected_status=http_client.UNAUTHORIZED,
                    token=user_token)
        # valid X-Auth-Token and invalid X-Subject-Token
        self.delete('/auth/tokens', headers=headers,
                    expected_status=http_client.NOT_FOUND,
                    token=adminA_token)
        # valid X-Auth-Token and invalid X-Subject-Token
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND,
                  token=adminA_token)

    def test_adminA_revokes_userA_token(self):
        user_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userNormalA['id'],
                password=self.userNormalA['password'],
                user_domain_id=self.domainA['id']))
        self.assertNotEmpty(user_token)
        headers = {'X-Subject-Token': user_token}

        adminA_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userAdminA['id'],
                password=self.userAdminA['password'],
                domain_name=self.domainA['name']))

        self.head('/auth/tokens', headers=headers, expected_status=200,
                  token=adminA_token)
        self.head('/auth/tokens', headers=headers, expected_status=200,
                  token=user_token)
        self.delete('/auth/tokens', headers=headers, expected_status=204,
                    token=adminA_token)
        # invalid X-Auth-Token and invalid X-Subject-Token
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.UNAUTHORIZED,
                  token=user_token)
        # valid X-Auth-Token and invalid X-Subject-Token
        self.delete('/auth/tokens', headers=headers,
                    expected_status=http_client.NOT_FOUND,
                    token=adminA_token)
        # valid X-Auth-Token and invalid X-Subject-Token
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND,
                  token=adminA_token)

    def test_adminB_fails_revoking_userA_token(self):
        # DomainB setup
        self.domainB = self.new_domain_ref()
        self.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.userAdminB = self.new_user_ref(domain_id=self.domainB['id'])
        password = self.userAdminB['password']
        self.userAdminB = self.identity_api.create_user(self.userAdminB)
        self.userAdminB['password'] = password
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.userAdminB['id'],
                                         domain_id=self.domainB['id'])

        user_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userNormalA['id'],
                password=self.userNormalA['password'],
                user_domain_id=self.domainA['id']))
        headers = {'X-Subject-Token': user_token}

        adminB_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.userAdminB['id'],
                password=self.userAdminB['password'],
                domain_name=self.domainB['name']))

        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.FORBIDDEN,
                  token=adminB_token)
        self.delete('/auth/tokens', headers=headers,
                    expected_status=http_client.FORBIDDEN,
                    token=adminB_token)


class TestTokenRevokeById(test_v3.RestfulTestCase):
    """Test token revocation on the v3 Identity API."""

    def config_overrides(self):
        super(TestTokenRevokeById, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)

    def setUp(self):
        """Setup for Token Revoking Test Cases.

        As well as the usual housekeeping, create a set of domains,
        users, groups, roles and projects for the subsequent tests:

        - Two domains: A & B
        - Three users (1, 2 and 3)
        - Three groups (1, 2 and 3)
        - Two roles (1 and 2)
        - DomainA owns user1, domainB owns user2 and user3
        - DomainA owns group1 and group2, domainB owns group3
        - User1 and user2 are members of group1
        - User3 is a member of group2
        - Two projects: A & B, both in domainA
        - Group1 has role1 on Project A and B, meaning that user1 and user2
          will get these roles by virtue of membership
        - User1, 2 and 3 have role1 assigned to projectA
        - Group1 has role1 on Project A and B, meaning that user1 and user2
          will get role1 (duplicated) by virtue of membership
        - User1 has role2 assigned to domainA

        """
        super(TestTokenRevokeById, self).setUp()

        # Start by creating a couple of domains and projects
        self.domainA = self.new_domain_ref()
        self.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = self.new_domain_ref()
        self.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.projectA = self.new_project_ref(domain_id=self.domainA['id'])
        self.resource_api.create_project(self.projectA['id'], self.projectA)
        self.projectB = self.new_project_ref(domain_id=self.domainA['id'])
        self.resource_api.create_project(self.projectB['id'], self.projectB)

        # Now create some users
        self.user1 = self.new_user_ref(
            domain_id=self.domainA['id'])
        password = self.user1['password']
        self.user1 = self.identity_api.create_user(self.user1)
        self.user1['password'] = password

        self.user2 = self.new_user_ref(
            domain_id=self.domainB['id'])
        password = self.user2['password']
        self.user2 = self.identity_api.create_user(self.user2)
        self.user2['password'] = password

        self.user3 = self.new_user_ref(
            domain_id=self.domainB['id'])
        password = self.user3['password']
        self.user3 = self.identity_api.create_user(self.user3)
        self.user3['password'] = password

        self.group1 = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.group1 = self.identity_api.create_group(self.group1)

        self.group2 = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.group2 = self.identity_api.create_group(self.group2)

        self.group3 = self.new_group_ref(
            domain_id=self.domainB['id'])
        self.group3 = self.identity_api.create_group(self.group3)

        self.identity_api.add_user_to_group(self.user1['id'],
                                            self.group1['id'])
        self.identity_api.add_user_to_group(self.user2['id'],
                                            self.group1['id'])
        self.identity_api.add_user_to_group(self.user3['id'],
                                            self.group2['id'])

        self.role1 = self.new_role_ref()
        self.role_api.create_role(self.role1['id'], self.role1)
        self.role2 = self.new_role_ref()
        self.role_api.create_role(self.role2['id'], self.role2)

        self.assignment_api.create_grant(self.role2['id'],
                                         user_id=self.user1['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user1['id'],
                                         project_id=self.projectA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user2['id'],
                                         project_id=self.projectA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user3['id'],
                                         project_id=self.projectA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         group_id=self.group1['id'],
                                         project_id=self.projectA['id'])

    def test_unscoped_token_remains_valid_after_role_assignment(self):
        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password']))

        scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                project_id=self.projectA['id']))

        # confirm both tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=200)

        # create a new role
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)

        # assign a new role
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': role['id']})

        # both tokens should remain valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=200)

    def test_deleting_user_grant_revokes_token(self):
        """Test deleting a user grant revokes token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Delete the grant user1 has on ProjectA
        - Check token is no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)
        # Delete the grant, which should invalidate the token
        grant_url = (
            '/projects/%(project_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        self.delete(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.NOT_FOUND)

    def role_data_fixtures(self):
        self.projectC = self.new_project_ref(domain_id=self.domainA['id'])
        self.resource_api.create_project(self.projectC['id'], self.projectC)
        self.user4 = self.new_user_ref(domain_id=self.domainB['id'])
        password = self.user4['password']
        self.user4 = self.identity_api.create_user(self.user4)
        self.user4['password'] = password
        self.user5 = self.new_user_ref(
            domain_id=self.domainA['id'])
        password = self.user5['password']
        self.user5 = self.identity_api.create_user(self.user5)
        self.user5['password'] = password
        self.user6 = self.new_user_ref(
            domain_id=self.domainA['id'])
        password = self.user6['password']
        self.user6 = self.identity_api.create_user(self.user6)
        self.user6['password'] = password
        self.identity_api.add_user_to_group(self.user5['id'],
                                            self.group1['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         group_id=self.group1['id'],
                                         project_id=self.projectB['id'])
        self.assignment_api.create_grant(self.role2['id'],
                                         user_id=self.user4['id'],
                                         project_id=self.projectC['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user6['id'],
                                         project_id=self.projectA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user6['id'],
                                         domain_id=self.domainA['id'])

    def test_deleting_role_revokes_token(self):
        """Test deleting a role revokes token.

            Add some additional test data, namely:
             - A third project (project C)
             - Three additional users - user4 owned by domainB and user5 and 6
               owned by domainA (different domain ownership should not affect
               the test results, just provided to broaden test coverage)
             - User5 is a member of group1
             - Group1 gets an additional assignment - role1 on projectB as
               well as its existing role1 on projectA
             - User4 has role2 on Project C
             - User6 has role1 on projectA and domainA
             - This allows us to create 5 tokens by virtue of different types
               of role assignment:
               - user1, scoped to ProjectA by virtue of user role1 assignment
               - user5, scoped to ProjectB by virtue of group role1 assignment
               - user4, scoped to ProjectC by virtue of user role2 assignment
               - user6, scoped to ProjectA by virtue of user role1 assignment
               - user6, scoped to DomainA by virtue of user role1 assignment
             - role1 is then deleted
             - Check the tokens on Project A and B, and DomainA are revoked,
               but not the one for Project C

        """

        self.role_data_fixtures()

        # Now we are ready to start issuing requests
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        tokenA = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user5['id'],
            password=self.user5['password'],
            project_id=self.projectB['id'])
        tokenB = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user4['id'],
            password=self.user4['password'],
            project_id=self.projectC['id'])
        tokenC = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            project_id=self.projectA['id'])
        tokenD = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            domain_id=self.domainA['id'])
        tokenE = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=200)

        # Delete the role, which should invalidate the tokens
        role_url = '/roles/%s' % self.role1['id']
        self.delete(role_url)

        # Check the tokens that used role1 is invalid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=http_client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=http_client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=http_client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=http_client.NOT_FOUND)

        # ...but the one using role2 is still valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=200)

    def test_domain_user_role_assignment_maintains_token(self):
        """Test user-domain role assignment maintains existing token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Create a grant for user1 on DomainB
        - Check token is still valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)
        # Assign a role, which should not affect the token
        grant_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': self.domainB['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        self.put(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

    def test_disabling_project_revokes_token(self):
        token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

        # disable the project, which should invalidate the token
        self.patch(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']},
            body={'project': {'enabled': False}})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.NOT_FOUND)
        self.v3_authenticate_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
            expected_status=http_client.UNAUTHORIZED)

    def test_deleting_project_revokes_token(self):
        token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

        # delete the project, which should invalidate the token
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.NOT_FOUND)
        self.v3_authenticate_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
            expected_status=http_client.UNAUTHORIZED)

    def test_deleting_group_grant_revokes_tokens(self):
        """Test deleting a group grant revokes tokens.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Get a token for user2, scoped to ProjectA
        - Get a token for user3, scoped to ProjectA
        - Delete the grant group1 has on ProjectA
        - Check tokens for user1 & user2 are no longer valid,
          since user1 and user2 are members of group1
        - Check token for user3 is invalid too

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token1 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        token2 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user3['id'],
            password=self.user3['password'],
            project_id=self.projectA['id'])
        token3 = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=200)
        # Delete the group grant, which should invalidate the
        # tokens for user1 and user2
        grant_url = (
            '/projects/%(project_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'group_id': self.group1['id'],
                'role_id': self.role1['id']})
        self.delete(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=http_client.NOT_FOUND)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=http_client.NOT_FOUND)
        # But user3's token should be invalid too as revocation is done for
        # scope role & project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=http_client.NOT_FOUND)

    def test_domain_group_role_assignment_maintains_token(self):
        """Test domain-group role assignment maintains existing token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Create a grant for group1 on DomainB
        - Check token is still longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)
        # Delete the grant, which should invalidate the token
        grant_url = (
            '/domains/%(domain_id)s/groups/%(group_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': self.domainB['id'],
                'group_id': self.group1['id'],
                'role_id': self.role1['id']})
        self.put(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

    def test_group_membership_changes_revokes_token(self):
        """Test add/removal to/from group revokes token.

        Test Plan:

        - Get a token for user1, scoped to ProjectA
        - Get a token for user2, scoped to ProjectA
        - Remove user1 from group1
        - Check token for user1 is no longer valid
        - Check token for user2 is still valid, even though
          user2 is also part of group1
        - Add user2 to group2
        - Check token for user2 is now no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        token1 = self.get_requested_token(auth_data)
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        token2 = self.get_requested_token(auth_data)
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=200)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=200)
        # Remove user1 from group1, which should invalidate
        # the token
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group1['id'],
            'user_id': self.user1['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=http_client.NOT_FOUND)
        # But user2's token should still be valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=200)
        # Adding user2 to a group should not invalidate token
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group2['id'],
            'user_id': self.user2['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=200)

    def test_removing_role_assignment_does_not_affect_other_users(self):
        """Revoking a role from one user should not affect other users."""

        # This group grant is not needed for the test
        self.delete(
            '/projects/%(project_id)s/groups/%(group_id)s/roles/%(role_id)s' %
            {'project_id': self.projectA['id'],
             'group_id': self.group1['id'],
             'role_id': self.role1['id']})

        user1_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']))

        user3_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

        # delete relationships between user1 and projectA from setUp
        self.delete(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        # authorization for the first user should now fail
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': user1_token},
                  expected_status=http_client.NOT_FOUND)
        self.v3_authenticate_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']),
            expected_status=http_client.UNAUTHORIZED)

        # authorization for the second user should still succeed
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': user3_token},
                  expected_status=200)
        self.v3_authenticate_token(
            self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))

    def test_deleting_project_deletes_grants(self):
        # This is to make it a little bit more pretty with PEP8
        role_path = ('/projects/%(project_id)s/users/%(user_id)s/'
                     'roles/%(role_id)s')
        role_path = role_path % {'user_id': self.user['id'],
                                 'project_id': self.projectA['id'],
                                 'role_id': self.role['id']}

        # grant the user a role on the project
        self.put(role_path)

        # delete the project, which should remove the roles
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})

        # Make sure that we get a NotFound(404) when heading that role.
        self.head(role_path, expected_status=http_client.NOT_FOUND)

    def get_v2_token(self, token=None, project_id=None):
        body = {'auth': {}, }

        if token:
            body['auth']['token'] = {
                'id': token
            }
        else:
            body['auth']['passwordCredentials'] = {
                'username': self.default_domain_user['name'],
                'password': self.default_domain_user['password'],
            }

        if project_id:
            body['auth']['tenantId'] = project_id

        r = self.admin_request(method='POST', path='/v2.0/tokens', body=body)
        return r.json_body['access']['token']['id']

    def test_revoke_v2_token_no_check(self):
        # Test that a V2 token can be revoked without validating it first.

        token = self.get_v2_token()

        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': token},
                    expected_status=204)

        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.NOT_FOUND)

    def test_revoke_token_from_token(self):
        # Test that a scoped token can be requested from an unscoped token,
        # the scoped token can be revoked, and the unscoped token remains
        # valid.

        unscoped_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password']))

        # Get a project-scoped token from the unscoped token
        project_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                project_id=self.projectA['id']))

        # Get a domain-scoped token from the unscoped token
        domain_scoped_token = self.get_requested_token(
            self.build_authentication_request(
                token=unscoped_token,
                domain_id=self.domainA['id']))

        # revoke the project-scoped token.
        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': project_scoped_token},
                    expected_status=204)

        # The project-scoped token is invalidated.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': project_scoped_token},
                  expected_status=http_client.NOT_FOUND)

        # The unscoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=200)

        # The domain-scoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': domain_scoped_token},
                  expected_status=200)

        # revoke the domain-scoped token.
        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': domain_scoped_token},
                    expected_status=204)

        # The domain-scoped token is invalid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': domain_scoped_token},
                  expected_status=http_client.NOT_FOUND)

        # The unscoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=200)

    def test_revoke_token_from_token_v2(self):
        # Test that a scoped token can be requested from an unscoped token,
        # the scoped token can be revoked, and the unscoped token remains
        # valid.

        # FIXME(blk-u): This isn't working correctly. The scoped token should
        # be revoked. See bug 1347318.

        unscoped_token = self.get_v2_token()

        # Get a project-scoped token from the unscoped token
        project_scoped_token = self.get_v2_token(
            token=unscoped_token, project_id=self.default_domain_project['id'])

        # revoke the project-scoped token.
        self.delete('/auth/tokens',
                    headers={'X-Subject-Token': project_scoped_token},
                    expected_status=204)

        # The project-scoped token is invalidated.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': project_scoped_token},
                  expected_status=http_client.NOT_FOUND)

        # The unscoped token should still be valid.
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=200)


class TestTokenRevokeByAssignment(TestTokenRevokeById):

    def config_overrides(self):
        super(TestTokenRevokeById, self).config_overrides()
        self.config_fixture.config(
            group='revoke',
            driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='uuid',
            revoke_by_id=True)

    def test_removing_role_assignment_keeps_other_project_token_groups(self):
        """Test assignment isolation.

        Revoking a group role from one project should not invalidate all group
        users' tokens
        """
        self.assignment_api.create_grant(self.role1['id'],
                                         group_id=self.group1['id'],
                                         project_id=self.projectB['id'])

        project_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectB['id']))

        other_project_token = self.get_requested_token(
            self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']))

        self.assignment_api.delete_grant(self.role1['id'],
                                         group_id=self.group1['id'],
                                         project_id=self.projectB['id'])

        # authorization for the projectA should still succeed
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': other_project_token},
                  expected_status=200)
        # while token for the projectB should not
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': project_token},
                  expected_status=http_client.NOT_FOUND)
        revoked_tokens = [
            t['id'] for t in self.token_provider_api.list_revoked_tokens()]
        # token is in token revocation list
        self.assertIn(project_token, revoked_tokens)


class TestTokenRevokeApi(TestTokenRevokeById):
    EXTENSION_NAME = 'revoke'
    EXTENSION_TO_ADD = 'revoke_extension'

    """Test token revocation on the v3 Identity API."""
    def config_overrides(self):
        super(TestTokenRevokeApi, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)

    def assertValidDeletedProjectResponse(self, events_response, project_id):
        events = events_response['events']
        self.assertEqual(1, len(events))
        self.assertEqual(project_id, events[0]['project_id'])
        self.assertIsNotNone(events[0]['issued_before'])
        self.assertIsNotNone(events_response['links'])
        del (events_response['events'][0]['issued_before'])
        del (events_response['links'])
        expected_response = {'events': [{'project_id': project_id}]}
        self.assertEqual(expected_response, events_response)

    def assertDomainInList(self, events_response, domain_id):
        events = events_response['events']
        self.assertEqual(1, len(events))
        self.assertEqual(domain_id, events[0]['domain_id'])
        self.assertIsNotNone(events[0]['issued_before'])
        self.assertIsNotNone(events_response['links'])
        del (events_response['events'][0]['issued_before'])
        del (events_response['links'])
        expected_response = {'events': [{'domain_id': domain_id}]}
        self.assertEqual(expected_response, events_response)

    def assertValidRevokedTokenResponse(self, events_response, **kwargs):
        events = events_response['events']
        self.assertEqual(1, len(events))
        for k, v in kwargs.items():
            self.assertEqual(v, events[0].get(k))
        self.assertIsNotNone(events[0]['issued_before'])
        self.assertIsNotNone(events_response['links'])
        del (events_response['events'][0]['issued_before'])
        del (events_response['links'])

        expected_response = {'events': [kwargs]}
        self.assertEqual(expected_response, events_response)

    def test_revoke_token(self):
        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        response = self.get('/auth/tokens', headers=headers,
                            expected_status=200).json_body['token']

        self.delete('/auth/tokens', headers=headers, expected_status=204)
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND)
        events_response = self.get('/OS-REVOKE/events',
                                   expected_status=200).json_body
        self.assertValidRevokedTokenResponse(events_response,
                                             audit_id=response['audit_ids'][0])

    def test_revoke_v2_token(self):
        token = self.get_v2_token()
        headers = {'X-Subject-Token': token}
        response = self.get('/auth/tokens', headers=headers,
                            expected_status=200).json_body['token']
        self.delete('/auth/tokens', headers=headers, expected_status=204)
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND)
        events_response = self.get('/OS-REVOKE/events',
                                   expected_status=200).json_body

        self.assertValidRevokedTokenResponse(
            events_response,
            audit_id=response['audit_ids'][0])

    def test_revoke_by_id_false_410(self):
        self.get('/auth/tokens/OS-PKI/revoked',
                 expected_status=http_client.GONE)

    def test_list_delete_project_shows_in_event_list(self):
        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body['events']
        self.assertEqual([], events)
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})
        events_response = self.get('/OS-REVOKE/events',
                                   expected_status=200).json_body

        self.assertValidDeletedProjectResponse(events_response,
                                               self.projectA['id'])

    def test_disable_domain_shows_in_event_list(self):
        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body['events']
        self.assertEqual([], events)
        disable_body = {'domain': {'enabled': False}}
        self.patch(
            '/domains/%(project_id)s' % {'project_id': self.domainA['id']},
            body=disable_body)

        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body

        self.assertDomainInList(events, self.domainA['id'])

    def assertEventDataInList(self, events, **kwargs):
        found = False
        for e in events:
            for key, value in kwargs.items():
                try:
                    if e[key] != value:
                        break
                except KeyError:
                    # Break the loop and present a nice error instead of
                    # KeyError
                    break
            else:
                # If the value of the event[key] matches the value of the kwarg
                # for each item in kwargs, the event was fully matched and
                # the assertTrue below should succeed.
                found = True
        self.assertTrue(found,
                        'event with correct values not in list, expected to '
                        'find event with key-value pairs. Expected: '
                        '"%(expected)s" Events: "%(events)s"' %
                        {'expected': ','.join(
                            ["'%s=%s'" % (k, v) for k, v in kwargs.items()]),
                         'events': events})

    def test_list_delete_token_shows_in_event_list(self):
        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body['events']
        self.assertEqual([], events)

        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        auth_req = self.build_authentication_request(token=scoped_token)
        response = self.v3_authenticate_token(auth_req)
        token2 = response.json_body['token']
        headers2 = {'X-Subject-Token': response.headers['X-Subject-Token']}

        response = self.v3_authenticate_token(auth_req)
        response.json_body['token']
        headers3 = {'X-Subject-Token': response.headers['X-Subject-Token']}

        self.head('/auth/tokens', headers=headers, expected_status=200)
        self.head('/auth/tokens', headers=headers2, expected_status=200)
        self.head('/auth/tokens', headers=headers3, expected_status=200)

        self.delete('/auth/tokens', headers=headers, expected_status=204)
        # NOTE(ayoung): not deleting token3, as it should be deleted
        # by previous
        events_response = self.get('/OS-REVOKE/events',
                                   expected_status=200).json_body
        events = events_response['events']
        self.assertEqual(1, len(events))
        self.assertEventDataInList(
            events,
            audit_id=token2['audit_ids'][1])
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND)
        self.head('/auth/tokens', headers=headers2, expected_status=200)
        self.head('/auth/tokens', headers=headers3, expected_status=200)

    def test_list_with_filter(self):

        self.role_data_fixtures()
        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body['events']
        self.assertEqual(0, len(events))

        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        auth = self.build_authentication_request(token=scoped_token)
        headers2 = {'X-Subject-Token': self.get_requested_token(auth)}
        self.delete('/auth/tokens', headers=headers, expected_status=204)
        self.delete('/auth/tokens', headers=headers2, expected_status=204)

        events = self.get('/OS-REVOKE/events',
                          expected_status=200).json_body['events']

        self.assertEqual(2, len(events))
        future = utils.isotime(timeutils.utcnow() +
                               datetime.timedelta(seconds=1000))

        events = self.get('/OS-REVOKE/events?since=%s' % (future),
                          expected_status=200).json_body['events']
        self.assertEqual(0, len(events))


class TestAuthExternalDisabled(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(TestAuthExternalDisabled, self).config_overrides()
        self.config_fixture.config(
            group='auth',
            methods=['password', 'token'])

    def test_remote_user_disabled(self):
        api = auth.controllers.Auth()
        remote_user = '%s@%s' % (self.user['name'], self.domain['name'])
        context, auth_info, auth_context = self.build_external_auth_request(
            remote_user)
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)


class TestAuthExternalDomain(test_v3.RestfulTestCase):
    content_type = 'json'

    def config_overrides(self):
        super(TestAuthExternalDomain, self).config_overrides()
        self.kerberos = False
        self.auth_plugin_config_override(external='Domain')

    def test_remote_user_with_realm(self):
        api = auth.controllers.Auth()
        remote_user = self.user['name']
        remote_domain = self.domain['name']
        context, auth_info, auth_context = self.build_external_auth_request(
            remote_user, remote_domain=remote_domain, kerberos=self.kerberos)

        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.user['id'], auth_context['user_id'])

        # Now test to make sure the user name can, itself, contain the
        # '@' character.
        user = {'name': 'myname@mydivision'}
        self.identity_api.update_user(self.user['id'], user)
        remote_user = user['name']
        context, auth_info, auth_context = self.build_external_auth_request(
            remote_user, remote_domain=remote_domain, kerberos=self.kerberos)

        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.user['id'], auth_context['user_id'])

    def test_project_id_scoped_with_remote_user(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        auth_data = self.build_authentication_request(
            project_id=self.project['id'],
            kerberos=self.kerberos)
        remote_user = self.user['name']
        remote_domain = self.domain['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'REMOTE_DOMAIN': remote_domain,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(self.user['name'], token['bind']['kerberos'])

    def test_unscoped_bind_with_remote_user(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        auth_data = self.build_authentication_request(kerberos=self.kerberos)
        remote_user = self.user['name']
        remote_domain = self.domain['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'REMOTE_DOMAIN': remote_domain,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertEqual(self.user['name'], token['bind']['kerberos'])


class TestAuthExternalDefaultDomain(test_v3.RestfulTestCase):
    content_type = 'json'

    def config_overrides(self):
        super(TestAuthExternalDefaultDomain, self).config_overrides()
        self.kerberos = False
        self.auth_plugin_config_override(
            external='keystone.auth.plugins.external.DefaultDomain')

    def test_remote_user_with_default_domain(self):
        api = auth.controllers.Auth()
        remote_user = self.default_domain_user['name']
        context, auth_info, auth_context = self.build_external_auth_request(
            remote_user, kerberos=self.kerberos)

        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.default_domain_user['id'],
                         auth_context['user_id'])

        # Now test to make sure the user name can, itself, contain the
        # '@' character.
        user = {'name': 'myname@mydivision'}
        self.identity_api.update_user(self.default_domain_user['id'], user)
        remote_user = user['name']
        context, auth_info, auth_context = self.build_external_auth_request(
            remote_user, kerberos=self.kerberos)

        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.default_domain_user['id'],
                         auth_context['user_id'])

    def test_project_id_scoped_with_remote_user(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        auth_data = self.build_authentication_request(
            project_id=self.default_domain_project['id'],
            kerberos=self.kerberos)
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(self.default_domain_user['name'],
                         token['bind']['kerberos'])

    def test_unscoped_bind_with_remote_user(self):
        self.config_fixture.config(group='token', bind=['kerberos'])
        auth_data = self.build_authentication_request(kerberos=self.kerberos)
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertEqual(self.default_domain_user['name'],
                         token['bind']['kerberos'])


class TestAuthKerberos(TestAuthExternalDomain):

    def config_overrides(self):
        super(TestAuthKerberos, self).config_overrides()
        self.kerberos = True
        self.auth_plugin_config_override(
            methods=['kerberos', 'password', 'token'])


class TestAuth(test_v3.RestfulTestCase):

    def test_unscoped_token_with_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def _second_project_as_default(self):
        ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # grant the user a role on the project
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'project_id': project['id'],
                'role_id': self.role['id']})

        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        return project

    def test_default_project_id_scoped_token_with_user_id(self):
        project = self._second_project_as_default()

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_default_project_id_scoped_token_with_user_id_no_catalog(self):
        project = self._second_project_as_default()

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data, noauth=True)
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_explicit_unscoped_token(self):
        self._second_project_as_default()

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            unscoped="unscoped")
        r = self.post('/auth/tokens', body=auth_data, noauth=True)

        self.assertIsNone(r.result['token'].get('project'))
        self.assertIsNone(r.result['token'].get('domain'))
        self.assertIsNone(r.result['token'].get('scope'))

    def test_implicit_project_id_scoped_token_with_user_id_no_catalog(self):
        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data, noauth=True)
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])

    def test_auth_catalog_attributes(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)

        catalog = r.result['token']['catalog']
        self.assertEqual(1, len(catalog))
        catalog = catalog[0]

        self.assertEqual(self.service['id'], catalog['id'])
        self.assertEqual(self.service['name'], catalog['name'])
        self.assertEqual(self.service['type'], catalog['type'])

        endpoint = catalog['endpoints']
        self.assertEqual(1, len(endpoint))
        endpoint = endpoint[0]

        self.assertEqual(self.endpoint['id'], endpoint['id'])
        self.assertEqual(self.endpoint['interface'], endpoint['interface'])
        self.assertEqual(self.endpoint['region_id'], endpoint['region_id'])
        self.assertEqual(self.endpoint['url'], endpoint['url'])

    def _check_disabled_endpoint_result(self, catalog, disabled_endpoint_id):
        endpoints = catalog[0]['endpoints']
        endpoint_ids = [ep['id'] for ep in endpoints]
        self.assertEqual([self.endpoint_id], endpoint_ids)

    def test_auth_catalog_disabled_service(self):
        """On authenticate, get a catalog that excludes disabled services."""
        # although the child endpoint is enabled, the service is disabled
        self.assertTrue(self.endpoint['enabled'])
        self.catalog_api.update_service(
            self.endpoint['service_id'], {'enabled': False})
        service = self.catalog_api.get_service(self.endpoint['service_id'])
        self.assertFalse(service['enabled'])

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)

        self.assertEqual([], r.result['token']['catalog'])

    def test_auth_catalog_disabled_endpoint(self):
        """On authenticate, get a catalog that excludes disabled endpoints."""

        # Create a disabled endpoint that's like the enabled one.
        disabled_endpoint_ref = copy.copy(self.endpoint)
        disabled_endpoint_id = uuid.uuid4().hex
        disabled_endpoint_ref.update({
            'id': disabled_endpoint_id,
            'enabled': False,
            'interface': 'internal'
        })
        self.catalog_api.create_endpoint(disabled_endpoint_id,
                                         disabled_endpoint_ref)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)

        self._check_disabled_endpoint_result(r.result['token']['catalog'],
                                             disabled_endpoint_id)

    def test_project_id_scoped_token_with_user_id_unauthorized(self):
        project = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project['id'], project)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_user_and_group_roles_scoped_token(self):
        """Test correct roles are returned in scoped token.

        Test Plan:

        - Create a domain, with 1 project, 2 users (user1 and user2)
          and 2 groups (group1 and group2)
        - Make user1 a member of group1, user2 a member of group2
        - Create 8 roles, assigning them to each of the 8 combinations
          of users/groups on domain/project
        - Get a project scoped token for user1, checking that the right
          two roles are returned (one directly assigned, one by virtue
          of group membership)
        - Repeat this for a domain scoped token
        - Make user1 also a member of group2
        - Get another scoped token making sure the additional role
          shows up
        - User2 is just here as a spoiler, to make sure we don't get
          any roles uniquely assigned to it returned in any of our
          tokens

        """

        domainA = self.new_domain_ref()
        self.resource_api.create_domain(domainA['id'], domainA)
        projectA = self.new_project_ref(domain_id=domainA['id'])
        self.resource_api.create_project(projectA['id'], projectA)

        user1 = self.new_user_ref(
            domain_id=domainA['id'])
        password = user1['password']
        user1 = self.identity_api.create_user(user1)
        user1['password'] = password

        user2 = self.new_user_ref(
            domain_id=domainA['id'])
        password = user2['password']
        user2 = self.identity_api.create_user(user2)
        user2['password'] = password

        group1 = self.new_group_ref(
            domain_id=domainA['id'])
        group1 = self.identity_api.create_group(group1)

        group2 = self.new_group_ref(
            domain_id=domainA['id'])
        group2 = self.identity_api.create_group(group2)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user2['id'],
                                            group2['id'])

        # Now create all the roles and assign them
        role_list = []
        for _ in range(8):
            role = self.new_role_ref()
            self.role_api.create_role(role['id'], role)
            role_list.append(role)

        self.assignment_api.create_grant(role_list[0]['id'],
                                         user_id=user1['id'],
                                         domain_id=domainA['id'])
        self.assignment_api.create_grant(role_list[1]['id'],
                                         user_id=user1['id'],
                                         project_id=projectA['id'])
        self.assignment_api.create_grant(role_list[2]['id'],
                                         user_id=user2['id'],
                                         domain_id=domainA['id'])
        self.assignment_api.create_grant(role_list[3]['id'],
                                         user_id=user2['id'],
                                         project_id=projectA['id'])
        self.assignment_api.create_grant(role_list[4]['id'],
                                         group_id=group1['id'],
                                         domain_id=domainA['id'])
        self.assignment_api.create_grant(role_list[5]['id'],
                                         group_id=group1['id'],
                                         project_id=projectA['id'])
        self.assignment_api.create_grant(role_list[6]['id'],
                                         group_id=group2['id'],
                                         domain_id=domainA['id'])
        self.assignment_api.create_grant(role_list[7]['id'],
                                         group_id=group2['id'],
                                         project_id=projectA['id'])

        # First, get a project scoped token - which should
        # contain the direct user role and the one by virtue
        # of group membership
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            project_id=projectA['id'])
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(2, len(token['roles']))
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)

        # Now the same thing for a domain scoped token
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            domain_id=domainA['id'])
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(2, len(token['roles']))
        self.assertIn(role_list[0]['id'], roles_ids)
        self.assertIn(role_list[4]['id'], roles_ids)

        # Finally, add user1 to the 2nd group, and get a new
        # scoped token - the extra role should now be included
        # by virtue of the 2nd group
        self.identity_api.add_user_to_group(user1['id'],
                                            group2['id'])
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            project_id=projectA['id'])
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(3, len(token['roles']))
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)
        self.assertIn(role_list[7]['id'], roles_ids)

    def test_auth_token_cross_domain_group_and_project(self):
        """Verify getting a token in cross domain group/project roles."""
        # create domain, project and group and grant roles to user
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.resource_api.create_project(project1['id'], project1)
        user_foo = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = user_foo['password']
        user_foo = self.identity_api.create_user(user_foo)
        user_foo['password'] = password
        role_member = {'id': uuid.uuid4().hex,
                       'name': uuid.uuid4().hex}
        self.role_api.create_role(role_member['id'], role_member)
        role_admin = {'id': uuid.uuid4().hex,
                      'name': uuid.uuid4().hex}
        self.role_api.create_role(role_admin['id'], role_admin)
        role_foo_domain1 = {'id': uuid.uuid4().hex,
                            'name': uuid.uuid4().hex}
        self.role_api.create_role(role_foo_domain1['id'], role_foo_domain1)
        role_group_domain1 = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.role_api.create_role(role_group_domain1['id'], role_group_domain1)
        self.assignment_api.add_user_to_project(project1['id'],
                                                user_foo['id'])
        new_group = {'domain_id': domain1['id'], 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        self.identity_api.add_user_to_group(user_foo['id'],
                                            new_group['id'])
        self.assignment_api.create_grant(
            user_id=user_foo['id'],
            project_id=project1['id'],
            role_id=role_member['id'])
        self.assignment_api.create_grant(
            group_id=new_group['id'],
            project_id=project1['id'],
            role_id=role_admin['id'])
        self.assignment_api.create_grant(
            user_id=user_foo['id'],
            domain_id=domain1['id'],
            role_id=role_foo_domain1['id'])
        self.assignment_api.create_grant(
            group_id=new_group['id'],
            domain_id=domain1['id'],
            role_id=role_group_domain1['id'])

        # Get a scoped token for the project
        auth_data = self.build_authentication_request(
            username=user_foo['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user_foo['password'],
            project_name=project1['name'],
            project_domain_id=domain1['id'])

        r = self.v3_authenticate_token(auth_data)
        scoped_token = self.assertValidScopedTokenResponse(r)
        project = scoped_token["project"]
        roles_ids = []
        for ref in scoped_token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(project1['id'], project["id"])
        self.assertIn(role_member['id'], roles_ids)
        self.assertIn(role_admin['id'], roles_ids)
        self.assertNotIn(role_foo_domain1['id'], roles_ids)
        self.assertNotIn(role_group_domain1['id'], roles_ids)

    def test_project_id_scoped_token_with_user_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_domain_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_id_scoped_token_with_user_domain_name(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_domain_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_domain_name(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_token_with_group_role(self):
        group = self.new_group_ref(
            domain_id=self.domain_id)
        group = self.identity_api.create_group(group)

        # add user to group
        self.identity_api.add_user_to_group(self.user['id'], group['id'])

        # grant the domain role to group
        path = '/domains/%s/groups/%s/roles/%s' % (
            self.domain['id'], group['id'], self.role['id'])
        self.put(path=path)

        # now get a domain-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_token_with_name(self):
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)
        # now get a domain-scoped token
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_failed(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_auth_with_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

        token = r.headers.get('X-Subject-Token')

        # test token auth
        auth_data = self.build_authentication_request(token=token)
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def get_v2_token(self, tenant_id=None):
        body = {
            'auth': {
                'passwordCredentials': {
                    'username': self.default_domain_user['name'],
                    'password': self.default_domain_user['password'],
                },
            },
        }
        r = self.admin_request(method='POST', path='/v2.0/tokens', body=body)
        return r

    def test_validate_v2_unscoped_token_with_v3_api(self):
        v2_token = self.get_v2_token().result['access']['token']['id']
        auth_data = self.build_authentication_request(token=v2_token)
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_v2_scoped_token_with_v3_api(self):
        v2_response = self.get_v2_token(
            tenant_id=self.default_domain_project['id'])
        result = v2_response.result
        v2_token = result['access']['token']['id']
        auth_data = self.build_authentication_request(
            token=v2_token,
            project_id=self.default_domain_project['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidScopedTokenResponse(r)

    def test_invalid_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_invalid_user_name(self):
        auth_data = self.build_authentication_request(
            username=uuid.uuid4().hex,
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_invalid_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_invalid_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=uuid.uuid4().hex,
            password=self.user['password'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_invalid_password(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=uuid.uuid4().hex)
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_remote_user_no_realm(self):
        api = auth.controllers.Auth()
        context, auth_info, auth_context = self.build_external_auth_request(
            self.default_domain_user['name'])
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.default_domain_user['id'],
                         auth_context['user_id'])
        # Now test to make sure the user name can, itself, contain the
        # '@' character.
        user = {'name': 'myname@mydivision'}
        self.identity_api.update_user(self.default_domain_user['id'], user)
        context, auth_info, auth_context = self.build_external_auth_request(
            user["name"])
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(self.default_domain_user['id'],
                         auth_context['user_id'])

    def test_remote_user_no_domain(self):
        api = auth.controllers.Auth()
        context, auth_info, auth_context = self.build_external_auth_request(
            self.user['name'])
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)

    def test_remote_user_and_password(self):
        # both REMOTE_USER and password methods must pass.
        # note that they do not have to match
        api = auth.controllers.Auth()
        auth_data = self.build_authentication_request(
            user_domain_id=self.default_domain_user['domain_id'],
            username=self.default_domain_user['name'],
            password=self.default_domain_user['password'])['auth']
        context, auth_info, auth_context = self.build_external_auth_request(
            self.default_domain_user['name'], auth_data=auth_data)

        api.authenticate(context, auth_info, auth_context)

    def test_remote_user_and_explicit_external(self):
        # both REMOTE_USER and password methods must pass.
        # note that they do not have to match
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password=self.user['password'])['auth']
        auth_data['identity']['methods'] = ["password", "external"]
        auth_data['identity']['external'] = {}
        api = auth.controllers.Auth()
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          self.empty_context,
                          auth_info,
                          auth_context)

    def test_remote_user_bad_password(self):
        # both REMOTE_USER and password methods must pass.
        api = auth.controllers.Auth()
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password='badpassword')['auth']
        context, auth_info, auth_context = self.build_external_auth_request(
            self.default_domain_user['name'], auth_data=auth_data)
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)

    def test_bind_not_set_with_remote_user(self):
        self.config_fixture.config(group='token', bind=[])
        auth_data = self.build_authentication_request()
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertNotIn('bind', token)

    # TODO(ayoung): move to TestPKITokenAPIs; it will be run for both formats
    def test_verify_with_bound_token(self):
        self.config_fixture.config(group='token', bind='kerberos')
        auth_data = self.build_authentication_request(
            project_id=self.project['id'])
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})

        token = self.get_requested_token(auth_data)
        headers = {'X-Subject-Token': token}
        r = self.get('/auth/tokens', headers=headers, token=token)
        token = self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(self.default_domain_user['name'],
                         token['bind']['kerberos'])

    def test_auth_with_bind_token(self):
        self.config_fixture.config(group='token', bind=['kerberos'])

        auth_data = self.build_authentication_request()
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.v3_authenticate_token(auth_data)

        # the unscoped token should have bind information in it
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertEqual(remote_user, token['bind']['kerberos'])

        token = r.headers.get('X-Subject-Token')

        # using unscoped token with remote user succeeds
        auth_params = {'token': token, 'project_id': self.project_id}
        auth_data = self.build_authentication_request(**auth_params)
        r = self.v3_authenticate_token(auth_data)
        token = self.assertValidProjectScopedTokenResponse(r)

        # the bind information should be carried over from the original token
        self.assertEqual(remote_user, token['bind']['kerberos'])

    def test_v2_v3_bind_token_intermix(self):
        self.config_fixture.config(group='token', bind='kerberos')

        # we need our own user registered to the default domain because of
        # the way external auth works.
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        body = {'auth': {}}
        resp = self.admin_request(path='/v2.0/tokens',
                                  method='POST',
                                  body=body)

        v2_token_data = resp.result

        bind = v2_token_data['access']['token']['bind']
        self.assertEqual(self.default_domain_user['name'], bind['kerberos'])

        v2_token_id = v2_token_data['access']['token']['id']
        # NOTE(gyee): self.get() will try to obtain an auth token if one
        # is not provided. When REMOTE_USER is present in the request
        # environment, the external user auth plugin is used in conjunction
        # with the password auth for the admin user. Therefore, we need to
        # cleanup the REMOTE_USER information from the previous call.
        del self.admin_app.extra_environ['REMOTE_USER']
        headers = {'X-Subject-Token': v2_token_id}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.result

        self.assertDictEqual(v2_token_data['access']['token']['bind'],
                             token_data['token']['bind'])

    def test_authenticating_a_user_with_no_password(self):
        user = self.new_user_ref(domain_id=self.domain['id'])
        user.pop('password', None)  # can't have a password for this test
        user = self.identity_api.create_user(user)

        auth_data = self.build_authentication_request(
            user_id=user['id'],
            password='password')

        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_disabled_default_project_result_in_unscoped_token(self):
        # create a disabled project to work with
        project = self.create_new_default_project_for_user(
            self.user['id'], self.domain_id, enable_project=False)

        # assign a role to user for the new project
        self.assignment_api.add_role_to_user_and_project(self.user['id'],
                                                         project['id'],
                                                         self.role_id)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_disabled_default_project_domain_result_in_unscoped_token(self):
        domain_ref = self.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        domain = self.assertValidDomainResponse(r, domain_ref)

        project = self.create_new_default_project_for_user(
            self.user['id'], domain['id'])

        # assign a role to user for the new project
        self.assignment_api.add_role_to_user_and_project(self.user['id'],
                                                         project['id'],
                                                         self.role_id)

        # now disable the project domain
        body = {'domain': {'enabled': False}}
        r = self.patch('/domains/%(domain_id)s' % {'domain_id': domain['id']},
                       body=body)
        self.assertValidDomainResponse(r)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_no_access_to_default_project_result_in_unscoped_token(self):
        # create a disabled project to work with
        self.create_new_default_project_for_user(self.user['id'],
                                                 self.domain_id)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_disabled_scope_project_domain_result_in_401(self):
        # create a disabled domain
        domain = self.new_domain_ref()
        domain['enabled'] = False
        self.resource_api.create_domain(domain['id'], domain)

        # create a project in the disabled domain
        project = self.new_project_ref(domain_id=domain['id'])
        self.resource_api.create_project(project['id'], project)

        # assign some role to self.user for the project in the disabled domain
        self.assignment_api.add_role_to_user_and_project(
            self.user['id'],
            project['id'],
            self.role_id)

        # user should not be able to auth with project_id
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

        # user should not be able to auth with project_name & domain
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_name=project['name'],
            project_domain_id=domain['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_auth_methods_with_different_identities_fails(self):
        # get the token for a user. This is self.user which is different from
        # self.default_domain_user.
        token = self.get_scoped_token()
        # try both password and token methods with different identities and it
        # should fail
        auth_data = self.build_authentication_request(
            token=token,
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)


class TestAuthJSONExternal(test_v3.RestfulTestCase):
    content_type = 'json'

    def auth_plugin_config_override(self, methods=None, **method_classes):
        self.config_fixture.config(group='auth', methods=[])

    def test_remote_user_no_method(self):
        api = auth.controllers.Auth()
        context, auth_info, auth_context = self.build_external_auth_request(
            self.default_domain_user['name'])
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)


class TestTrustOptional(test_v3.RestfulTestCase):
    def config_overrides(self):
        super(TestTrustOptional, self).config_overrides()
        self.config_fixture.config(group='trust', enabled=False)

    def test_trusts_404(self):
        self.get('/OS-TRUST/trusts', body={'trust': {}},
                 expected_status=http_client.NOT_FOUND)
        self.post('/OS-TRUST/trusts', body={'trust': {}},
                  expected_status=http_client.NOT_FOUND)

    def test_auth_with_scope_in_trust_forbidden(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            trust_id=uuid.uuid4().hex)
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.FORBIDDEN)


class TestTrustRedelegation(test_v3.RestfulTestCase):
    """Redelegation valid and secure

    Redelegation is a hierarchical structure of trusts between initial trustor
    and a group of users allowed to impersonate trustor and act in his name.
    Hierarchy is created in a process of trusting already trusted permissions
    and organized as an adjacency list using 'redelegated_trust_id' field.
    Redelegation is valid if each subsequent trust in a chain passes 'not more'
    permissions than being redelegated.

    Trust constraints are:
     * roles - set of roles trusted by trustor
     * expiration_time
     * allow_redelegation - a flag
     * redelegation_count - decreasing value restricting length of trust chain
     * remaining_uses - DISALLOWED when allow_redelegation == True

    Trust becomes invalid in case:
     * trust roles were revoked from trustor
     * one of the users in the delegation chain was disabled or deleted
     * expiration time passed
     * one of the parent trusts has become invalid
     * one of the parent trusts was deleted

    """

    def config_overrides(self):
        super(TestTrustRedelegation, self).config_overrides()
        self.config_fixture.config(
            group='trust',
            enabled=True,
            allow_redelegation=True,
            max_redelegation_count=10
        )

    def setUp(self):
        super(TestTrustRedelegation, self).setUp()
        # Create a trustee to delegate stuff to
        trustee_user_ref = self.new_user_ref(domain_id=self.domain_id)
        self.trustee_user = self.identity_api.create_user(trustee_user_ref)
        self.trustee_user['password'] = trustee_user_ref['password']

        # trustor->trustee
        self.redelegated_trust_ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            allow_redelegation=True)

        # trustor->trustee (no redelegation)
        self.chained_trust_ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id],
            allow_redelegation=True)

    def _get_trust_token(self, trust):
        trust_id = trust['id']
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust_id)
        trust_token = self.get_requested_token(auth_data)
        return trust_token

    def test_depleted_redelegation_count_error(self):
        self.redelegated_trust_ref['redelegation_count'] = 0
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust.
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http_client.FORBIDDEN)

    def test_modified_redelegation_count_error(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust with incorrect
        # redelegation_count.
        correct = trust['redelegation_count'] - 1
        incorrect = correct - 1
        self.chained_trust_ref['redelegation_count'] = incorrect
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http_client.FORBIDDEN)

    def test_max_redelegation_count_constraint(self):
        incorrect = CONF.trust.max_redelegation_count + 1
        self.redelegated_trust_ref['redelegation_count'] = incorrect
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.redelegated_trust_ref},
                  expected_status=http_client.FORBIDDEN)

    def test_redelegation_expiry(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust supposed to last longer
        # than the parent trust: let's give it 10 minutes (>1 minute).
        too_long_live_chained_trust_ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=10),
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts',
                  body={'trust': too_long_live_chained_trust_ref},
                  token=trust_token,
                  expected_status=http_client.FORBIDDEN)

    def test_redelegation_remaining_uses(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Attempt to create a redelegated trust with remaining_uses defined.
        # It must fail according to specification: remaining_uses must be
        # omitted for trust redelegation. Any number here.
        self.chained_trust_ref['remaining_uses'] = 5
        self.post('/OS-TRUST/trusts',
                  body={'trust': self.chained_trust_ref},
                  token=trust_token,
                  expected_status=http_client.BAD_REQUEST)

    def test_roles_subset(self):
        # Build second role
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)
        # assign a new role to the user
        self.assignment_api.create_grant(role_id=role['id'],
                                         user_id=self.user_id,
                                         project_id=self.project_id)

        # Create first trust with extended set of roles
        ref = self.redelegated_trust_ref
        ref['roles'].append({'id': role['id']})
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        # Trust created with exact set of roles (checked by role id)
        role_id_set = set(r['id'] for r in ref['roles'])
        trust_role_id_set = set(r['id'] for r in trust['roles'])
        self.assertEqual(role_id_set, trust_role_id_set)

        trust_token = self._get_trust_token(trust)

        # Chain second trust with roles subset
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.chained_trust_ref},
                      token=trust_token)
        trust2 = self.assertValidTrustResponse(r)
        # First trust contains roles superset
        # Second trust contains roles subset
        role_id_set1 = set(r['id'] for r in trust['roles'])
        role_id_set2 = set(r['id'] for r in trust2['roles'])
        self.assertThat(role_id_set1, matchers.GreaterThan(role_id_set2))

    def test_redelegate_with_role_by_name(self):
        # For role by name testing
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_names=[self.role['name']],
            allow_redelegation=True)
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        # Ensure we can get a token with this trust
        trust_token = self._get_trust_token(trust)
        # Chain second trust with roles subset
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user['id'],
            project_id=self.project_id,
            impersonation=True,
            role_names=[self.role['name']],
            allow_redelegation=True)
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref},
                      token=trust_token)
        trust = self.assertValidTrustResponse(r)
        # Ensure we can get a token with this trust
        self._get_trust_token(trust)

    def test_redelegate_new_role_fails(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Build second trust with a role not in parent's roles
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)
        # assign a new role to the user
        self.assignment_api.create_grant(role_id=role['id'],
                                         user_id=self.user_id,
                                         project_id=self.project_id)

        # Try to chain a trust with the role not from parent trust
        self.chained_trust_ref['roles'] = [{'id': role['id']}]

        # Bypass policy enforcement
        with mock.patch.object(rules, 'enforce', return_value=True):
            self.post('/OS-TRUST/trusts',
                      body={'trust': self.chained_trust_ref},
                      token=trust_token,
                      expected_status=http_client.FORBIDDEN)

    def test_redelegation_terminator(self):
        r = self.post('/OS-TRUST/trusts',
                      body={'trust': self.redelegated_trust_ref})
        trust = self.assertValidTrustResponse(r)
        trust_token = self._get_trust_token(trust)

        # Build second trust - the terminator
        ref = dict(self.chained_trust_ref,
                   redelegation_count=1,
                   allow_redelegation=False)

        r = self.post('/OS-TRUST/trusts',
                      body={'trust': ref},
                      token=trust_token)

        trust = self.assertValidTrustResponse(r)
        # Check that allow_redelegation == False caused redelegation_count
        # to be set to 0, while allow_redelegation is removed
        self.assertNotIn('allow_redelegation', trust)
        self.assertEqual(0, trust['redelegation_count'])
        trust_token = self._get_trust_token(trust)

        # Build third trust, same as second
        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  token=trust_token,
                  expected_status=http_client.FORBIDDEN)


class TestTrustChain(test_v3.RestfulTestCase):

    def config_overrides(self):
        super(TestTrustChain, self).config_overrides()
        self.config_fixture.config(
            group='trust',
            enabled=True,
            allow_redelegation=True,
            max_redelegation_count=10
        )

    def setUp(self):
        super(TestTrustChain, self).setUp()
        # Create trust chain
        self.user_chain = list()
        self.trust_chain = list()
        for _ in range(3):
            user_ref = self.new_user_ref(domain_id=self.domain_id)
            user = self.identity_api.create_user(user_ref)
            user['password'] = user_ref['password']
            self.user_chain.append(user)

        # trustor->trustee
        trustee = self.user_chain[0]
        trust_ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=trustee['id'],
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        trust_ref.update(
            allow_redelegation=True,
            redelegation_count=3)

        r = self.post('/OS-TRUST/trusts',
                      body={'trust': trust_ref})

        trust = self.assertValidTrustResponse(r)
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])
        trust_token = self.get_requested_token(auth_data)
        self.trust_chain.append(trust)

        for trustee in self.user_chain[1:]:
            trust_ref = self.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=trustee['id'],
                project_id=self.project_id,
                impersonation=True,
                role_ids=[self.role_id])
            trust_ref.update(
                allow_redelegation=True)
            r = self.post('/OS-TRUST/trusts',
                          body={'trust': trust_ref},
                          token=trust_token)
            trust = self.assertValidTrustResponse(r)
            auth_data = self.build_authentication_request(
                user_id=trustee['id'],
                password=trustee['password'],
                trust_id=trust['id'])
            trust_token = self.get_requested_token(auth_data)
            self.trust_chain.append(trust)

        trustee = self.user_chain[-1]
        trust = self.trust_chain[-1]
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password'],
            trust_id=trust['id'])

        self.last_token = self.get_requested_token(auth_data)

    def assert_user_authenticate(self, user):
        auth_data = self.build_authentication_request(
            user_id=user['id'],
            password=user['password']
        )
        r = self.v3_authenticate_token(auth_data)
        self.assertValidTokenResponse(r)

    def assert_trust_tokens_revoked(self, trust_id):
        trustee = self.user_chain[0]
        auth_data = self.build_authentication_request(
            user_id=trustee['id'],
            password=trustee['password']
        )
        r = self.v3_authenticate_token(auth_data)
        self.assertValidTokenResponse(r)

        revocation_response = self.get('/OS-REVOKE/events')
        revocation_events = revocation_response.json_body['events']
        found = False
        for event in revocation_events:
            if event.get('OS-TRUST:trust_id') == trust_id:
                found = True
        self.assertTrue(found, 'event with trust_id %s not found in list' %
                        trust_id)

    def test_delete_trust_cascade(self):
        self.assert_user_authenticate(self.user_chain[0])
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': self.trust_chain[0]['id']},
            expected_status=204)

        headers = {'X-Subject-Token': self.last_token}
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND)
        self.assert_trust_tokens_revoked(self.trust_chain[0]['id'])

    def test_delete_broken_chain(self):
        self.assert_user_authenticate(self.user_chain[0])
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': self.trust_chain[1]['id']},
            expected_status=204)

        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': self.trust_chain[0]['id']},
            expected_status=204)

    def test_trustor_roles_revoked(self):
        self.assert_user_authenticate(self.user_chain[0])

        self.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id
        )

        auth_data = self.build_authentication_request(
            token=self.last_token,
            trust_id=self.trust_chain[-1]['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.NOT_FOUND)

    def test_intermediate_user_disabled(self):
        self.assert_user_authenticate(self.user_chain[0])

        disabled = self.user_chain[0]
        disabled['enabled'] = False
        self.identity_api.update_user(disabled['id'], disabled)

        # Bypass policy enforcement
        with mock.patch.object(rules, 'enforce', return_value=True):
            headers = {'X-Subject-Token': self.last_token}
            self.head('/auth/tokens', headers=headers,
                      expected_status=http_client.FORBIDDEN)

    def test_intermediate_user_deleted(self):
        self.assert_user_authenticate(self.user_chain[0])

        self.identity_api.delete_user(self.user_chain[0]['id'])

        # Bypass policy enforcement
        with mock.patch.object(rules, 'enforce', return_value=True):
            headers = {'X-Subject-Token': self.last_token}
            self.head('/auth/tokens', headers=headers,
                      expected_status=http_client.FORBIDDEN)


class TestTrustAuth(test_v3.RestfulTestCase):
    EXTENSION_NAME = 'revoke'
    EXTENSION_TO_ADD = 'revoke_extension'

    def config_overrides(self):
        super(TestTrustAuth, self).config_overrides()
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='token',
            provider='pki',
            revoke_by_id=False)
        self.config_fixture.config(group='trust', enabled=True)

    def setUp(self):
        super(TestTrustAuth, self).setUp()

        # create a trustee to delegate stuff to
        self.trustee_user = self.new_user_ref(domain_id=self.domain_id)
        password = self.trustee_user['password']
        self.trustee_user = self.identity_api.create_user(self.trustee_user)
        self.trustee_user['password'] = password
        self.trustee_user_id = self.trustee_user['id']

    def test_create_trust_bad_request(self):
        # The server returns a 403 Forbidden rather than a 400, see bug 1133435
        self.post('/OS-TRUST/trusts', body={'trust': {}},
                  expected_status=http_client.FORBIDDEN)

    def test_create_unscoped_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id)
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        self.assertValidTrustResponse(r, ref)

    def test_create_trust_no_roles(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id)
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.FORBIDDEN)

    def _initialize_test_consume_trust(self, count):
        # Make sure remaining_uses is decremented as we consume the trust
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            remaining_uses=count,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        # make sure the trust exists
        trust = self.assertValidTrustResponse(r, ref)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        # get a token for the trustee
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])
        r = self.v3_authenticate_token(auth_data)
        token = r.headers.get('X-Subject-Token')
        # get a trust token, consume one use
        auth_data = self.build_authentication_request(
            token=token,
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        return trust

    def test_consume_trust_once(self):
        trust = self._initialize_test_consume_trust(2)
        # check decremented value
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        trust = r.result.get('trust')
        self.assertIsNotNone(trust)
        self.assertEqual(1, trust['remaining_uses'])

    def test_create_one_time_use_trust(self):
        trust = self._initialize_test_consume_trust(1)
        # No more uses, the trust is made unavailable
        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)
        # this time we can't get a trust token
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_create_trust_with_bad_values_for_remaining_uses(self):
        # negative values for the remaining_uses parameter are forbidden
        self._create_trust_with_bad_remaining_use(bad_value=-1)
        # 0 is a forbidden value as well
        self._create_trust_with_bad_remaining_use(bad_value=0)
        # as are non integer values
        self._create_trust_with_bad_remaining_use(bad_value="a bad value")
        self._create_trust_with_bad_remaining_use(bad_value=7.2)

    def _create_trust_with_bad_remaining_use(self, bad_value):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            remaining_uses=bad_value,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_invalid_trust_request_without_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])

        del ref['impersonation']

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_invalid_trust_request_without_trustee(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])

        del ref['trustee_user_id']

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  expected_status=http_client.BAD_REQUEST)

    def test_create_unlimited_use_trust(self):
        # by default trusts are unlimited in terms of tokens that can be
        # generated from them, this test creates such a trust explicitly
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            remaining_uses=None,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])
        r = self.v3_authenticate_token(auth_data)
        token = r.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            token=token,
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        trust = r.result.get('trust')
        self.assertIsNone(trust['remaining_uses'])

    def test_trust_crud(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=200)
        self.assertValidTrustResponse(r, ref)

        # validate roles on the trust
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles' % {
                'trust_id': trust['id']},
            expected_status=200)
        roles = self.assertValidRoleListResponse(r, self.role)
        self.assertIn(self.role['id'], [x['id'] for x in roles])
        self.head(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            expected_status=200)
        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            expected_status=200)
        self.assertValidRoleResponse(r, self.role)

        r = self.get('/OS-TRUST/trusts', expected_status=200)
        self.assertValidTrustListResponse(r, trust)

        # trusts are immutable
        self.patch(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            body={'trust': ref},
            expected_status=http_client.NOT_FOUND)

        self.delete(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=204)

        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

    def test_create_trust_trustee_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=uuid.uuid4().hex,
            project_id=self.project_id,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_trustor_trustee_backwards(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=self.user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.FORBIDDEN)

    def test_create_trust_project_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=uuid.uuid4().hex,
            role_ids=[self.role_id])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_role_id_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[uuid.uuid4().hex])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_create_trust_role_name_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[uuid.uuid4().hex])
        self.post('/OS-TRUST/trusts', body={'trust': ref},
                  expected_status=http_client.NOT_FOUND)

    def test_v3_v2_intermix_trustor_not_in_default_domain_failed(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.default_domain_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.default_domain_user)

        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=CONF.admin_token,
            method='GET', expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_trustor_not_in_default_domaini_failed(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=CONF.admin_token,
            method='GET', expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix_project_not_in_default_domaini_failed(self):
        # create a trustee in default domain to delegate stuff to
        trustee_user = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = trustee_user['password']
        trustee_user = self.identity_api.create_user(trustee_user)
        trustee_user['password'] = password
        trustee_user_id = trustee_user['id']

        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=CONF.admin_token,
            method='GET', expected_status=http_client.UNAUTHORIZED)

    def test_v3_v2_intermix(self):
        # create a trustee in default domain to delegate stuff to
        trustee_user = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = trustee_user['password']
        trustee_user = self.identity_api.create_user(trustee_user)
        trustee_user['password'] = password
        trustee_user_id = trustee_user['id']

        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=trustee_user_id,
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        token = self.get_requested_token(auth_data)

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token=CONF.admin_token,
            method='GET', expected_status=200)

    def test_exercise_trust_scoped_token_without_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(r, self.trustee_user)
        self.assertEqual(self.trustee_user['id'],
                         r.result['token']['user']['id'])
        self.assertEqual(self.trustee_user['name'],
                         r.result['token']['user']['name'])
        self.assertEqual(self.domain['id'],
                         r.result['token']['user']['domain']['id'])
        self.assertEqual(self.domain['name'],
                         r.result['token']['user']['domain']['name'])
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])
        self.assertEqual(self.project['name'],
                         r.result['token']['project']['name'])

    def test_exercise_trust_scoped_token_with_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(r, self.user)
        self.assertEqual(self.user['id'], r.result['token']['user']['id'])
        self.assertEqual(self.user['name'], r.result['token']['user']['name'])
        self.assertEqual(self.domain['id'],
                         r.result['token']['user']['domain']['id'])
        self.assertEqual(self.domain['name'],
                         r.result['token']['user']['domain']['name'])
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])
        self.assertEqual(self.project['name'],
                         r.result['token']['project']['name'])

    def test_impersonation_token_cannot_create_new_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])

        trust_token = self.get_requested_token(auth_data)

        # Build second trust
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        self.post('/OS-TRUST/trusts',
                  body={'trust': ref},
                  token=trust_token,
                  expected_status=http_client.FORBIDDEN)

    def test_trust_deleted_grant(self):
        # create a new role
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)

        grant_url = (
            '/projects/%(project_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'project_id': self.project_id,
                'user_id': self.user_id,
                'role_id': role['id']})

        # assign a new role
        self.put(grant_url)

        # create a trust that delegates the new role
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[role['id']])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        # delete the grant
        self.delete(grant_url)

        # attempt to get a trust token with the deleted grant
        # and ensure it's unauthorized
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data,
                                       expected_status=http_client.FORBIDDEN)

    def test_trust_chained(self):
        """Test that a trust token can't be used to execute another trust.

        To do this, we create an A->B->C hierarchy of trusts, then attempt to
        execute the trusts in series (C->B->A).

        """
        # create a sub-trustee user
        sub_trustee_user = self.new_user_ref(
            domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = sub_trustee_user['password']
        sub_trustee_user = self.identity_api.create_user(sub_trustee_user)
        sub_trustee_user['password'] = password
        sub_trustee_user_id = sub_trustee_user['id']

        # create a new role
        role = self.new_role_ref()
        self.role_api.create_role(role['id'], role)

        # assign the new role to trustee
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.project_id,
                'user_id': self.trustee_user_id,
                'role_id': role['id']})

        # create a trust from trustor -> trustee
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust1 = self.assertValidTrustResponse(r)

        # authenticate as trustee so we can create a second trust
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user_id,
            password=self.trustee_user['password'],
            project_id=self.project_id)
        token = self.get_requested_token(auth_data)

        # create a trust from trustee -> sub-trustee
        ref = self.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=sub_trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[role['id']])
        r = self.post('/OS-TRUST/trusts', token=token, body={'trust': ref})
        trust2 = self.assertValidTrustResponse(r)

        # authenticate as sub-trustee and get a trust token
        auth_data = self.build_authentication_request(
            user_id=sub_trustee_user['id'],
            password=sub_trustee_user['password'],
            trust_id=trust2['id'])
        trust_token = self.get_requested_token(auth_data)

        # attempt to get the second trust using a trust token
        auth_data = self.build_authentication_request(
            token=trust_token,
            trust_id=trust1['id'])
        r = self.v3_authenticate_token(auth_data,
                                       expected_status=http_client.FORBIDDEN)

    def assertTrustTokensRevoked(self, trust_id):
        revocation_response = self.get('/OS-REVOKE/events',
                                       expected_status=200)
        revocation_events = revocation_response.json_body['events']
        found = False
        for event in revocation_events:
            if event.get('OS-TRUST:trust_id') == trust_id:
                found = True
        self.assertTrue(found, 'event with trust_id %s not found in list' %
                        trust_id)

    def test_delete_trust_revokes_tokens(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        trust_id = trust['id']
        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust_id)
        r = self.v3_authenticate_token(auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.trustee_user)
        trust_token = r.headers['X-Subject-Token']
        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust_id},
            expected_status=204)
        headers = {'X-Subject-Token': trust_token}
        self.head('/auth/tokens', headers=headers,
                  expected_status=http_client.NOT_FOUND)
        self.assertTrustTokensRevoked(trust_id)

    def disable_user(self, user):
        user['enabled'] = False
        self.identity_api.update_user(user['id'], user)

    def test_trust_get_token_fails_if_trustor_disabled(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data, expected_status=201)

        self.disable_user(self.user)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.FORBIDDEN)

    def test_trust_get_token_fails_if_trustee_disabled(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data, expected_status=201)

        self.disable_user(self.trustee_user)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_delete_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=204)

        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=http_client.NOT_FOUND)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.UNAUTHORIZED)

    def test_list_trusts(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        for i in range(3):
            r = self.post('/OS-TRUST/trusts', body={'trust': ref})
            self.assertValidTrustResponse(r, ref)

        r = self.get('/OS-TRUST/trusts', expected_status=200)
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        r = self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.result['trusts']
        self.assertEqual(3, len(trusts))
        self.assertValidTrustListResponse(r)

        r = self.get('/OS-TRUST/trusts?trustee_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.result['trusts']
        self.assertEqual(0, len(trusts))

    def test_change_password_invalidates_trust_tokens(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.v3_authenticate_token(auth_data)

        self.assertValidProjectTrustScopedTokenResponse(r, self.user)
        trust_token = r.headers.get('X-Subject-Token')

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, expected_status=200,
                 token=trust_token)

        self.assertValidUserResponse(
            self.patch('/users/%s' % self.trustee_user['id'],
                       body={'user': {'password': uuid.uuid4().hex}},
                       expected_status=200))

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, expected_status=http_client.UNAUTHORIZED,
                 token=trust_token)

    def test_trustee_can_do_role_ops(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            role_ids=[self.role_id])

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])

        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles' % {
                'trust_id': trust['id']},
            auth=auth_data)
        self.assertValidRoleListResponse(r, self.role)

        self.head(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            auth=auth_data,
            expected_status=200)

        r = self.get(
            '/OS-TRUST/trusts/%(trust_id)s/roles/%(role_id)s' % {
                'trust_id': trust['id'],
                'role_id': self.role['id']},
            auth=auth_data,
            expected_status=200)
        self.assertValidRoleResponse(r, self.role)

    def test_do_not_consume_remaining_uses_when_get_token_fails(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id],
            remaining_uses=3)
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        new_trust = r.result.get('trust')
        trust_id = new_trust.get('id')
        # Pass in another user's ID as the trustee, the result being a failed
        # token authenticate and the remaining_uses of the trust should not be
        # decremented.
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            trust_id=trust_id)
        self.v3_authenticate_token(auth_data,
                                   expected_status=http_client.FORBIDDEN)

        r = self.get('/OS-TRUST/trusts/%s' % trust_id)
        self.assertEqual(3, r.result.get('trust').get('remaining_uses'))


class TestAPIProtectionWithoutAuthContextMiddleware(test_v3.RestfulTestCase):
    def test_api_protection_with_no_auth_context_in_env(self):
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.project['id'])
        token = self.get_requested_token(auth_data)
        auth_controller = auth.controllers.Auth()
        # all we care is that auth context is not in the environment and
        # 'token_id' is used to build the auth context instead
        context = {'subject_token_id': token,
                   'token_id': token,
                   'query_string': {},
                   'environment': {}}
        r = auth_controller.validate_token(context)
        self.assertEqual(200, r.status_code)


class TestAuthContext(unit.TestCase):
    def setUp(self):
        super(TestAuthContext, self).setUp()
        self.auth_context = auth.controllers.AuthContext()

    def test_pick_lowest_expires_at(self):
        expires_at_1 = utils.isotime(timeutils.utcnow())
        expires_at_2 = utils.isotime(timeutils.utcnow() +
                                     datetime.timedelta(seconds=10))
        # make sure auth_context picks the lowest value
        self.auth_context['expires_at'] = expires_at_1
        self.auth_context['expires_at'] = expires_at_2
        self.assertEqual(expires_at_1, self.auth_context['expires_at'])

    def test_identity_attribute_conflict(self):
        for identity_attr in auth.controllers.AuthContext.IDENTITY_ATTRIBUTES:
            self.auth_context[identity_attr] = uuid.uuid4().hex
            if identity_attr == 'expires_at':
                # 'expires_at' is a special case. Will test it in a separate
                # test case.
                continue
            self.assertRaises(exception.Unauthorized,
                              operator.setitem,
                              self.auth_context,
                              identity_attr,
                              uuid.uuid4().hex)

    def test_identity_attribute_conflict_with_none_value(self):
        for identity_attr in auth.controllers.AuthContext.IDENTITY_ATTRIBUTES:
            self.auth_context[identity_attr] = None

            if identity_attr == 'expires_at':
                # 'expires_at' is a special case and is tested above.
                self.auth_context['expires_at'] = uuid.uuid4().hex
                continue

            self.assertRaises(exception.Unauthorized,
                              operator.setitem,
                              self.auth_context,
                              identity_attr,
                              uuid.uuid4().hex)

    def test_non_identity_attribute_conflict_override(self):
        # for attributes Keystone doesn't know about, make sure they can be
        # freely manipulated
        attr_name = uuid.uuid4().hex
        attr_val_1 = uuid.uuid4().hex
        attr_val_2 = uuid.uuid4().hex
        self.auth_context[attr_name] = attr_val_1
        self.auth_context[attr_name] = attr_val_2
        self.assertEqual(attr_val_2, self.auth_context[attr_name])


class TestAuthSpecificData(test_v3.RestfulTestCase):

    def test_get_catalog_project_scoped_token(self):
        """Call ``GET /auth/catalog`` with a project-scoped token."""
        r = self.get(
            '/auth/catalog',
            expected_status=200)
        self.assertValidCatalogResponse(r)

    def test_get_catalog_domain_scoped_token(self):
        """Call ``GET /auth/catalog`` with a domain-scoped token."""
        # grant a domain role to a user
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        self.get(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.user['id'],
                password=self.user['password'],
                domain_id=self.domain['id']),
            expected_status=http_client.FORBIDDEN)

    def test_get_catalog_unscoped_token(self):
        """Call ``GET /auth/catalog`` with an unscoped token."""
        self.get(
            '/auth/catalog',
            auth=self.build_authentication_request(
                user_id=self.default_domain_user['id'],
                password=self.default_domain_user['password']),
            expected_status=http_client.FORBIDDEN)

    def test_get_catalog_no_token(self):
        """Call ``GET /auth/catalog`` without a token."""
        self.get(
            '/auth/catalog',
            noauth=True,
            expected_status=http_client.UNAUTHORIZED)

    def test_get_projects_project_scoped_token(self):
        r = self.get('/auth/projects', expected_status=200)
        self.assertThat(r.json['projects'], matchers.HasLength(1))
        self.assertValidProjectListResponse(r)

    def test_get_domains_project_scoped_token(self):
        self.put(path='/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id']))

        r = self.get('/auth/domains', expected_status=200)
        self.assertThat(r.json['domains'], matchers.HasLength(1))
        self.assertValidDomainListResponse(r)


class TestFernetTokenProvider(test_v3.RestfulTestCase):
    def setUp(self):
        super(TestFernetTokenProvider, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

    def _make_auth_request(self, auth_data):
        resp = self.post('/auth/tokens', body=auth_data, expected_status=201)
        token = resp.headers.get('X-Subject-Token')
        self.assertLess(len(token), 255)
        return token

    def _get_unscoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        return self._make_auth_request(auth_data)

    def _get_project_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project_id)
        return self._make_auth_request(auth_data)

    def _get_domain_scoped_token(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain_id)
        return self._make_auth_request(auth_data)

    def _get_trust_scoped_token(self, trustee_user, trust):
        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        return self._make_auth_request(auth_data)

    def _validate_token(self, token, expected_status=200):
        return self.get(
            '/auth/tokens',
            headers={'X-Subject-Token': token},
            expected_status=expected_status)

    def _revoke_token(self, token, expected_status=204):
        return self.delete(
            '/auth/tokens',
            headers={'X-Subject-Token': token},
            expected_status=expected_status)

    def _set_user_enabled(self, user, enabled=True):
        user['enabled'] = enabled
        self.identity_api.update_user(user['id'], user)

    def _create_trust(self):
        # Create a trustee user
        trustee_user_ref = self.new_user_ref(domain_id=self.domain_id)
        trustee_user = self.identity_api.create_user(trustee_user_ref)
        trustee_user['password'] = trustee_user_ref['password']
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=trustee_user['id'],
            project_id=self.project_id,
            impersonation=False,
            role_ids=[self.role_id])

        # Create a trust
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)
        return (trustee_user, trust)

    def config_overrides(self):
        super(TestFernetTokenProvider, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')

    def test_validate_unscoped_token(self):
        unscoped_token = self._get_unscoped_token()
        self._validate_token(unscoped_token)

    def test_validate_tampered_unscoped_token_fails(self):
        unscoped_token = self._get_unscoped_token()
        tampered_token = (unscoped_token[:50] + uuid.uuid4().hex +
                          unscoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http_client.NOT_FOUND)

    def test_revoke_unscoped_token(self):
        unscoped_token = self._get_unscoped_token()
        self._validate_token(unscoped_token)
        self._revoke_token(unscoped_token)
        self._validate_token(unscoped_token,
                             expected_status=http_client.NOT_FOUND)

    def test_unscoped_token_is_invalid_after_disabling_user(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        self._validate_token(unscoped_token)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          unscoped_token)

    def test_unscoped_token_is_invalid_after_enabling_disabled_user(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        self._validate_token(unscoped_token)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          unscoped_token)
        # Enable the user
        self._set_user_enabled(self.user)
        # Ensure validating a token for a re-enabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          unscoped_token)

    def test_unscoped_token_is_invalid_after_disabling_user_domain(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        self._validate_token(unscoped_token)
        # Disable the user's domain
        self.domain['enabled'] = False
        self.resource_api.update_domain(self.domain['id'], self.domain)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          unscoped_token)

    def test_unscoped_token_is_invalid_after_changing_user_password(self):
        unscoped_token = self._get_unscoped_token()
        # Make sure the token is valid
        self._validate_token(unscoped_token)
        # Change user's password
        self.user['password'] = 'Password1'
        self.identity_api.update_user(self.user['id'], self.user)
        # Ensure updating user's password revokes existing user's tokens
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          unscoped_token)

    def test_validate_project_scoped_token(self):
        project_scoped_token = self._get_project_scoped_token()
        self._validate_token(project_scoped_token)

    def test_validate_domain_scoped_token(self):
        # Grant user access to domain
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])
        domain_scoped_token = self._get_domain_scoped_token()
        resp = self._validate_token(domain_scoped_token)
        resp_json = json.loads(resp.body)
        self.assertIsNotNone(resp_json['token']['catalog'])
        self.assertIsNotNone(resp_json['token']['roles'])
        self.assertIsNotNone(resp_json['token']['domain'])

    def test_validate_tampered_project_scoped_token_fails(self):
        project_scoped_token = self._get_project_scoped_token()
        tampered_token = (project_scoped_token[:50] + uuid.uuid4().hex +
                          project_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http_client.NOT_FOUND)

    def test_revoke_project_scoped_token(self):
        project_scoped_token = self._get_project_scoped_token()
        self._validate_token(project_scoped_token)
        self._revoke_token(project_scoped_token)
        self._validate_token(project_scoped_token,
                             expected_status=http_client.NOT_FOUND)

    def test_project_scoped_token_is_invalid_after_disabling_user(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        self._validate_token(project_scoped_token)
        # Disable the user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          project_scoped_token)

    def test_domain_scoped_token_is_invalid_after_disabling_user(self):
        # Grant user access to domain
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        self._validate_token(domain_scoped_token)
        # Disable user
        self._set_user_enabled(self.user, enabled=False)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          domain_scoped_token)

    def test_domain_scoped_token_is_invalid_after_deleting_grant(self):
        # Grant user access to domain
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        self._validate_token(domain_scoped_token)
        # Delete access to domain
        self.assignment_api.delete_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          domain_scoped_token)

    def test_project_scoped_token_invalid_after_changing_user_password(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        self._validate_token(project_scoped_token)
        # Update user's password
        self.user['password'] = 'Password1'
        self.identity_api.update_user(self.user['id'], self.user)
        # Ensure updating user's password revokes existing tokens
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          project_scoped_token)

    def test_project_scoped_token_invalid_after_disabling_project(self):
        project_scoped_token = self._get_project_scoped_token()
        # Make sure the token is valid
        self._validate_token(project_scoped_token)
        # Disable project
        self.project['enabled'] = False
        self.resource_api.update_project(self.project['id'], self.project)
        # Ensure validating a token for a disabled project fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          project_scoped_token)

    def test_domain_scoped_token_invalid_after_disabling_domain(self):
        # Grant user access to domain
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])
        domain_scoped_token = self._get_domain_scoped_token()
        # Make sure the token is valid
        self._validate_token(domain_scoped_token)
        # Disable domain
        self.domain['enabled'] = False
        self.resource_api.update_domain(self.domain['id'], self.domain)
        # Ensure validating a token for a disabled domain fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          domain_scoped_token)

    def test_rescope_unscoped_token_with_trust(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        self.assertLess(len(trust_scoped_token), 255)

    def test_validate_a_trust_scoped_token(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)

    def test_validate_tampered_trust_scoped_token_fails(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Get a trust scoped token
        tampered_token = (trust_scoped_token[:50] + uuid.uuid4().hex +
                          trust_scoped_token[50 + 32:])
        self._validate_token(tampered_token,
                             expected_status=http_client.NOT_FOUND)

    def test_revoke_trust_scoped_token(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)
        self._revoke_token(trust_scoped_token)
        self._validate_token(trust_scoped_token,
                             expected_status=http_client.NOT_FOUND)

    def test_trust_scoped_token_is_invalid_after_disabling_trustee(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)

        # Disable trustee
        trustee_update_ref = dict(enabled=False)
        self.identity_api.update_user(trustee_user['id'], trustee_update_ref)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          trust_scoped_token)

    def test_trust_scoped_token_invalid_after_changing_trustee_password(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)
        # Change trustee's password
        trustee_update_ref = dict(password='Password1')
        self.identity_api.update_user(trustee_user['id'], trustee_update_ref)
        # Ensure updating trustee's password revokes existing tokens
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          trust_scoped_token)

    def test_trust_scoped_token_is_invalid_after_disabling_trustor(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)

        # Disable the trustor
        trustor_update_ref = dict(enabled=False)
        self.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure validating a token for a disabled user fails
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          trust_scoped_token)

    def test_trust_scoped_token_invalid_after_changing_trustor_password(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)

        # Change trustor's password
        trustor_update_ref = dict(password='Password1')
        self.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure updating trustor's password revokes existing user's tokens
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          trust_scoped_token)

    def test_trust_scoped_token_invalid_after_disabled_trustor_domain(self):
        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        # Validate a trust scoped token
        self._validate_token(trust_scoped_token)

        # Disable trustor's domain
        self.domain['enabled'] = False
        self.resource_api.update_domain(self.domain['id'], self.domain)

        trustor_update_ref = dict(password='Password1')
        self.identity_api.update_user(self.user['id'], trustor_update_ref)
        # Ensure updating trustor's password revokes existing user's tokens
        self.assertRaises(exception.TokenNotFound,
                          self.token_provider_api.validate_token,
                          trust_scoped_token)

    def test_v2_validate_unscoped_token_returns_unauthorized(self):
        """Test raised exception when validating unscoped token.

        Test that validating an unscoped token in v2.0 of a v3 user of a
        non-default domain returns unauthorized.
        """
        unscoped_token = self._get_unscoped_token()
        self.assertRaises(exception.Unauthorized,
                          self.token_provider_api.validate_v2_token,
                          unscoped_token)

    def test_v2_validate_domain_scoped_token_returns_unauthorized(self):
        """Test raised exception when validating a domain scoped token.

        Test that validating an domain scoped token in v2.0
        returns unauthorized.
        """

        # Grant user access to domain
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user['id'],
                                         domain_id=self.domain['id'])

        scoped_token = self._get_domain_scoped_token()
        self.assertRaises(exception.Unauthorized,
                          self.token_provider_api.validate_v2_token,
                          scoped_token)

    def test_v2_validate_trust_scoped_token(self):
        """Test raised exception when validating a trust scoped token.

        Test that validating an trust scoped token in v2.0 returns
        unauthorized.
        """

        trustee_user, trust = self._create_trust()
        trust_scoped_token = self._get_trust_scoped_token(trustee_user, trust)
        self.assertRaises(exception.Unauthorized,
                          self.token_provider_api.validate_v2_token,
                          trust_scoped_token)


class TestAuthFernetTokenProvider(TestAuth):
    def setUp(self):
        super(TestAuthFernetTokenProvider, self).setUp()
        self.useFixture(ksfixtures.KeyRepository(self.config_fixture))

    def config_overrides(self):
        super(TestAuthFernetTokenProvider, self).config_overrides()
        self.config_fixture.config(group='token', provider='fernet')

    def test_verify_with_bound_token(self):
        self.config_fixture.config(group='token', bind='kerberos')
        auth_data = self.build_authentication_request(
            project_id=self.project['id'])
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        # Bind not current supported by Fernet, see bug 1433311.
        self.v3_authenticate_token(auth_data, expected_status=501)

    def test_v2_v3_bind_token_intermix(self):
        self.config_fixture.config(group='token', bind='kerberos')

        # we need our own user registered to the default domain because of
        # the way external auth works.
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        body = {'auth': {}}
        # Bind not current supported by Fernet, see bug 1433311.
        self.admin_request(path='/v2.0/tokens',
                           method='POST',
                           body=body,
                           expected_status=501)

    def test_auth_with_bind_token(self):
        self.config_fixture.config(group='token', bind=['kerberos'])

        auth_data = self.build_authentication_request()
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        # Bind not current supported by Fernet, see bug 1433311.
        self.v3_authenticate_token(auth_data, expected_status=501)
