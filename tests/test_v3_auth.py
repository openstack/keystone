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
import uuid

import nose.exc

from keystone.common import cms
from keystone import auth
from keystone import config
from keystone import exception

import test_v3


CONF = config.CONF


class TestAuthInfo(test_v3.RestfulTestCase):
    # TDOD(henry-nash) These tests are somewhat inefficient, since by
    # using the test_v3.RestfulTestCase class to gain access to the auth
    # building helper functions, they cause backend databases and fixtures
    # to be loaded unnecessarily.  Separating out the helper functions from
    # this base class would improve efficiency (Bug #1134836)
    def setUp(self, load_sample_data=False):
        super(TestAuthInfo, self).setUp(load_sample_data=load_sample_data)

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
        auth_data = self.build_authentication_request(
            username='test',
            password='test',
            project_name='abc')['auth']
        self.assertRaises(exception.ValidationError,
                          auth.controllers.AuthInfo,
                          None,
                          auth_data)

    def test_both_project_and_domain_in_scope(self):
        auth_data = self.build_authentication_request(
            user_id='test',
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
        auth_data = self.build_authentication_request(
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
        auth_data = self.build_authentication_request(
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

    def test_v3_v2_intermix_non_default_domain_failed(self):
        self.opt_in_group('signing', token_format='UUID')
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token = resp.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix_domain_scoped_token_failed(self):
        self.opt_in_group('signing', token_format='UUID')
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token = resp.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix_non_default_project_failed(self):
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.project['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.body
        token = resp.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_unscoped_uuid_token_intermix(self):
        self.opt_in_group('signing', token_format='UUID')
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'])
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

    def test_v3_v2_unscoped_pki_token_intermix(self):
        self.opt_in_group('signing', token_format='PKI')
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'])
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

    def test_v3_v2_uuid_token_intermix(self):
        # FIXME(gyee): PKI tokens are not interchangeable because token
        # data is baked into the token itself.
        self.opt_in_group('signing', token_format='UUID')
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id'])
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
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id'])
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

    def test_v2_v3_unscoped_uuid_token_intermix(self):
        self.opt_in_group('signing', token_format='UUID')
        body = {
            'auth': {
                'passwordCredentials': {
                    'userId': self.user['id'],
                    'password': self.user['password']
                }
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

    def test_v2_v3_unscoped_pki_token_intermix(self):
        self.opt_in_group('signing', token_format='PKI')
        body = {
            'auth': {
                'passwordCredentials': {
                    'userId': self.user['id'],
                    'password': self.user['password']
                }
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
        auth_data = self.build_authentication_request(
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


class TestTokenRevoking(test_v3.RestfulTestCase):
    """Test token revoking for relevant v3 identity apis"""

    def setUp(self):
        """Setup for Token Revoking Test Cases.

        As well as the usual housekeeping, create a set of domains,
        users, groups, roles and projects for the subsequent tests:

        - Two domains: A & B
        - DomainA has user1, domainB has user2 and user3
        - DomainA has group1 and group2, domainB has group3
        - User1 has a role on domainA
        - Two projects: A & B, both in domainA
        - All users have a role on projectA
        - Two groups: 1 & 2
        - User1 and user2 are members of group1
        - User3 is a member of group2

        """
        super(TestTokenRevoking, self).setUp()

        # Start by creating a couple of domains and projects
        self.domainA = self.new_domain_ref()
        domainA_ref = self.identity_api.create_domain(self.domainA['id'],
                                                      self.domainA)
        self.domainB = self.new_domain_ref()
        domainB_ref = self.identity_api.create_domain(self.domainB['id'],
                                                      self.domainB)
        self.projectA = self.new_project_ref(domain_id=self.domainA['id'])
        projectA_ref = self.identity_api.create_project(self.projectA['id'],
                                                        self.projectA)
        self.projectB = self.new_project_ref(domain_id=self.domainA['id'])
        projectB_ref = self.identity_api.create_project(self.projectB['id'],
                                                        self.projectB)

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.user1['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user1['id'],
                                                 self.user1)

        self.user2 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user2['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user2['id'],
                                                 self.user2)

        self.user3 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user3['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user3['id'],
                                                 self.user3)

        self.group1 = self.new_group_ref(
            domain_id=self.domainA['id'])
        user_ref = self.identity_api.create_group(self.group1['id'],
                                                  self.group1)

        self.group2 = self.new_group_ref(
            domain_id=self.domainA['id'])
        user_ref = self.identity_api.create_group(self.group2['id'],
                                                  self.group2)

        self.group3 = self.new_group_ref(
            domain_id=self.domainB['id'])
        user_ref = self.identity_api.create_group(self.group3['id'],
                                                  self.group3)

        self.identity_api.add_user_to_group(self.user1['id'],
                                            self.group1['id'])
        self.identity_api.add_user_to_group(self.user2['id'],
                                            self.group1['id'])
        self.identity_api.add_user_to_group(self.user3['id'],
                                            self.group2['id'])

        self.role1 = self.new_role_ref()
        self.identity_api.create_role(self.role1['id'], self.role1)
        self.role2 = self.new_role_ref()
        self.identity_api.create_role(self.role2['id'], self.role2)

        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user1['id'],
                                       domain_id=self.domainA['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user1['id'],
                                       project_id=self.projectA['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user2['id'],
                                       project_id=self.projectA['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user3['id'],
                                       project_id=self.projectA['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       group_id=self.group1['id'],
                                       project_id=self.projectA['id'])

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
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.getheader('X-Subject-Token')
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)
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
                  expected_status=401)

    def test_creating_user_grant_revokes_token(self):
        """Test creating a user grant revokes token.

        Test Plan:
        - Get a token for user1, scoped to ProjectA
        - Create a grant for user1 on DomainB
        - Check token is no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.getheader('X-Subject-Token')
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)
        # Delete the grant, which should invalidate the token
        grant_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/'
            'roles/%(role_id)s' % {
                'domain_id': self.domainB['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        self.put(grant_url)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=401)

    def test_deleting_group_grant_revokes_tokens(self):
        """Test deleting a group grant revokes tokens.

        Test Plan:
        - Get a token for user1, scoped to ProjectA
        - Get a token for user2, scoped to ProjectA
        - Get a token for user3, scoped to ProjectA
        - Delete the grant group1 has on ProjectA
        - Check tokens for user1 & user2 are no longer valid,
          since user1 and user2 are members of group1
        - Check token for user3 is still valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token1 = resp.getheader('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token2 = resp.getheader('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user3['id'],
            password=self.user3['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token3 = resp.getheader('X-Subject-Token')
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=204)
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
                  expected_status=401)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=401)
        # But user3's token should still be valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=204)

    def test_creating_group_grant_revokes_token(self):
        """Test creating a group grant revokes token.

        Test Plan:
        - Get a token for user1, scoped to ProjectA
        - Create a grant for group1 on DomainB
        - Check token is no longer valid

        """
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.getheader('X-Subject-Token')
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)
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
                  expected_status=401)

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
        resp = self.post('/auth/tokens', body=auth_data)
        token1 = resp.getheader('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token2 = resp.getheader('X-Subject-Token')
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=204)
        # Remove user1 from group1, which should invalidate
        # the token
        self.delete('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group1['id'],
            'user_id': self.user1['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token1},
                  expected_status=401)
        # But user2's token should still be valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=204)
        # Adding user2 to a group should invalidate token
        self.put('/groups/%(group_id)s/users/%(user_id)s' % {
            'group_id': self.group2['id'],
            'user_id': self.user2['id']})
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=401)

    def test_removing_role_assignment_does_not_affect_other_users(self):
        """Revoking a role from one user should not affect other users."""
        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']))
        user1_token = r.getheader('X-Subject-Token')

        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))
        user3_token = r.getheader('X-Subject-Token')

        # delete relationships between user1 and projectA from setUp
        self.delete(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': self.role1['id']})
        self.delete(
            '/projects/%(project_id)s/groups/%(group_id)s/roles/%(role_id)s' %
            {'project_id': self.projectA['id'],
             'group_id': self.group1['id'],
             'role_id': self.role1['id']})

        # authorization for the first user should now fail
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': user1_token},
                  expected_status=401)
        self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']),
            expected_status=401)

        # authorization for the second user should still succeed
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': user3_token},
                  expected_status=204)
        self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))


class TestAuthJSON(test_v3.RestfulTestCase):
    content_type = 'json'

    def test_unscoped_token_with_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_unscoped_token_with_user_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=self.domain['name'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_default_project_id_scoped_token_with_user_id(self):
        # create a second project to work with
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

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(r.body['token']['project']['id'], project['id'])

    def test_default_project_id_scoped_token_with_user_id_401(self):
        # create a second project to work with
        ref = self.new_project_ref(domain_id=self.domain['id'])
        del ref['id']
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # set the user's preferred project without having authz on that project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        # attempt to authenticate without requesting a project
        # the default_project_id should be the assumed scope of the request,
        # and fail because the user doesn't have explicit authz on that scope
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_project_id_scoped_token_with_user_id_401(self):
        project_id = uuid.uuid4().hex
        project = self.new_project_ref(domain_id=self.domain_id)
        self.identity_api.create_project(project_id, project)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_project_id_scoped_token_with_user_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r)

    def test_project_id_scoped_token_with_user_domain_name(self):
        auth_data = self.build_authentication_request(
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

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        r = self.post('/auth/tokens', body=auth_data)
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
        r = self.post('/auth/tokens', body=auth_data)
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
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_name_scoped_token_with_user_id(self):
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
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
        r = self.post('/auth/tokens', body=auth_data)
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
        auth_data = self.build_authentication_request(
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
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_name=self.domain['name'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidDomainScopedTokenResponse(r)

    def test_domain_scope_failed(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_auth_with_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

        token = r.getheader('X-Subject-Token')
        headers = {'X-Subject-Token': r.getheader('X-Subject-Token')}

        # test token auth
        auth_data = self.build_authentication_request(token=token)
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_invalid_user_id(self):
        auth_data = self.build_authentication_request(
            user_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_user_name(self):
        auth_data = self.build_authentication_request(
            username=uuid.uuid4().hex,
            user_domain_id=self.domain['id'],
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_domain_id(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_domain_name(self):
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_name=uuid.uuid4().hex,
            password=self.user['password'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_invalid_password(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=uuid.uuid4().hex)
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_remote_user(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], self.user['id'])

    def test_remote_user_no_domain(self):
        auth_data = self.build_authentication_request(
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


class TestTrustOptional(test_v3.RestfulTestCase):
    def setUp(self, *args, **kwargs):
        self.opt_in_group('trust', enabled=False)
        super(TestTrustOptional, self).setUp(*args, **kwargs)

    def test_trusts_404(self):
        self.get('/OS-TRUST/trusts', body={'trust': {}}, expected_status=404)
        self.post('/OS-TRUST/trusts', body={'trust': {}}, expected_status=404)

    def test_auth_with_scope_in_trust_403(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            trust_id=uuid.uuid4().hex)
        self.post('/auth/tokens', body=auth_data, expected_status=403)


class TestTrustAuth(TestAuthInfo):
    def setUp(self):
        self.opt_in_group('trust', enabled=True)
        super(TestTrustAuth, self).setUp(load_sample_data=True)

        # create a trustee to delegate stuff to
        self.trustee_user_id = uuid.uuid4().hex
        self.trustee_user = self.new_user_ref(domain_id=self.domain_id)
        self.trustee_user['id'] = self.trustee_user_id
        self.identity_api.create_user(self.trustee_user_id, self.trustee_user)

    def test_create_trust_400(self):
        raise nose.exc.SkipTest('Blocked by bug 1133435')
        self.post('/OS-TRUST/trusts', body={'trust': {}}, expected_status=400)

    def test_create_unscoped_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id)
        del ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        self.assertValidTrustResponse(r, ref)

    def test_trust_crud(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[self.role_id])
        del ref['id']
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
            expected_status=204)
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
            expected_status=404)

        self.delete(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=204)

        self.get(
            '/OS-TRUST/trusts/%(trust_id)s' % {'trust_id': trust['id']},
            expected_status=404)

    def test_create_trust_trustee_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=uuid.uuid4().hex)
        del ref['id']
        self.post('/OS-TRUST/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_trustor_trustee_backwards(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.trustee_user_id,
            trustee_user_id=self.user_id)
        del ref['id']
        self.post('/OS-TRUST/trusts', body={'trust': ref}, expected_status=403)

    def test_create_trust_project_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=uuid.uuid4().hex,
            role_ids=[self.role_id])
        del ref['id']
        self.post('/OS-TRUST/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_role_id_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_ids=[uuid.uuid4().hex])
        del ref['id']
        self.post('/OS-TRUST/trusts', body={'trust': ref}, expected_status=404)

    def test_create_trust_role_name_404(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            role_names=[uuid.uuid4().hex])
        del ref['id']
        self.post('/OS-TRUST/trusts', body={'trust': ref}, expected_status=404)

    def test_create_expired_trust(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            expires=dict(seconds=-1),
            role_ids=[self.role_id])
        del ref['id']
        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r, ref)

        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

    def test_v3_v2_intermix_trustor_not_in_default_domain_failed(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.default_domain_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.default_domain_user)

        token = r.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix_trustor_not_in_default_domaini_failed(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        r = self.post('/auth/tokens', body=auth_data)
        token = r.getheader('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.trustee_user)
        token = r.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix_project_not_in_default_domaini_failed(self):
        # create a trustee in default domain to delegate stuff to
        trustee_user_id = uuid.uuid4().hex
        trustee_user = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        trustee_user['id'] = trustee_user_id
        self.identity_api.create_user(trustee_user_id, trustee_user)

        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        r = self.post('/auth/tokens', body=auth_data)
        token = r.getheader('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix(self):
        # create a trustee in default domain to delegate stuff to
        trustee_user_id = uuid.uuid4().hex
        trustee_user = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        trustee_user['id'] = trustee_user_id
        self.identity_api.create_user(trustee_user_id, trustee_user)

        ref = self.new_trust_ref(
            trustor_user_id=self.default_domain_user_id,
            trustee_user_id=trustee_user_id,
            project_id=self.default_domain_project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project_id)
        r = self.post('/auth/tokens', body=auth_data)
        token = r.getheader('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.getheader('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=200)

    def test_exercise_trust_scoped_token_without_impersonation(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=False,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
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

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
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

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})

        trust = self.assertValidTrustResponse(r, ref)

        self.delete('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=204)

        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        self.get('/OS-TRUST/trusts/%(trust_id)s' % {
            'trust_id': trust['id']},
            expected_status=404)

        auth_data = self.build_authentication_request(
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
            r = self.post('/OS-TRUST/trusts', body={'trust': ref})
            trust = self.assertValidTrustResponse(r, ref)

        r = self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.body['trusts']
        self.assertEqual(len(trusts), 3)

        r = self.get('/OS-TRUST/trusts?trustee_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.body['trusts']
        self.assertEqual(len(trusts), 0)

    def test_change_password_invalidates_trust_tokens(self):
        ref = self.new_trust_ref(
            trustor_user_id=self.user_id,
            trustee_user_id=self.trustee_user_id,
            project_id=self.project_id,
            impersonation=True,
            expires=dict(minutes=1),
            role_ids=[self.role_id])
        del ref['id']

        r = self.post('/OS-TRUST/trusts', body={'trust': ref})
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)

        self.assertValidProjectTrustScopedTokenResponse(r, self.user)
        trust_token = r.getheader('X-Subject-Token')

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, expected_status=200,
                 token=trust_token)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'])

        self.assertValidUserResponse(
            self.patch('/users/%s' % self.trustee_user['id'],
                       body={'user': {'password': uuid.uuid4().hex}},
                       auth=auth_data,
                       expected_status=200))

        self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.user_id, expected_status=401,
                 token=trust_token)
