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

import json
import uuid

from keystone import auth
from keystone.common import cms
from keystone import config
from keystone import exception
from keystone import tests
from keystone.tests import test_v3


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

    def test_get_method_data_invalid_method(self):
        auth_data = self.build_authentication_request(
            user_id='test',
            password='test')['auth']
        context = None
        auth_info = auth.controllers.AuthInfo(context, auth_data)

        method_name = uuid.uuid4().hex
        self.assertRaises(exception.ValidationError,
                          auth_info.get_method_data,
                          method_name)


class TestPKITokenAPIs(test_v3.RestfulTestCase):
    def config_files(self):
        conf_files = super(TestPKITokenAPIs, self).config_files()
        conf_files.append(tests.testsdir('test_pki_token_provider.conf'))
        return conf_files

    def setUp(self):
        super(TestPKITokenAPIs, self).setUp()
        auth_data = self.build_authentication_request(
            username=self.user['name'],
            user_domain_id=self.domain_id,
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        self.token_data = resp.result
        self.token = resp.headers.get('X-Subject-Token')
        self.headers = {'X-Subject-Token': resp.headers.get('X-Subject-Token')}

    def test_default_fixture_scope_token(self):
        self.assertIsNotNone(self.get_scoped_token())

    def test_v3_token_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.result
        token_id = resp.headers.get('X-Subject-Token')
        self.assertIn('expires_at', token_data['token'])

        expected_token_id = cms.cms_sign_token(json.dumps(token_data),
                                               CONF.signing.certfile,
                                               CONF.signing.keyfile)
        self.assertEqual(expected_token_id, token_id)
        # should be able to validate hash PKI token as well
        hash_token_id = cms.cms_hash_token(token_id)
        headers = {'X-Subject-Token': hash_token_id}
        resp = self.get('/auth/tokens', headers=headers)
        expected_token_data = resp.result
        self.assertDictEqual(expected_token_data, token_data)

    def test_v3_v2_intermix_non_default_domain_failed(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_intermix_domain_scoped_token_failed(self):
        # grant the domain role to user
        path = '/domains/%s/users/%s/roles/%s' % (
            self.domain['id'], self.user['id'], self.role['id'])
        self.put(path=path)
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.headers.get('X-Subject-Token')

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
        token = resp.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET',
                                  expected_status=401)

    def test_v3_v2_unscoped_token_intermix(self):
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.result
        token = resp.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
                                  method='GET')
        v2_token = resp.result
        self.assertEqual(v2_token['access']['user']['id'],
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token['access']['token']['expires'][:-1],
                      token_data['token']['expires_at'])

    def test_v3_v2_token_intermix(self):
        # FIXME(gyee): PKI tokens are not interchangeable because token
        # data is baked into the token itself.
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.result
        token = resp.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
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

    def test_v3_v2_hashed_pki_token_intermix(self):
        auth_data = self.build_authentication_request(
            user_id=self.default_domain_user['id'],
            password=self.default_domain_user['password'],
            project_id=self.default_domain_project['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.result
        token = resp.headers.get('X-Subject-Token')

        # should be able to validate a hash PKI token in v2 too
        token = cms.cms_hash_token(token)
        path = '/v2.0/tokens/%s' % (token)
        resp = self.admin_request(path=path,
                                  token='ADMIN',
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

    def test_v2_v3_unscoped_token_intermix(self):
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
        v2_token_data = resp.result
        v2_token = v2_token_data['access']['token']['id']
        headers = {'X-Subject-Token': v2_token}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.result
        self.assertEqual(v2_token_data['access']['user']['id'],
                         token_data['token']['user']['id'])
        # v2 token time has not fraction of second precision so
        # just need to make sure the non fraction part agrees
        self.assertIn(v2_token_data['access']['token']['expires'][-1],
                      token_data['token']['expires_at'])

    def test_v2_v3_token_intermix(self):
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
        v2_token_data = resp.result
        v2_token = v2_token_data['access']['token']['id']
        headers = {'X-Subject-Token': v2_token}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.result
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
        self.assertEqual(expires, r.result['token']['expires_at'])

    def test_check_token(self):
        self.head('/auth/tokens', headers=self.headers, expected_status=204)

    def test_validate_token(self):
        r = self.get('/auth/tokens', headers=self.headers)
        self.assertValidUnscopedTokenResponse(r)

    def test_revoke_token(self):
        headers = {'X-Subject-Token': self.get_scoped_token()}
        self.delete('/auth/tokens', headers=headers, expected_status=204)
        self.head('/auth/tokens', headers=headers, expected_status=404)
        # make sure we have a CRL
        r = self.get('/auth/tokens/OS-PKI/revoked')
        self.assertIn('signed', r.result)


class TestUUIDTokenAPIs(TestPKITokenAPIs):
    def config_files(self):
        conf_files = super(TestUUIDTokenAPIs, self).config_files()
        conf_files.append(tests.testsdir('test_uuid_token_provider.conf'))
        return conf_files

    def test_v3_token_id(self):
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        resp = self.post('/auth/tokens', body=auth_data)
        token_data = resp.result
        token_id = resp.headers.get('X-Subject-Token')
        self.assertIn('expires_at', token_data['token'])
        self.assertFalse(cms.is_ans1_token(token_id))

    def test_v3_v2_hashed_pki_token_intermix(self):
        # this test is only applicable for PKI tokens
        # skipping it for UUID tokens
        pass


class TestTokenRevokeSelfAndAdmin(test_v3.RestfulTestCase):
    """Test token revoke using v3 Identity API by token owner and admin."""
    def setUp(self):
        """Setup for Test Cases.
        One domain A
        Two users userNormalA and userAdminA

        """
        super(TestTokenRevokeSelfAndAdmin, self).setUp()

        self.domainA = self.new_domain_ref()
        self.identity_api.create_domain(self.domainA['id'], self.domainA)

        self.userAdminA = self.new_user_ref(domain_id=self.domainA['id'])
        self.userAdminA['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.userAdminA['id'], self.userAdminA)

        self.userNormalA = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.userNormalA['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.userNormalA['id'], self.userNormalA)

        self.role1 = self.new_role_ref()
        self.role1['name'] = 'admin'
        self.identity_api.create_role(self.role1['id'], self.role1)

        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.userAdminA['id'],
                                       domain_id=self.domainA['id'])

        # Finally, switch to the v3 sample policy file
        self.orig_policy_file = CONF.policy_file
        from keystone.policy.backends import rules
        rules.reset()
        self.opt(policy_file=tests.etcdir('policy.v3cloudsample.json'))

    def test_user_revokes_own_token(self):
        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.userNormalA['id'],
                password=self.userNormalA['password'],
                user_domain_id=self.domainA['id']))

        user_token = r.headers.get('X-Subject-Token')
        self.assertNotEmpty(user_token)
        headers = {'X-Subject-Token': user_token}

        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.userAdminA['id'],
                password=self.userAdminA['password'],
                domain_name=self.domainA['name']))
        adminA_token = r.headers.get('X-Subject-Token')

        self.head('/auth/tokens', headers=headers, expected_status=204,
                  token=adminA_token)
        self.head('/auth/tokens', headers=headers, expected_status=204,
                  token=user_token)
        self.delete('/auth/tokens', headers=headers, expected_status=204,
                    token=user_token)
        # invalid X-Auth-Token and invalid X-Subject-Token (401)
        self.head('/auth/tokens', headers=headers, expected_status=401,
                  token=user_token)
        # invalid X-Auth-Token and invalid X-Subject-Token (401)
        self.delete('/auth/tokens', headers=headers, expected_status=401,
                    token=user_token)
        # valid X-Auth-Token and invalid X-Subject-Token (404)
        self.delete('/auth/tokens', headers=headers, expected_status=404,
                    token=adminA_token)
        # valid X-Auth-Token and invalid X-Subject-Token (404)
        self.head('/auth/tokens', headers=headers, expected_status=404,
                  token=adminA_token)

    def test_admin_revokes_user_token(self):
        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.userNormalA['id'],
                password=self.userNormalA['password'],
                user_domain_id=self.domainA['id']))

        user_token = r.headers.get('X-Subject-Token')
        self.assertNotEmpty(user_token)
        headers = {'X-Subject-Token': user_token}

        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.userAdminA['id'],
                password=self.userAdminA['password'],
                domain_name=self.domainA['name']))
        adminA_token = r.headers.get('X-Subject-Token')

        self.head('/auth/tokens', headers=headers, expected_status=204,
                  token=adminA_token)
        self.head('/auth/tokens', headers=headers, expected_status=204,
                  token=user_token)
        self.delete('/auth/tokens', headers=headers, expected_status=204,
                    token=adminA_token)
        # invalid X-Auth-Token and invalid X-Subject-Token (401)
        self.head('/auth/tokens', headers=headers, expected_status=401,
                  token=user_token)
        # valid X-Auth-Token and invalid X-Subject-Token (404)
        self.delete('/auth/tokens', headers=headers, expected_status=404,
                    token=adminA_token)
        # valid X-Auth-Token and invalid X-Subject-Token (404)
        self.head('/auth/tokens', headers=headers, expected_status=404,
                  token=adminA_token)


class TestTokenRevoking(test_v3.RestfulTestCase):
    """Test token revocation on the v3 Identity API."""

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
        super(TestTokenRevoking, self).setUp()

        # Start by creating a couple of domains and projects
        self.domainA = self.new_domain_ref()
        self.identity_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = self.new_domain_ref()
        self.identity_api.create_domain(self.domainB['id'], self.domainB)
        self.projectA = self.new_project_ref(domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.projectA['id'], self.projectA)
        self.projectB = self.new_project_ref(domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.projectB['id'], self.projectB)

        # Now create some users
        self.user1 = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.user1['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user1['id'], self.user1)

        self.user2 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user2['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user2['id'], self.user2)

        self.user3 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user3['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user3['id'], self.user3)

        self.group1 = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group1['id'], self.group1)

        self.group2 = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group2['id'], self.group2)

        self.group3 = self.new_group_ref(
            domain_id=self.domainB['id'])
        self.identity_api.create_group(self.group3['id'], self.group3)

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

        self.identity_api.create_grant(self.role2['id'],
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

    def test_unscoped_token_remains_valid_after_role_assignment(self):
        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password']))
        unscoped_token = r.headers.get('X-Subject-Token')

        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                token=unscoped_token,
                project_id=self.projectA['id']))
        scoped_token = r.headers.get('X-Subject-Token')

        # confirm both tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=204)

        # create a new role
        role = self.new_role_ref()
        self.identity_api.create_role(role['id'], role)

        # assign a new role
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'project_id': self.projectA['id'],
                'user_id': self.user1['id'],
                'role_id': role['id']})

        # both tokens should remain valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': unscoped_token},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': scoped_token},
                  expected_status=204)

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
        token = resp.headers.get('X-Subject-Token')
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
                  expected_status=404)

    def test_deleting_role_revokes_token(self):
        """Test deleting a role revokes token.

        Test Plan:
        - Add some additional test data, namely:
            - A third project (project C)
            - Three additional users - user4 owned by domainB and user5 and 6
              owned by domainA (different domain ownership should not affect
              the test results, just provided to broaden test coverage)
            - User5 is a member of group1
            - Group1 gets an additional assignment - role1 on projectB as
              well as its existing role1 on projectA
            - User4 has role2 on Project C
            - User6 has role1 on projectA and domainA
        - This allows us to create 5 tokens by virtue of different types of
          role assignment:
          - user1, scoped to ProjectA by virtue of user role1 assignment
          - user5, scoped to ProjectB by virtue of group role1 assignment
          - user4, scoped to ProjectC by virtue of user role2 assignment
          - user6, scoped to ProjectA by virtue of user role1 assignment
          - user6, scoped to DomainA by virtue of user role1 assignment
        - role1 is then deleted
        - Check the tokens on Project A and B, and DomainA are revoked,
          but not the one for Project C

        """
        # Add the additional test data
        self.projectC = self.new_project_ref(domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.projectC['id'], self.projectC)
        self.user4 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user4['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user4['id'], self.user4)

        self.user5 = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.user5['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user5['id'], self.user5)

        self.user6 = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.user6['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user6['id'], self.user6)
        self.identity_api.add_user_to_group(self.user5['id'],
                                            self.group1['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       group_id=self.group1['id'],
                                       project_id=self.projectB['id'])
        self.identity_api.create_grant(self.role2['id'],
                                       user_id=self.user4['id'],
                                       project_id=self.projectC['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user6['id'],
                                       project_id=self.projectA['id'])
        self.identity_api.create_grant(self.role1['id'],
                                       user_id=self.user6['id'],
                                       domain_id=self.domainA['id'])

        # Now we are ready to start issuing requests
        auth_data = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        tokenA = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user5['id'],
            password=self.user5['password'],
            project_id=self.projectB['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        tokenB = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user4['id'],
            password=self.user4['password'],
            project_id=self.projectC['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        tokenC = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        tokenD = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user6['id'],
            password=self.user6['password'],
            domain_id=self.domainA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        tokenE = resp.headers.get('X-Subject-Token')
        # Confirm tokens are valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=204)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=204)

        # Delete the role, which should invalidate the tokens
        role_url = '/roles/%s' % self.role1['id']
        self.delete(role_url)

        # Check the tokens that used role1 is invalid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenA},
                  expected_status=404)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenB},
                  expected_status=404)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenD},
                  expected_status=404)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenE},
                  expected_status=404)

        # ...but the one using role2 is still valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': tokenC},
                  expected_status=204)

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
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.headers.get('X-Subject-Token')
        # Confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)
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
                  expected_status=204)

    def test_disabling_project_revokes_token(self):
        resp = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))
        token = resp.headers.get('X-Subject-Token')

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)

        # disable the project, which should invalidate the token
        self.patch(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']},
            body={'project': {'enabled': False}})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=404)
        resp = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
            expected_status=401)

    def test_deleting_project_revokes_token(self):
        resp = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))
        token = resp.headers.get('X-Subject-Token')

        # confirm token is valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=204)

        # delete the project, which should invalidate the token
        self.delete(
            '/projects/%(project_id)s' % {'project_id': self.projectA['id']})

        # user should no longer have access to the project
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=404)
        resp = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']),
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
        token1 = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token2 = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user3['id'],
            password=self.user3['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token3 = resp.headers.get('X-Subject-Token')
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
                  expected_status=404)
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token2},
                  expected_status=404)
        # But user3's token should still be valid
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token3},
                  expected_status=204)

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
        resp = self.post('/auth/tokens', body=auth_data)
        token = resp.headers.get('X-Subject-Token')
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
                  expected_status=204)

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
        token1 = resp.headers.get('X-Subject-Token')
        auth_data = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectA['id'])
        resp = self.post('/auth/tokens', body=auth_data)
        token2 = resp.headers.get('X-Subject-Token')
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
                  expected_status=404)
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
                  expected_status=404)

    def test_removing_role_assignment_does_not_affect_other_users(self):
        """Revoking a role from one user should not affect other users."""
        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user1['id'],
                password=self.user1['password'],
                project_id=self.projectA['id']))
        user1_token = r.headers.get('X-Subject-Token')

        r = self.post(
            '/auth/tokens',
            body=self.build_authentication_request(
                user_id=self.user3['id'],
                password=self.user3['password'],
                project_id=self.projectA['id']))
        user3_token = r.headers.get('X-Subject-Token')

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
                  expected_status=404)
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
        self.head(role_path, expected_status=404)


class TestAuthExternalDisabled(test_v3.RestfulTestCase):
    def config_files(self):
        list = self._config_file_list[:]
        list.append('auth_plugin_external_disabled.conf')
        return list

    def test_remote_user_disabled(self):
        auth_data = self.build_authentication_request()['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': '%s@%s' % (self.user['name'],
                                             self.domain['id'])}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)


class TestAuthExternalDomain(test_v3.RestfulTestCase):
    content_type = 'json'

    def config_files(self):
        list = self._config_file_list[:]
        list.append('auth_plugin_external_domain.conf')
        return list

    def test_remote_user_with_realm(self):
        auth_data = self.build_authentication_request()['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': '%s@%s' %
                   (self.user['name'], self.domain['name'])}
        auth_info = auth.controllers.AuthInfo(context, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], self.user['id'])

        # Now test to make sure the user name can, itself, contain the
        # '@' character.
        user = {'name': 'myname@mydivision'}
        self.identity_api.update_user(self.user['id'], user)
        context = {'REMOTE_USER': '%s@%s' %
                   (user['name'], self.domain['name'])}
        auth_info = auth.controllers.AuthInfo(context, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'], self.user['id'])

    def test_project_id_scoped_with_remote_user(self):
        CONF.token.bind = ['kerberos']
        auth_data = self.build_authentication_request(
            project_id=self.project['id'])
        remote_user = '%s@%s' % (self.user['name'], self.domain['name'])
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidProjectScopedTokenResponse(r)
        self.assertEquals(token['bind']['kerberos'], self.user['name'])

    def test_unscoped_bind_with_remote_user(self):
        CONF.token.bind = ['kerberos']
        auth_data = self.build_authentication_request()
        remote_user = '%s@%s' % (self.user['name'], self.domain['name'])
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertEquals(token['bind']['kerberos'], self.user['name'])


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
        self.assertEqual(r.result['token']['project']['id'], project['id'])

    def test_default_project_id_scoped_token_with_user_id_no_catalog(self):
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
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(r.result['token']['project']['id'], project['id'])

    def test_implicit_project_id_scoped_token_with_user_id_no_catalog(self):
        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(r, require_catalog=False)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

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
        self.assignment_api.create_project(project_id, project)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=project['id'])
        self.post('/auth/tokens', body=auth_data, expected_status=401)

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
        self.identity_api.create_domain(domainA['id'], domainA)
        projectA = self.new_project_ref(domain_id=domainA['id'])
        self.assignment_api.create_project(projectA['id'], projectA)

        user1 = self.new_user_ref(
            domain_id=domainA['id'])
        user1['password'] = uuid.uuid4().hex
        self.identity_api.create_user(user1['id'], user1)

        user2 = self.new_user_ref(
            domain_id=domainA['id'])
        user2['password'] = uuid.uuid4().hex
        self.identity_api.create_user(user2['id'], user2)

        group1 = self.new_group_ref(
            domain_id=domainA['id'])
        self.identity_api.create_group(group1['id'], group1)

        group2 = self.new_group_ref(
            domain_id=domainA['id'])
        self.identity_api.create_group(group2['id'], group2)

        self.identity_api.add_user_to_group(user1['id'],
                                            group1['id'])
        self.identity_api.add_user_to_group(user2['id'],
                                            group2['id'])

        # Now create all the roles and assign them
        role_list = []
        for _ in range(8):
            role = self.new_role_ref()
            self.identity_api.create_role(role['id'], role)
            role_list.append(role)

        self.identity_api.create_grant(role_list[0]['id'],
                                       user_id=user1['id'],
                                       domain_id=domainA['id'])
        self.identity_api.create_grant(role_list[1]['id'],
                                       user_id=user1['id'],
                                       project_id=projectA['id'])
        self.identity_api.create_grant(role_list[2]['id'],
                                       user_id=user2['id'],
                                       domain_id=domainA['id'])
        self.identity_api.create_grant(role_list[3]['id'],
                                       user_id=user2['id'],
                                       project_id=projectA['id'])
        self.identity_api.create_grant(role_list[4]['id'],
                                       group_id=group1['id'],
                                       domain_id=domainA['id'])
        self.identity_api.create_grant(role_list[5]['id'],
                                       group_id=group1['id'],
                                       project_id=projectA['id'])
        self.identity_api.create_grant(role_list[6]['id'],
                                       group_id=group2['id'],
                                       domain_id=domainA['id'])
        self.identity_api.create_grant(role_list[7]['id'],
                                       group_id=group2['id'],
                                       project_id=projectA['id'])

        # First, get a project scoped token - which should
        # contain the direct user role and the one by virtue
        # of group membership
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            project_id=projectA['id'])
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(len(token['roles']), 2)
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)

        # Now the same thing for a domain scoped token
        auth_data = self.build_authentication_request(
            user_id=user1['id'],
            password=user1['password'],
            domain_id=domainA['id'])
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(len(token['roles']), 2)
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
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidScopedTokenResponse(r)
        roles_ids = []
        for ref in token['roles']:
            roles_ids.append(ref['id'])
        self.assertEqual(len(token['roles']), 3)
        self.assertIn(role_list[1]['id'], roles_ids)
        self.assertIn(role_list[5]['id'], roles_ids)
        self.assertIn(role_list[7]['id'], roles_ids)

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

        token = r.headers.get('X-Subject-Token')

        # test token auth
        auth_data = self.build_authentication_request(token=token)
        r = self.post('/auth/tokens', body=auth_data)
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
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidUnscopedTokenResponse(r)

    def test_validate_v2_scoped_token_with_v3_api(self):
        v2_response = self.get_v2_token(
            tenant_id=self.default_domain_project['id'])
        result = v2_response.result
        v2_token = result['access']['token']['id']
        auth_data = self.build_authentication_request(
            token=v2_token,
            project_id=self.default_domain_project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidScopedTokenResponse(r)

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

    def test_remote_user_no_realm(self):
        CONF.auth.methods = 'external'
        api = auth.controllers.Auth()
        auth_data = self.build_authentication_request()['auth']
        context = {'REMOTE_USER': self.default_domain_user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)
        self.assertEqual(auth_context['user_id'],
                         self.default_domain_user['id'])

    def test_remote_user_no_domain(self):
        auth_data = self.build_authentication_request()['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)

    def test_remote_user_and_password(self):
        #both REMOTE_USER and password methods must pass.
        #note that they do not have to match
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password=self.user['password'])['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.default_domain_user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        api.authenticate(context, auth_info, auth_context)

    def test_remote_user_and_explicit_external(self):
        #both REMOTE_USER and password methods must pass.
        #note that they do not have to match
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password=self.user['password'])['auth']
        auth_data['identity']['methods'] = ["password", "external"]
        auth_data['identity']['external'] = {}
        api = auth.controllers.Auth()
        context = {}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)

    def test_remote_user_bad_password(self):
        #both REMOTE_USER and password methods must pass.
        auth_data = self.build_authentication_request(
            user_domain_id=self.domain['id'],
            username=self.user['name'],
            password='badpassword')['auth']
        api = auth.controllers.Auth()
        context = {'REMOTE_USER': self.default_domain_user['name']}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          api.authenticate,
                          context,
                          auth_info,
                          auth_context)

    def test_bind_not_set_with_remote_user(self):
        CONF.token.bind = []
        auth_data = self.build_authentication_request()
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertNotIn('bind', token)

    #TODO(ayoung): move to TestPKITokenAPIs; it will be run for both formats
    def test_verify_with_bound_token(self):
        self.opt_in_group('token', bind='kerberos')
        auth_data = self.build_authentication_request(
            project_id=self.project['id'])
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})

        resp = self.post('/auth/tokens', body=auth_data)

        token = resp.headers.get('X-Subject-Token')
        headers = {'X-Subject-Token': token}
        r = self.get('/auth/tokens', headers=headers, token=token)
        token = self.assertValidProjectScopedTokenResponse(r)
        self.assertEqual(token['bind']['kerberos'],
                         self.default_domain_user['name'])

    def test_auth_with_bind_token(self):
        CONF.token.bind = ['kerberos']

        auth_data = self.build_authentication_request()
        remote_user = self.default_domain_user['name']
        self.admin_app.extra_environ.update({'REMOTE_USER': remote_user,
                                             'AUTH_TYPE': 'Negotiate'})
        r = self.post('/auth/tokens', body=auth_data)

        # the unscoped token should have bind information in it
        token = self.assertValidUnscopedTokenResponse(r)
        self.assertEqual(token['bind']['kerberos'], remote_user)

        token = r.headers.get('X-Subject-Token')

        # using unscoped token with remote user succeeds
        auth_params = {'token': token, 'project_id': self.project_id}
        auth_data = self.build_authentication_request(**auth_params)
        r = self.post('/auth/tokens', body=auth_data)
        token = self.assertValidProjectScopedTokenResponse(r)

        # the bind information should be carried over from the original token
        self.assertEqual(token['bind']['kerberos'], remote_user)

    def test_v2_v3_bind_token_intermix(self):
        self.opt_in_group('token', bind='kerberos')

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
        self.assertEqual(bind['kerberos'], self.default_domain_user['name'])

        v2_token_id = v2_token_data['access']['token']['id']
        headers = {'X-Subject-Token': v2_token_id}
        resp = self.get('/auth/tokens', headers=headers)
        token_data = resp.result

        self.assertDictEqual(v2_token_data['access']['token']['bind'],
                             token_data['token']['bind'])

    def test_authenticating_a_user_with_no_password(self):
        user = self.new_user_ref(domain_id=self.domain['id'])
        user.pop('password', None)  # can't have a password for this test
        self.identity_api.create_user(user['id'], user)

        auth_data = self.build_authentication_request(
            user_id=user['id'],
            password='password')

        self.post('/auth/tokens', body=auth_data, expected_status=401)


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
        self.skipTest('Blocked by bug 1133435')
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

        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token='ADMIN', method='GET', expected_status=401)

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
        token = r.headers.get('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=self.trustee_user['id'],
            password=self.trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, self.trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token='ADMIN', method='GET', expected_status=401)

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
        token = r.headers.get('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token='ADMIN', method='GET', expected_status=401)

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
        token = r.headers.get('X-Subject-Token')

        r = self.post('/OS-TRUST/trusts', body={'trust': ref}, token=token)
        trust = self.assertValidTrustResponse(r)

        auth_data = self.build_authentication_request(
            user_id=trustee_user['id'],
            password=trustee_user['password'],
            trust_id=trust['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectTrustScopedTokenResponse(
            r, trustee_user)
        token = r.headers.get('X-Subject-Token')

        # now validate the v3 token with v2 API
        path = '/v2.0/tokens/%s' % (token)
        self.admin_request(
            path=path, token='ADMIN', method='GET', expected_status=200)

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
        self.assertEqual(r.result['token']['user']['id'],
                         self.trustee_user['id'])
        self.assertEqual(r.result['token']['user']['name'],
                         self.trustee_user['name'])
        self.assertEqual(r.result['token']['user']['domain']['id'],
                         self.domain['id'])
        self.assertEqual(r.result['token']['user']['domain']['name'],
                         self.domain['name'])
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])
        self.assertEqual(r.result['token']['project']['name'],
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
        self.assertEqual(r.result['token']['user']['id'], self.user['id'])
        self.assertEqual(r.result['token']['user']['name'], self.user['name'])
        self.assertEqual(r.result['token']['user']['domain']['id'],
                         self.domain['id'])
        self.assertEqual(r.result['token']['user']['domain']['name'],
                         self.domain['name'])
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])
        self.assertEqual(r.result['token']['project']['name'],
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

        for i in range(3):
            r = self.post('/OS-TRUST/trusts', body={'trust': ref})
            self.assertValidTrustResponse(r, ref)

        r = self.get('/OS-TRUST/trusts?trustor_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.result['trusts']
        self.assertEqual(len(trusts), 3)

        r = self.get('/OS-TRUST/trusts?trustee_user_id=%s' %
                     self.user_id, expected_status=200)
        trusts = r.result['trusts']
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
        trust_token = r.headers.get('X-Subject-Token')

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
