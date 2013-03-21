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

import copy
import datetime
import time
import uuid

from keystone import auth
from keystone import config
from keystone import exception
from keystone import identity
from keystone.openstack.common import timeutils
from keystone import test
from keystone import token
from keystone import trust

import default_fixtures


CONF = config.CONF
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


def _build_user_auth(token=None, user_id=None, username=None,
                     password=None, tenant_id=None, tenant_name=None,
                     trust_id=None):
    """Build auth dictionary.

    It will create an auth dictionary based on all the arguments
    that it receives.
    """
    auth_json = {}
    if token is not None:
        auth_json['token'] = token
    if username or password:
        auth_json['passwordCredentials'] = {}
    if username is not None:
        auth_json['passwordCredentials']['username'] = username
    if user_id is not None:
        auth_json['passwordCredentials']['userId'] = user_id
    if password is not None:
        auth_json['passwordCredentials']['password'] = password
    if tenant_name is not None:
        auth_json['tenantName'] = tenant_name
    if tenant_id is not None:
        auth_json['tenantId'] = tenant_id
    if trust_id is not None:
        auth_json['trust_id'] = trust_id
    return auth_json


class AuthTest(test.TestCase):
    def setUp(self):
        super(AuthTest, self).setUp()

        CONF.identity.driver = 'keystone.identity.backends.kvs.Identity'
        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.controller = token.controllers.Auth()

    def assertEqualTokens(self, a, b):
        """Assert that two tokens are equal.

        Compare two tokens except for their ids. This also truncates
        the time in the comparison.
        """
        def normalize(token):
            token['access']['token']['id'] = 'dummy'
            del token['access']['token']['expires']
            del token['access']['token']['issued_at']
            return token

        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['access']['token']['expires']),
            timeutils.parse_isotime(b['access']['token']['expires']))
        self.assertCloseEnoughForGovernmentWork(
            timeutils.parse_isotime(a['access']['token']['issued_at']),
            timeutils.parse_isotime(b['access']['token']['issued_at']))
        return self.assertDictEqual(normalize(a), normalize(b))


class AuthBadRequests(AuthTest):
    def setUp(self):
        super(AuthBadRequests, self).setUp()

    def test_no_external_auth(self):
        """Verify that _authenticate_external() raises exception if
        not applicable"""
        self.assertRaises(
            token.controllers.ExternalAuthNotApplicable,
            self.controller._authenticate_external,
            {}, {})

    def test_no_token_in_auth(self):
        """Verity that _authenticate_token() raises exception if no token"""
        self.assertRaises(
            exception.ValidationError,
            self.controller._authenticate_token,
            None, {})

    def test_no_credentials_in_auth(self):
        """Verity that _authenticate_local() raises exception if no creds"""
        self.assertRaises(
            exception.ValidationError,
            self.controller._authenticate_local,
            None, {})

    def test_authenticate_blank_request_body(self):
        """Verify sending empty json dict raises the right exception."""
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          {}, {})

    def test_authenticate_blank_auth(self):
        """Verify sending blank 'auth' raises the right exception."""
        body_dict = _build_user_auth()
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_invalid_auth_content(self):
        """Verify sending invalid 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          {}, {'auth': 'abcd'})

    def test_authenticate_user_id_too_large(self):
        """Verify sending large 'userId' raises the right exception."""
        body_dict = _build_user_auth(user_id='0' * 65, username='FOO',
                                     password='foo2')
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_username_too_large(self):
        """Verify sending large 'username' raises the right exception."""
        body_dict = _build_user_auth(username='0' * 65, password='foo2')
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_tenant_id_too_large(self):
        """Verify sending large 'tenantId' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_id='0' * 65)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_tenant_name_too_large(self):
        """Verify sending large 'tenantName' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_name='0' * 65)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_token_too_large(self):
        """Verify sending large 'token' raises the right exception."""
        body_dict = _build_user_auth(token={'id': '0' * 8193})
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_password_too_large(self):
        """Verify sending large 'password' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='0' * 8193)
        self.assertRaises(exception.ValidationSizeError,
                          self.controller.authenticate,
                          {}, body_dict)


class AuthWithToken(AuthTest):
    def setUp(self):
        super(AuthWithToken, self).setUp()

    def test_unscoped_token(self):
        """Verify getting an unscoped token with password creds"""
        body_dict = _build_user_auth(username='FOO',
                                     password='foo2')
        unscoped_token = self.controller.authenticate({}, body_dict)
        tenant = unscoped_token["access"]["token"].get("tenant", None)
        self.assertEqual(tenant, None)

    def test_auth_invalid_token(self):
        """Verify exception is raised if invalid token"""
        body_dict = _build_user_auth(token={"id": uuid.uuid4().hex})
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            {}, body_dict)

    def test_auth_bad_formatted_token(self):
        """Verify exception is raised if invalid token"""
        body_dict = _build_user_auth(token={})
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            {}, body_dict)

    def test_auth_unscoped_token_no_project(self):
        """Verify getting an unscoped token with an unscoped token"""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        unscoped_token = self.controller.authenticate({}, body_dict)

        body_dict = _build_user_auth(
            token=unscoped_token["access"]["token"])
        unscoped_token_2 = self.controller.authenticate({}, body_dict)

        self.assertEqualTokens(unscoped_token, unscoped_token_2)

    def test_auth_unscoped_token_project(self):
        """Verify getting a token in a tenant with an unscoped token"""
        # Add a role in so we can check we get this back
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        # Get an unscoped tenant
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        unscoped_token = self.controller.authenticate({}, body_dict)
        # Get a token on BAR tenant using the unscoped tenant
        body_dict = _build_user_auth(
            token=unscoped_token["access"]["token"],
            tenant_name="BAR")
        scoped_token = self.controller.authenticate({}, body_dict)

        tenant = scoped_token["access"]["token"]["tenant"]
        roles = scoped_token["access"]["metadata"]["roles"]
        self.assertEquals(tenant["id"], self.tenant_bar['id'])
        self.assertEquals(roles[0], self.role_member['id'])

    def test_auth_token_project_group_role(self):
        """Verify getting a token in a tenant with group roles"""
        # Add a v2 style role in so we can check we get this back
        self.identity_api.add_role_to_user_and_project(
            self.user_foo['id'],
            self.tenant_bar['id'],
            self.role_member['id'])
        # Now create a group role for this user as well
        new_group = {'id': uuid.uuid4().hex, 'domain_id': uuid.uuid4().hex,
                     'name': uuid.uuid4().hex}
        self.identity_api.create_group(new_group['id'], new_group)
        self.identity_api.add_user_to_group(self.user_foo['id'],
                                            new_group['id'])
        self.identity_api.create_grant(
            group_id=new_group['id'],
            project_id=self.tenant_bar['id'],
            role_id=self.role_admin['id'])

        # Get a scoped token for the tenant
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name="BAR")

        scoped_token = self.controller.authenticate({}, body_dict)

        tenant = scoped_token["access"]["token"]["tenant"]
        roles = scoped_token["access"]["metadata"]["roles"]
        self.assertEquals(tenant["id"], self.tenant_bar['id'])
        self.assertIn(self.role_member['id'], roles)
        self.assertIn(self.role_admin['id'], roles)

    def test_auth_token_cross_domain_group_and_project(self):
        """Verify getting a token in cross domain group/project roles"""
        # create domain, project and group and grant roles to user
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.identity_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.identity_api.create_project(project1['id'], project1)
        role_foo_domain1 = {'id': uuid.uuid4().hex,
                            'name': uuid.uuid4().hex}
        self.identity_api.create_role(role_foo_domain1['id'],
                                      role_foo_domain1)
        role_group_domain1 = {'id': uuid.uuid4().hex,
                              'name': uuid.uuid4().hex}
        self.identity_api.create_role(role_group_domain1['id'],
                                      role_group_domain1)
        self.identity_api.add_user_to_project(project1['id'],
                                              self.user_foo['id'])
        new_group = {'id': uuid.uuid4().hex, 'domain_id': domain1['id'],
                     'name': uuid.uuid4().hex}
        self.identity_api.create_group(new_group['id'], new_group)
        self.identity_api.add_user_to_group(self.user_foo['id'],
                                            new_group['id'])
        self.identity_api.create_grant(
            user_id=self.user_foo['id'],
            project_id=project1['id'],
            role_id=self.role_member['id'])
        self.identity_api.create_grant(
            group_id=new_group['id'],
            project_id=project1['id'],
            role_id=self.role_admin['id'])
        self.identity_api.create_grant(
            user_id=self.user_foo['id'],
            domain_id=domain1['id'],
            role_id=role_foo_domain1['id'])
        self.identity_api.create_grant(
            group_id=new_group['id'],
            domain_id=domain1['id'],
            role_id=role_group_domain1['id'])

        # Get a scoped token for the tenant
        body_dict = _build_user_auth(
            username=self.user_foo['name'],
            password=self.user_foo['password'],
            tenant_name=project1['name'])

        scoped_token = self.controller.authenticate({}, body_dict)
        tenant = scoped_token["access"]["token"]["tenant"]
        roles = scoped_token["access"]["metadata"]["roles"]
        self.assertEquals(tenant["id"], project1['id'])
        self.assertIn(self.role_member['id'], roles)
        self.assertIn(self.role_admin['id'], roles)
        self.assertNotIn(role_foo_domain1['id'], roles)
        self.assertNotIn(role_group_domain1['id'], roles)

    def test_belongs_to_no_tenant(self):
        r = self.controller.authenticate(
            {},
            auth={
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password']
                }
            })
        unscoped_token_id = r['access']['token']['id']
        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token,
            dict(is_admin=True, query_string={'belongsTo': 'BAR'}),
            token_id=unscoped_token_id)

    def test_belongs_to(self):
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name="BAR")

        scoped_token = self.controller.authenticate({}, body_dict)
        scoped_token_id = scoped_token['access']['token']['id']

        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token,
            dict(is_admin=True, query_string={'belongsTo': 'me'}),
            token_id=scoped_token_id)

        self.assertRaises(
            exception.Unauthorized,
            self.controller.validate_token,
            dict(is_admin=True, query_string={'belongsTo': 'BAR'}),
            token_id=scoped_token_id)


class AuthWithPasswordCredentials(AuthTest):
    def setUp(self):
        super(AuthWithPasswordCredentials, self).setUp()

    def test_auth_invalid_user(self):
        """Verify exception is raised if invalid user"""
        body_dict = _build_user_auth(
            username=uuid.uuid4().hex,
            password=uuid.uuid4().hex)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            {}, body_dict)

    def test_auth_valid_user_invalid_password(self):
        """Verify exception is raised if invalid password"""
        body_dict = _build_user_auth(
            username="FOO",
            password=uuid.uuid4().hex)
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            {}, body_dict)

    def test_auth_empty_password(self):
        """Verify exception is raised if empty password"""
        body_dict = _build_user_auth(
            username="FOO",
            password="")
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            {}, body_dict)

    def test_auth_no_password(self):
        """Verify exception is raised if empty password"""
        body_dict = _build_user_auth(username="FOO")
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            {}, body_dict)

    def test_authenticate_blank_password_credentials(self):
        """Verify sending empty json dict as passwordCredentials raises the
        right exception."""
        body_dict = {'passwordCredentials': {}, 'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_authenticate_no_username(self):
        """Verify skipping username raises the right exception."""
        body_dict = _build_user_auth(password="pass",
                                     tenant_name="demo")
        self.assertRaises(exception.ValidationError,
                          self.controller.authenticate,
                          {}, body_dict)


class AuthWithRemoteUser(AuthTest):
    def setUp(self):
        super(AuthWithRemoteUser, self).setUp()

    def test_unscoped_remote_authn(self):
        """Verify getting an unscoped token with external authn"""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2')
        local_token = self.controller.authenticate(
            {}, body_dict)

        body_dict = _build_user_auth()
        remote_token = self.controller.authenticate(
            {'REMOTE_USER': 'FOO'}, body_dict)

        self.assertEqualTokens(local_token, remote_token)

    def test_unscoped_remote_authn_jsonless(self):
        """Verify that external auth with invalid request fails"""
        self.assertRaises(
            exception.ValidationError,
            self.controller.authenticate,
            {'REMOTE_USER': 'FOO'},
            None)

    def test_scoped_remote_authn(self):
        """Verify getting a token with external authn"""
        body_dict = _build_user_auth(
            username='FOO',
            password='foo2',
            tenant_name='BAR')
        local_token = self.controller.authenticate(
            {}, body_dict)

        body_dict = _build_user_auth(
            tenant_name='BAR')
        remote_token = self.controller.authenticate(
            {'REMOTE_USER': 'FOO'}, body_dict)

        self.assertEqualTokens(local_token, remote_token)

    def test_scoped_nometa_remote_authn(self):
        """Verify getting a token with external authn and no metadata"""
        body_dict = _build_user_auth(
            username='TWO',
            password='two2',
            tenant_name='BAZ')
        local_token = self.controller.authenticate(
            {}, body_dict)

        body_dict = _build_user_auth(tenant_name='BAZ')
        remote_token = self.controller.authenticate(
            {'REMOTE_USER': 'TWO'}, body_dict)

        self.assertEqualTokens(local_token, remote_token)

    def test_scoped_remote_authn_invalid_user(self):
        """Verify that external auth with invalid user fails"""
        body_dict = _build_user_auth(tenant_name="BAR")
        self.assertRaises(
            exception.Unauthorized,
            self.controller.authenticate,
            {'REMOTE_USER': uuid.uuid4().hex},
            body_dict)


class AuthWithTrust(AuthTest):
    def setUp(self):
        super(AuthWithTrust, self).setUp()
        self.opt_in_group('trust', enabled=True)

        trust.Manager()
        self.trust_controller = trust.controllers.TrustV3()
        self.auth_v3_controller = auth.controllers.Auth()
        self.trustor = self.user_foo
        self.trustee = self.user_two
        self.assigned_roles = [self.role_member['id'],
                               self.role_browser['id']]
        for assigned_role in self.assigned_roles:
            self.identity_api.add_role_to_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)

        self.sample_data = {'trustor_user_id': self.trustor['id'],
                            'trustee_user_id': self.trustee['id'],
                            'project_id': self.tenant_bar['id'],
                            'impersonation': 'True',
                            'roles': [{'id': self.role_browser['id']},
                                      {'name': self.role_member['name']}]}
        expires_at = timeutils.strtime(timeutils.utcnow() +
                                       datetime.timedelta(minutes=10),
                                       fmt=TIME_FORMAT)
        self.create_trust(expires_at=expires_at)

    def create_trust(self, expires_at=None, impersonation='True'):
        username = self.trustor['name'],
        password = 'foo2'
        body_dict = _build_user_auth(username=username, password=password)
        self.unscoped_token = self.controller.authenticate({}, body_dict)
        context = {'token_id': self.unscoped_token['access']['token']['id']}
        trust_data = copy.deepcopy(self.sample_data)
        trust_data['expires_at'] = expires_at
        trust_data['impersonation'] = impersonation

        self.new_trust = (self.trust_controller.create_trust
                          (context, trust=trust_data)['trust'])

    def build_v2_token_request(self, username, password):
        body_dict = _build_user_auth(username=username, password=password)
        self.unscoped_token = self.controller.authenticate({}, body_dict)
        unscoped_token_id = self.unscoped_token['access']['token']['id']
        request_body = _build_user_auth(token={'id': unscoped_token_id},
                                        trust_id=self.new_trust['id'],
                                        tenant_id=self.tenant_bar['id'])
        return request_body

    def test_create_trust_bad_data_fails(self):
        context = {'token_id': self.unscoped_token['access']['token']['id']}
        bad_sample_data = {'trustor_user_id': self.trustor['id']}

        self.assertRaises(exception.ValidationError,
                          self.trust_controller.create_trust,
                          context, trust=bad_sample_data)

    def test_create_trust_no_roles(self):
        self.new_trust = None
        self.sample_data['roles'] = []
        self.create_trust()
        self.assertEquals(self.new_trust['roles'], [])

    def test_create_trust(self):
        self.assertEquals(self.new_trust['trustor_user_id'],
                          self.trustor['id'])
        self.assertEquals(self.new_trust['trustee_user_id'],
                          self.trustee['id'])
        role_ids = [self.role_browser['id'], self.role_member['id']]
        self.assertTrue(timeutils.parse_strtime(self.new_trust['expires_at'],
                                                fmt=TIME_FORMAT))

        for role in self.new_trust['roles']:
            self.assertIn(role['id'], role_ids)

    def test_get_trust(self):
        context = {'token_id': self.unscoped_token['access']['token']['id']}
        trust = self.trust_controller.get_trust(context,
                                                self.new_trust['id'])['trust']
        self.assertEquals(trust['trustor_user_id'],
                          self.trustor['id'])
        self.assertEquals(trust['trustee_user_id'],
                          self.trustee['id'])
        role_ids = [self.role_browser['id'], self.role_member['id']]
        for role in self.new_trust['roles']:
            self.assertIn(role['id'], role_ids)

    def test_create_trust_no_impersonation(self):
        self.create_trust(expires_at=None, impersonation='False')
        self.assertEquals(self.new_trust['trustor_user_id'],
                          self.trustor['id'])
        self.assertEquals(self.new_trust['trustee_user_id'],
                          self.trustee['id'])
        self.assertEquals(self.new_trust['impersonation'],
                          'False')
        auth_response = self.fetch_v2_token_from_trust()
        token_user = auth_response['access']['user']
        self.assertEquals(token_user['id'],
                          self.new_trust['trustee_user_id'])

        #TODO Endpoints

    def test_token_from_trust_wrong_user_fails(self):
        new_trust = self.create_trust()
        request_body = self.build_v2_token_request('FOO', 'foo2')
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, {}, request_body)

    def fetch_v2_token_from_trust(self):
        request_body = self.build_v2_token_request('TWO', 'two2')
        auth_response = self.controller.authenticate({}, request_body)
        return auth_response

    def fetch_v3_token_from_trust(self):
        v3_password_data = {
            'identity': {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": self.trustee["id"],
                        "password": self.trustee["password"]}}
            },
            'scope': {
                'project': {
                    'id': self.tenant_baz['id']}}}
        auth_response = (self.auth_v3_controller.authenticate_for_token
                         ({}, v3_password_data))
        token = auth_response.headers['X-Subject-Token']

        v3_req_with_trust = {
            "identity": {
                "methods": ["token"],
                "token": {"id": token}},
            "scope": {
                "RH-TRUST:trust": {"id": self.new_trust['id']}}}
        token_auth_response = (self.auth_v3_controller.authenticate_for_token
                               ({}, v3_req_with_trust))
        return token_auth_response

    def test_create_v3_token_from_trust(self):
        auth_response = self.fetch_v3_token_from_trust()

        trust_token_user = auth_response.json['token']['user']
        self.assertEquals(trust_token_user['id'], self.trustor['id'])

        trust_token_trust = auth_response.json['token']['RH-TRUST:trust']
        self.assertEquals(trust_token_trust['id'], self.new_trust['id'])
        self.assertEquals(trust_token_trust['trustor_user']['id'],
                          self.trustor['id'])
        self.assertEquals(trust_token_trust['trustee_user']['id'],
                          self.trustee['id'])

        trust_token_roles = auth_response.json['token']['roles']
        self.assertEquals(len(trust_token_roles), 2)

    def test_v3_trust_token_get_token_fails(self):
        auth_response = self.fetch_v3_token_from_trust()
        trust_token = auth_response.headers['X-Subject-Token']
        v3_token_data = {
            "methods": ["token"],
            "token": {"id": trust_token}
        }
        self.assertRaises(
            exception.Unauthorized,
            self.auth_v3_controller.authenticate_for_token,
            {}, v3_token_data)

    def test_token_from_trust(self):
        auth_response = self.fetch_v2_token_from_trust()

        self.assertIsNotNone(auth_response)
        self.assertEquals(len(auth_response['access']['metadata']['roles']),
                          2,
                          "user_foo has three roles, but the token should"
                          " only get the two roles specified in the trust.")

    def assert_token_count_for_trust(self, expected_value):
        tokens = self.trust_controller.token_api.list_tokens(
            {}, self.trustee['id'], trust_id=self.new_trust['id'])
        token_count = len(tokens)
        self.assertEquals(token_count, expected_value)

    def test_delete_tokens_for_user_invalidates_tokens_from_trust(self):
        self.assert_token_count_for_trust(0)
        auth_response = self.fetch_v2_token_from_trust()
        self.assert_token_count_for_trust(1)
        self.trust_controller._delete_tokens_for_user(
            {},
            self.trustee['id'])
        self.assert_token_count_for_trust(0)

    def test_token_from_trust_cant_get_another_token(self):
        auth_response = self.fetch_v2_token_from_trust()
        trust_token_id = auth_response['access']['token']['id']
        request_body = _build_user_auth(token={'id': trust_token_id},
                                        tenant_id=self.tenant_bar['id'])
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, {}, request_body)

    def test_delete_trust_revokes_token(self):
        context = {'token_id': self.unscoped_token['access']['token']['id']}
        auth_response = self.fetch_v2_token_from_trust()
        trust_id = self.new_trust['id']
        trust_token_id = auth_response['access']['token']['id']
        tokens = self.token_api.list_tokens(self.trustor['id'],
                                            trust_id=trust_id)
        self.assertEquals(len(tokens), 1)
        self.trust_controller.delete_trust(context, trust_id=trust_id)
        tokens = self.token_api.list_tokens(self.trustor['id'],
                                            trust_id=trust_id)
        self.assertEquals(len(tokens), 0)

    def test_token_from_trust_with_no_role_fails(self):
        for assigned_role in self.assigned_roles:
            self.identity_api.remove_role_from_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)
        request_body = self.build_v2_token_request('TWO', 'two2')
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, {}, request_body)

    def test_expired_trust_get_token_fails(self):
        expiry = "1999-02-18T10:10:00Z"
        self.create_trust(expiry)
        request_body = self.build_v2_token_request('TWO', 'two2')
        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, {}, request_body)

    def test_token_from_trust_with_wrong_role_fails(self):
        self.identity_api.add_role_to_user_and_project(
            self.trustor['id'],
            self.tenant_bar['id'],
            self.role_other['id'])
        for assigned_role in self.assigned_roles:
            self.identity_api.remove_role_from_user_and_project(
                self.trustor['id'], self.tenant_bar['id'], assigned_role)

        request_body = self.build_v2_token_request('TWO', 'two2')

        self.assertRaises(
            exception.Forbidden,
            self.controller.authenticate, {}, request_body)


class TokenExpirationTest(AuthTest):
    def _maintain_token_expiration(self):
        """Token expiration should be maintained after re-auth & validation."""
        r = self.controller.authenticate(
            {},
            auth={
                'passwordCredentials': {
                    'username': self.user_foo['name'],
                    'password': self.user_foo['password']
                }
            })
        unscoped_token_id = r['access']['token']['id']
        original_expiration = r['access']['token']['expires']

        time.sleep(0.5)

        r = self.controller.validate_token(
            dict(is_admin=True, query_string={}),
            token_id=unscoped_token_id)
        self.assertEqual(original_expiration, r['access']['token']['expires'])

        time.sleep(0.5)

        r = self.controller.authenticate(
            {},
            auth={
                'token': {
                    'id': unscoped_token_id,
                },
                'tenantId': self.tenant_bar['id'],
            })
        scoped_token_id = r['access']['token']['id']
        self.assertEqual(original_expiration, r['access']['token']['expires'])

        time.sleep(0.5)

        r = self.controller.validate_token(
            dict(is_admin=True, query_string={}),
            token_id=scoped_token_id)
        self.assertEqual(original_expiration, r['access']['token']['expires'])

    def test_maintain_uuid_token_expiration(self):
        self.opt_in_group('signing', token_format='UUID')
        self._maintain_token_expiration()
