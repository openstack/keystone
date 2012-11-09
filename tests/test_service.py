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

import default_fixtures

from keystone import exception
from keystone import identity
from keystone import service
from keystone import test
from keystone.identity.backends import kvs as kvs_identity
from keystone.openstack.common import timeutils


class FakeIdentityManager(object):
    def get_user_by_name(self, context, user_name):
        return {'id': 1, 'name': 'test', 'extra': ''}


class TokenControllerTest(test.TestCase):
    def setUp(self):
        super(TokenControllerTest, self).setUp()
        self.stubs.Set(identity, 'Manager', FakeIdentityManager)
        self.api = service.TokenController()

    def test_authenticate_blank_password_credentials(self):
        """Verify sending empty json dict as passwordCredentials raises the
        right exception."""
        body_dict = {'passwordCredentials': {}, 'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_no_username(self):
        """Verify skipping username raises the right exception."""
        body_dict = {'passwordCredentials': {'password': 'pass'},
                     'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_no_password(self):
        """Verify skipping password raises the right exception."""
        body_dict = {'passwordCredentials': {'username': 'user1'},
                     'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_blank_request_body(self):
        """Verify sending empty json dict raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, {})

    def test_authenticate_blank_auth(self):
        """Verify sending blank 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, {'auth': {}})

    def test_authenticate_invalid_auth_content(self):
        """Verify sending invalid 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          {}, {'auth': 'abcd'})


class RemoteUserTest(test.TestCase):
    def setUp(self):
        super(RemoteUserTest, self).setUp()
        self.identity_api = kvs_identity.Identity()
        self.load_fixtures(default_fixtures)
        self.api = service.TokenController()

    def _build_user_auth(self, username, passwd, tenant):
        auth_json = {'passwordCredentials': {}}
        if username is not None:
            auth_json['passwordCredentials']['username'] = username
        if passwd is not None:
            auth_json['passwordCredentials']['password'] = passwd
        if tenant is not None:
            auth_json['tenantName'] = tenant
        return auth_json

    def assertEqualTokens(self, a, b):
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

    def test_unscoped_remote_authn(self):
        local_token = self.api.authenticate(
            {},
            self._build_user_auth('FOO', 'foo2', None))
        remote_token = self.api.authenticate(
            {'REMOTE_USER': 'FOO'},
            self._build_user_auth('FOO', 'nosir', None))
        self.assertEqualTokens(local_token, remote_token)

    def test_unscoped_remote_authn_jsonless(self):
        self.assertRaises(
            exception.ValidationError,
            self.api.authenticate,
            {'REMOTE_USER': 'FOO'},
            None)

    def test_scoped_remote_authn(self):
        local_token = self.api.authenticate(
            {},
            self._build_user_auth('FOO', 'foo2', 'BAR'))
        remote_token = self.api.authenticate(
            {'REMOTE_USER': 'FOO'},
            self._build_user_auth('FOO', 'nosir', 'BAR'))
        self.assertEqualTokens(local_token, remote_token)

    def test_scoped_remote_authn_invalid_user(self):
        self.assertRaises(
            exception.Unauthorized,
            self.api.authenticate,
            {'REMOTE_USER': 'FOOZBALL'},
            self._build_user_auth('FOO', 'nosir', 'BAR'))
