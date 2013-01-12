# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat, Inc.
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

from keystone import config
from keystone import exception
from keystone import service
from keystone import test

import default_fixtures

CONF = config.CONF


def _build_user_auth(token=None, user_id=None, username=None,
                    password=None, tenant_id=None, tenant_name=None):
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
    return auth_json


class AuthTest(test.TestCase):
    def setUp(self):
        super(AuthTest, self).setUp()

        CONF.identity.driver = 'keystone.identity.backends.kvs.Identity'
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.api = service.TokenController()

    def test_authenticate_user_id_too_large(self):
        """Verify sending large 'userId' raises the right exception."""
        body_dict = _build_user_auth(user_id='0' * 65, username='FOO',
                                     password='foo2')
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_username_too_large(self):
        """Verify sending large 'username' raises the right exception."""
        body_dict = _build_user_auth(username='0' * 65, password='foo2')
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_tenant_id_too_large(self):
        """Verify sending large 'tenantId' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_id='0' * 65)
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_tenant_name_too_large(self):
        """Verify sending large 'tenantName' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='foo2',
                                     tenant_name='0' * 65)
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_token_too_large(self):
        """Verify sending large 'token' raises the right exception."""
        body_dict = _build_user_auth(token={'id': '0' * 8193})
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)

    def test_authenticate_password_too_large(self):
        """Verify sending large 'password' raises the right exception."""
        body_dict = _build_user_auth(username='FOO', password='0' * 8193)
        self.assertRaises(exception.ValidationSizeError, self.api.authenticate,
                          {}, body_dict)
