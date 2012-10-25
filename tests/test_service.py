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

from keystone import exception
from keystone import identity
from keystone import service
from keystone import test


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
                          None, body_dict)

    def test_authenticate_no_username(self):
        """Verify skipping username raises the right exception."""
        body_dict = {'passwordCredentials': {'password': 'pass'},
                     'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          None, body_dict)

    def test_authenticate_no_password(self):
        """Verify skipping password raises the right exception."""
        body_dict = {'passwordCredentials': {'username': 'user1'},
                     'tenantName': 'demo'}
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          None, body_dict)

    def test_authenticate_blank_request_body(self):
        """Verify sending empty json dict raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          None, {})

    def test_authenticate_blank_auth(self):
        """Verify sending blank 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          None, {'auth': {}})

    def test_authenticate_invalid_auth_content(self):
        """Verify sending invalid 'auth' raises the right exception."""
        self.assertRaises(exception.ValidationError, self.api.authenticate,
                          None, {'auth': 'abcd'})
