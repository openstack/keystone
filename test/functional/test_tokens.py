# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import dtest
from dtest import util

import base
import simplerest


class AuthenticateTest(base.BaseKeystoneTest):
    def test_authenticate(self):
        """Test that we can authenticate using Keystone."""

        # Issue the authentication request
        resp = self.ks.authenticate(base.options.adminuser,
                                    base.options.adminpass)

        # Verify that resp is correct
        util.assert_equal(resp.status, 200)
        util.assert_in('auth', resp.obj)
        util.assert_in('token', resp.obj['auth'])
        util.assert_in('expires', resp.obj['auth']['token'])
        util.assert_in('id', resp.obj['auth']['token'])

        # Squirrel away the admin token ID
        admin_tok = resp.obj['auth']['token']['id']

        # Now ensure we can revoke an authentication token
        resp = self.ks_admin.revoke_token(admin_tok, admin_tok)
        util.assert_equal(resp.status, 204)

    @dtest.depends(test_authenticate)
    def test_adminauth(self):
        """Test that we can authenticate using Keystone Admin API."""

        # Issue the authentication request
        resp = self.ks_admin.authenticate(base.options.adminuser,
                                          base.options.adminpass)

        # Verify that resp is correct
        util.assert_equal(resp.status, 200)
        util.assert_in('auth', resp.obj)
        util.assert_in('token', resp.obj['auth'])
        util.assert_in('expires', resp.obj['auth']['token'])
        util.assert_in('id', resp.obj['auth']['token'])

        # Squirrel away the admin token ID
        admin_tok = resp.obj['auth']['token']['id']

        # Now ensure we can revoke an authentication token
        resp = self.ks_admin.revoke_token(admin_tok, admin_tok)
        util.assert_equal(resp.status, 204)


# Ensure that all remaining tests wait for test_authenticate
dtest.depends(AuthenticateTest.test_authenticate,
              AuthenticateTest.test_adminauth)(base.KeystoneTest.setUpClass)


class ValidateTest(base.KeystoneTest):
    def test_validate(self):
        """Test that we can validate tokens using Keystone."""

        # Issue the validation request
        resp = self.ks_admin.validate_token(self.admin_tok, self.user_tok)

        # Verify that resp is correct
        util.assert_equal(resp.status, 200)
        util.assert_in('auth', resp.obj)
        util.assert_in('token', resp.obj['auth'])
        util.assert_in('expires', resp.obj['auth']['token'])
        util.assert_equal(resp.obj['auth']['token']['expires'],
                          self.user_expire)
        util.assert_in('id', resp.obj['auth']['token'])
        util.assert_equal(resp.obj['auth']['token']['id'], self.user_tok)
        util.assert_in('user', resp.obj['auth'])
        util.assert_in('username', resp.obj['auth']['user'])
        util.assert_equal(resp.obj['auth']['user']['username'],
                          base.options.username)
