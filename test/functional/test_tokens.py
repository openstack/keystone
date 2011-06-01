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

        # Now, issue a secondary authentication request
        resp = self.ks.authenticate(base.options.username,
                                    base.options.password)

        # Verify that resp is correct
        util.assert_equal(resp.status, 200)
        util.assert_in('auth', resp.obj)
        util.assert_in('token', resp.obj['auth'])
        util.assert_in('id', resp.obj['auth']['token'])

        # Now ensure we can revoke an authentication token
        auth_tok = resp.obj['auth']['token']['id']
        with util.assert_raises(simplerest.UnauthorizedException):
            resp = self.ks_admin.revoke_token(admin_tok, auth_tok)
            util.assert_equal(resp.status, 204)


# Ensure that all remaining tests wait for test_authenticate
dtest.depends(AuthenticateTest.test_authenticate)(base.KeystoneTest.setUpClass)
