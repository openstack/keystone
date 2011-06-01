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

import ksapi
import simplerest


options = None


def _get_ksapi(url):
    """Get an instance of KeystoneAPI20."""

    # If debug mode has been enabled, let's select a debug stream
    dbstream = None
    if options.debug:
        dbstream = dtest.status

    # Build and return the API object
    return ksapi.KeystoneAPI20(url, dbstream)


class BaseKeystoneTest(dtest.DTestCase):
    """Base class for Keystone tests."""

    def setUp(self):
        """Initialize tests by setting up a KeystoneAPI20 to call."""

        # Build the API objects
        self.ks = _get_ksapi(options.keystone)
        self.ks_admin = _get_ksapi(options.keystone_admin)


class KeystoneTest(BaseKeystoneTest):
    """Base class for Keystone tests."""

    user_tok = None
    user_expire = None
    admin_tok = None
    admin_expire = None

    @classmethod
    def setUpClass(cls):
        """Initialize tests by setting up a keystone token."""

        # Get an API object
        ks = _get_ksapi(options.keystone)

        # Next, let's authenticate and get a user token
        resp = ks.authenticate(options.username, options.password)

        # Save the authentication token and other data
        cls.user_tok = resp.obj['auth']['token']['id']
        cls.user_expire = resp.obj['auth']['token']['expires']

        # Now, let's get an admin token
        resp = ks.authenticate(options.adminuser, options.adminpass)

        # Save the authentication token and other data
        cls.admin_tok = resp.obj['auth']['token']['id']
        cls.admin_expire = resp.obj['auth']['token']['expires']

    @classmethod
    def tearDownClass(cls):
        """Revoke the authentication token."""

        # Get an API object
        ks = _get_ksapi(options.keystone_admin)

        try:
            # First, let's revoke the user token
            resp = ks.revoke_token(cls.admin_tok, cls.user_tok)
        except simplerest.RESTException:
            # Ignore errors revoking the token
            pass

        try:
            # Now, let's revoke the admin token
            resp = ks.revoke_token(cls.admin_tok, cls.admin_tok)
        except simplerest.RESTException:
            # Ignore errors revoking the token
            pass

        # For completeness sake...
        cls.token = None
