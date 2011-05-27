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


options = None


def _get_ksapi():
    """Get an instance of KeystoneAPI20."""

    # If debug mode has been enabled, let's select a debug stream
    dbstream = None
    if options.debug:
        dbstream = dtest.status

    # Build and return the API object
    return ksapi.KeystoneAPI20(options.keystone, dbstream)


class BaseKeystoneTest(dtest.DTestCase):
    """Base class for Keystone tests."""

    def setUp(self):
        """Initialize tests by setting up a KeystoneAPI20 to call."""

        # Build the API object
        self.ks = _get_ksapi()


class KeystoneTest(BaseKeystoneTest):
    """Base class for Keystone tests."""

    token = None

    @classmethod
    def setUpClass(cls):
        """Initialize tests by setting up a keystone token."""

        # Get an API object
        ks = _get_ksapi()

        # Next, let's authenticate
        resp = ks.authenticate(options.username, options.password)

        # Finally, save the authentication token
        cls.token = resp.obj['auth']['token']['id']

    @classmethod
    def tearDownClass(cls):
        """Revoke the authentication token."""

        # Get an API object
        ks = _get_ksapi()

        # Now, let's revoke the token
        resp = ks.revoke_token(cls.token, cls.token)

        # For completeness sake...
        cls.token = None
