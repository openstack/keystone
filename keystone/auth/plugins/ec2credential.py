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

"""EC2 credential marker auth plugin.

This is a deliberately non-functional auth plugin. EC2 and S3 credentials
are validated and exchanged for tokens exclusively by the ``/v3/ec2tokens``
and ``/v3/s3tokens`` endpoints, which never invoke this plugin. Its sole
purpose is to give the ``ec2credential`` auth method -- the marker those
endpoints have recorded on the tokens they mint since the method was
introduced -- a registered identity, so that the marker survives the token
payload round-trip (the fernet provider encodes ``methods`` as a bitmask of
the configured auth methods, so an unregistered method is silently
dropped).

Preserving the method name is what allows the guards that reject
delegated-credential tokens (authorization in Keystone, token re-scoping,
trust / application credential / OAuth1 management) to recognize a token
that was minted from an EC2 or S3 credential (LP#2153453).
"""

from keystone.auth.plugins import base
from keystone import exception
from keystone.i18n import _

METHOD_NAME = 'ec2credential'


class Plugin(base.AuthMethodHandler):
    def authenticate(self, auth_payload):
        # EC2 credentials cannot be exchanged for a token via
        # /v3/auth/tokens; they must be presented to /v3/ec2tokens where
        # the signature is verified. Never authenticate through this method.
        raise exception.Unauthorized(
            _(
                'The ec2credential method cannot be used to authenticate '
                'via /v3/auth/tokens. Exchange your EC2 credentials at '
                '/v3/ec2tokens instead.'
            )
        )
