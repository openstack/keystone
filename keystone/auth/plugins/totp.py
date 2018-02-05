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

"""Time-based One-time Password Algorithm (TOTP) auth plugin.

TOTP is an algorithm that computes a one-time password from a shared secret
key and the current time.

TOTP is an implementation of a hash-based message authentication code (HMAC).
It combines a secret key with the current timestamp using a cryptographic hash
function to generate a one-time password. The timestamp typically increases in
30-second intervals, so passwords generated close together in time from the
same secret key will be equal.
"""

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor import totp as crypto_totp
from oslo_log import log
from oslo_utils import timeutils
import six

from keystone.auth import plugins
from keystone.auth.plugins import base
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _


METHOD_NAME = 'totp'

LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


def _generate_totp_passcode(secret):
    """Generate TOTP passcode.

    :param bytes secret: A base32 encoded secret for the TOTP authentication
    :returns: totp passcode as bytes
    """
    if isinstance(secret, six.text_type):
        # NOTE(dstanek): since this may be coming from the JSON stored in the
        # database it may be UTF-8 encoded
        secret = secret.encode('utf-8')

    # NOTE(nonameentername): cryptography takes a non base32 encoded value for
    # TOTP. Add the correct padding to be able to base32 decode
    while len(secret) % 8 != 0:
        secret = secret + b'='

    decoded = base64.b32decode(secret)
    # NOTE(lhinds) This is marked as #nosec since bandit will see SHA1
    # which is marked as insecure. In this instance however, keystone uses
    # HMAC-SHA1 when generating the TOTP, which is currently not insecure but
    # will still trigger when scanned by bandit.
    totp = crypto_totp.TOTP(
        decoded, 6, hashes.SHA1(), 30, backend=default_backend())  # nosec
    return totp.generate(timeutils.utcnow_ts(microsecond=True)).decode('utf-8')


class TOTP(base.AuthMethodHandler):

    def authenticate(self, request, auth_payload):
        """Try to authenticate using TOTP."""
        response_data = {}
        user_info = plugins.TOTPUserInfo.create(auth_payload, METHOD_NAME)
        auth_passcode = auth_payload.get('user').get('passcode')

        credentials = PROVIDERS.credential_api.list_credentials_for_user(
            user_info.user_id, type='totp')

        valid_passcode = False
        for credential in credentials:
            try:
                generated_passcode = _generate_totp_passcode(
                    credential['blob'])
                if auth_passcode == generated_passcode:
                    valid_passcode = True
                    break
            except (ValueError, KeyError):
                LOG.debug('No TOTP match; credential id: %s, user_id: %s',
                          credential['id'], user_info.user_id)
            except (TypeError):
                LOG.debug('Base32 decode failed for TOTP credential %s',
                          credential['id'])

        if not valid_passcode:
            # authentication failed because of invalid username or passcode
            msg = _('Invalid username or TOTP passcode')
            raise exception.Unauthorized(msg)

        response_data['user_id'] = user_info.user_id

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)
