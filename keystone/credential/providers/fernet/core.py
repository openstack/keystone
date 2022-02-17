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

import hashlib

from cryptography import fernet
from oslo_log import log

from keystone.common import fernet_utils
import keystone.conf
from keystone.credential.providers import core
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

# NOTE(lbragstad): Credential key rotation operates slightly different than
# token key rotation. Each credential holds a hash of the key that encrypted
# it. This is important for credential key rotation because it helps us make
# sure we don't over-rotate credential keys. During a rotation of credential
# keys, if any credential has not been re-encrypted with the current primary
# key, we can abandon the key rotation until all credentials have been migrated
# to the new primary key. If we don't take this step, it is possible that we
# could remove a key used to encrypt credentials, leaving them unrecoverable.
# This also means that we don't need to expose a `[credential] max_active_keys`
# option through configuration. Instead we will use a global variable and share
# that across all places that need to use FernetUtils for credential
# encryption.
MAX_ACTIVE_KEYS = 3


def get_multi_fernet_keys():
    key_utils = fernet_utils.FernetUtils(
        CONF.credential.key_repository, MAX_ACTIVE_KEYS,
        'credential')
    keys = key_utils.load_keys(use_null_key=True)

    fernet_keys = [fernet.Fernet(key) for key in keys]
    crypto = fernet.MultiFernet(fernet_keys)

    return crypto, keys


def primary_key_hash(keys):
    """Calculate a hash of the primary key used for encryption."""
    if isinstance(keys[0], str):
        keys[0] = keys[0].encode('utf-8')
    # NOTE(lhinds) This is marked as #nosec since bandit will see SHA1 which
    # is marked as insecure. However, this hash function is used alongside
    # encrypted blobs to implement HMAC-SHA1, which is currently not insecure
    # but will still trigger when scanned by bandit.
    return hashlib.sha1(keys[0]).hexdigest()  # nosec


class Provider(core.Provider):
    def encrypt(self, credential):
        """Attempt to encrypt a plaintext credential.

        :param credential: a plaintext representation of a credential
        :returns: an encrypted credential
        """
        crypto, keys = get_multi_fernet_keys()

        if keys[0] == fernet_utils.NULL_KEY:
            LOG.warning(
                'Encrypting credentials with the null key. Please properly '
                'encrypt credentials using `keystone-manage credential_setup`,'
                ' `keystone-manage credential_migrate`, and `keystone-manage '
                'credential_rotate`')

        try:
            return (
                crypto.encrypt(credential.encode('utf-8')),
                primary_key_hash(keys))
        except (TypeError, ValueError) as e:
            msg = 'Credential could not be encrypted: %s' % str(e)
            tr_msg = _('Credential could not be encrypted: %s') % str(e)
            LOG.error(msg)
            raise exception.CredentialEncryptionError(tr_msg)

    def decrypt(self, credential):
        """Attempt to decrypt a credential.

        :param credential: an encrypted credential string
        :returns: a decrypted credential
        """
        key_utils = fernet_utils.FernetUtils(
            CONF.credential.key_repository, MAX_ACTIVE_KEYS, 'credential')
        keys = key_utils.load_keys(use_null_key=True)
        fernet_keys = [fernet.Fernet(key) for key in keys]
        crypto = fernet.MultiFernet(fernet_keys)

        try:
            if isinstance(credential, str):
                credential = credential.encode('utf-8')
            return crypto.decrypt(credential).decode('utf-8')
        except (fernet.InvalidToken, TypeError, ValueError):
            msg = ('Credential could not be decrypted. Please contact the '
                   'administrator')
            tr_msg = _('Credential could not be decrypted. Please contact the '
                       'administrator')
            LOG.error(msg)
            raise exception.CredentialEncryptionError(tr_msg)
