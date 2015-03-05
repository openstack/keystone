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

import datetime
import uuid

from cryptography import fernet
import msgpack
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import six

from keystone import exception
from keystone.token.providers.fernet import format_map as fm
from keystone.token.providers.fernet import utils


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class BaseTokenFormatter(object):
    """Base object for token formatters to inherit."""

    # NOTE(lbragstad): Each class the inherits BaseTokenFormatter should define
    # the `token_format` and `token_version`. The combination of the two should
    # be unique.
    token_format = None
    token_version = None

    @property
    def crypto(self):
        """Return a cryptography instance.

        You can extend this class with a custom crypto @property to provide
        your own token encoding / decoding. For example, using a different
        cryptography library (e.g. ``python-keyczar``) or to meet arbitrary
        security requirements.

        This @property just needs to return an object that implements
        ``encrypt(plaintext)`` and ``decrypt(ciphertext)``.

        """
        keys = utils.load_keys()

        if not keys:
            raise exception.KeysNotFound()

        fernet_instances = [fernet.Fernet(key) for key in utils.load_keys()]
        return fernet.MultiFernet(fernet_instances)

    def _convert_uuid_hex_to_bytes(self, uuid_string):
        """Compress UUID formatted strings to bytes.

        :param uuid_string: uuid string to compress to bytes
        :returns: a byte representation of the uuid

        """
        # TODO(lbragstad): Wrap this in an exception. Not sure what the case
        # would be where we couldn't handle what we've been given but incase
        # the integrity of the token has been compromised.
        uuid_obj = uuid.UUID(uuid_string)
        return uuid_obj.bytes

    def _convert_uuid_bytes_to_hex(self, uuid_byte_string):
        """Generate uuid.hex format based on byte string.

        :param uuid_byte_string: uuid string to generate from
        :returns: uuid hex formatted string

        """
        # TODO(lbragstad): Wrap this in an exception. Not sure what the case
        # would be where we couldn't handle what we've been given but incase
        # the integrity of the token has been compromised.
        uuid_obj = uuid.UUID(bytes=uuid_byte_string)
        return uuid_obj.hex

    def _convert_time_string_to_int(self, time_string):
        """Convert a time formatted string to a timestamp integer.

        :param time_string: time formatted string
        :returns: an integer timestamp

        """
        time_object = timeutils.parse_isotime(time_string)
        return int(time_object.strftime('%s'))

    def _convert_int_to_time_string(self, time_int):
        """Convert a timestamp integer to a string.

        :param time_int: integer representing time
        :returns: a time formatted string

        """
        time_object = datetime.datetime.fromtimestamp(int(time_int))
        return timeutils.isotime(time_object)

    def pack(self, payload):
        """Pack a payload for transport."""
        msgpacked = msgpack.packb(payload)
        encrypted = self.crypto.encrypt(msgpacked)

        # Tack the token format on to the encrypted_token
        return self.token_format + encrypted

    def unpack(self, token_string):
        """Unpack and validate a payload."""
        try:
            decrypted_token = self.crypto.decrypt(token_string)
        except fernet.InvalidToken as e:
            raise exception.Unauthorized(six.text_type(e))

        # TODO(lbragstad): catch msgpack errors here
        payload = msgpack.unpackb(decrypted_token)

        return payload


class UnscopedTokenFormatter(BaseTokenFormatter):

    token_format = fm.UNSCOPED_TOKEN_PREFIX

    def create_token(self, user_id, created_at, expires_at, audit_ids):
        """Create a unscoped token.

        :param user_id: identifier of the user in the token request
        :param created_at: datetime of the token's creation
        :param expires_at_int: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :returns: a string representing the token

        """
        b_user_id = self._convert_uuid_hex_to_bytes(user_id)
        issued_at_int = self._convert_time_string_to_int(created_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)
        payload = (b_user_id, issued_at_int, expires_at_int, audit_ids)

        return self.pack(payload)

    def validate_token(self, token_string):
        """Validate an unscoped token.

        :param token_string: a string representing the token
        :returns: a tuple containing the user_id, issued_at_str,
                  expires_at_str, audit_ids

        """
        payload = self.unpack(token_string)

        # Rebuild and retrieve token information from the token string
        b_user_id = payload[0]
        issued_at_ts = payload[1]
        expires_at_ts = payload[2]
        audit_ids = payload[3]

        user_id = self._convert_uuid_bytes_to_hex(b_user_id)

        issued_at_str = self._convert_int_to_time_string(issued_at_ts)
        expires_at_str = self._convert_int_to_time_string(expires_at_ts)

        return (user_id, issued_at_str, expires_at_str, audit_ids)


class ScopedTokenFormatter(BaseTokenFormatter):

    token_format = fm.SCOPED_TOKEN_PREFIX

    def create_token(self, user_id, project_id, created_at, expires_at,
                     audit_ids):
        """Create a standard formatted token.

        :param user_id: ID of the user in the token request
        :param project_id: ID of the project to scope to
        :param created_at: datetime of the token's creation
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :returns: a string representing the token

        """
        issued_at_int = self._convert_time_string_to_int(created_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)
        b_user_id = self._convert_uuid_hex_to_bytes(user_id)
        if project_id:
            b_scope_id = self._convert_uuid_hex_to_bytes(project_id)
            payload = (
                b_user_id, b_scope_id, issued_at_int, expires_at_int,
                audit_ids)
        else:
            payload = (b_user_id, issued_at_int, expires_at_int, audit_ids)

        return self.pack(payload)

    def validate_token(self, token_string):
        """Validate a F00 formatted token.

        :param token_string: a string representing the token
        :returns: a tuple containing the user_id, project_id, issued_at_str,
                 expires_at_str, and audit_ids

        """
        payload = self.unpack(token_string)

        # Rebuild and retrieve token information from the token string
        b_user_id = payload[0]
        b_project_id = None
        if isinstance(payload[1], str):
            b_project_id = payload[1]
            issued_at_ts = payload[2]
            expires_at_ts = payload[3]
            audit_ids = payload[4]
        else:
            issued_at_ts = payload[1]
            expires_at_ts = payload[2]
            audit_ids = payload[3]

        # Uncompress the IDs
        user_id = self._convert_uuid_bytes_to_hex(b_user_id)
        project_id = None
        if b_project_id:
            project_id = self._convert_uuid_bytes_to_hex(b_project_id)

        # Generate created at and expires at times
        issued_at_str = self._convert_int_to_time_string(issued_at_ts)
        expires_at_str = self._convert_int_to_time_string(expires_at_ts)

        return (user_id, project_id, issued_at_str, expires_at_str, audit_ids)


class TrustTokenFormatter(BaseTokenFormatter):

    token_format = fm.TRUST_TOKEN_PREFIX

    def create_token(self, user_id, project_id, created_at, expires_at,
                     audit_ids, trust_id):
        """Create a trust formatted token.

        :param user_id: ID of the user in the token request
        :param project_id: ID of the project to scope to
        :param created_at: datetime of the token's creation
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param trust_id: ID of the trust in effect
        :returns: a string representing the token

        """
        issued_at_int = self._convert_time_string_to_int(created_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)
        b_user_id = self._convert_uuid_hex_to_bytes(user_id)
        b_project_id = self._convert_uuid_hex_to_bytes(project_id)
        b_trust_id = self._convert_uuid_hex_to_bytes(trust_id)
        payload = (b_user_id, b_project_id, b_trust_id, issued_at_int,
                   expires_at_int, audit_ids)

        return self.pack(payload)

    def validate_token(self, token_string):
        """Validate a trust formatted token.

        :param token_string: a string representing the token
        :returns: a tuple containing the user_id, project_id, issued_at_str,
                  expires_at_str, audit_ids, and trust_id

        """
        payload = self.unpack(token_string)

        # Rebuild and retrieve token information from the token string
        b_user_id = payload[0]
        b_project_id = payload[1]
        b_trust_id = payload[2]
        issued_at_ts = payload[3]
        expires_at_ts = payload[4]
        audit_ids = payload[5]

        # Uncompress the IDs
        user_id = self._convert_uuid_bytes_to_hex(b_user_id)
        project_id = self._convert_uuid_bytes_to_hex(b_project_id)
        trust_id = self._convert_uuid_bytes_to_hex(b_trust_id)
        # Generate created at and expires at times
        issued_at_str = self._convert_int_to_time_string(issued_at_ts)
        expires_at_str = self._convert_int_to_time_string(expires_at_ts)

        return (user_id, project_id, issued_at_str, expires_at_str, audit_ids,
                trust_id)
