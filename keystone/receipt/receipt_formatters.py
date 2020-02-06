# Copyright 2018 Catalyst Cloud Ltd
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

import base64
import datetime
import struct
import uuid

from cryptography import fernet
import msgpack
from oslo_log import log
from oslo_utils import timeutils

from keystone.auth import plugins as auth_plugins
from keystone.common import fernet_utils as utils
from keystone.common import utils as ks_utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

# Fernet byte indexes as computed by pypi/keyless_fernet and defined in
# https://github.com/fernet/spec
TIMESTAMP_START = 1
TIMESTAMP_END = 9


class ReceiptFormatter(object):
    """Packs and unpacks payloads into receipts for transport."""

    @property
    def crypto(self):
        """Return a cryptography instance.

        You can extend this class with a custom crypto @property to provide
        your own receipt encoding / decoding. For example, using a different
        cryptography library (e.g. ``python-keyczar``) or to meet arbitrary
        security requirements.

        This @property just needs to return an object that implements
        ``encrypt(plaintext)`` and ``decrypt(ciphertext)``.

        """
        fernet_utils = utils.FernetUtils(
            CONF.fernet_receipts.key_repository,
            CONF.fernet_receipts.max_active_keys,
            'fernet_receipts'
        )
        keys = fernet_utils.load_keys()

        if not keys:
            raise exception.KeysNotFound()

        fernet_instances = [fernet.Fernet(key) for key in keys]
        return fernet.MultiFernet(fernet_instances)

    def pack(self, payload):
        """Pack a payload for transport as a receipt.

        :type payload: bytes
        :rtype: str

        """
        # base64 padding (if any) is not URL-safe
        return self.crypto.encrypt(payload).rstrip(b'=').decode('utf-8')

    def unpack(self, receipt):
        """Unpack a receipt, and validate the payload.

        :type receipt: str
        :rtype: bytes

        """
        receipt = ReceiptFormatter.restore_padding(receipt)

        try:
            return self.crypto.decrypt(receipt.encode('utf-8'))
        except fernet.InvalidToken:
            raise exception.ValidationError(
                _('This is not a recognized Fernet receipt %s') % receipt)

    @classmethod
    def restore_padding(cls, receipt):
        """Restore padding based on receipt size.

        :param receipt: receipt to restore padding on
        :type receipt: str
        :returns: receipt with correct padding

        """
        # Re-inflate the padding
        mod_returned = len(receipt) % 4
        if mod_returned:
            missing_padding = 4 - mod_returned
            receipt += '=' * missing_padding
        return receipt

    @classmethod
    def creation_time(cls, fernet_receipt):
        """Return the creation time of a valid Fernet receipt.

        :type fernet_receipt: str

        """
        fernet_receipt = ReceiptFormatter.restore_padding(fernet_receipt)
        # fernet_receipt is str

        # Fernet receipts are base64 encoded, so we need to unpack them first
        # urlsafe_b64decode() requires bytes
        receipt_bytes = base64.urlsafe_b64decode(
            fernet_receipt.encode('utf-8'))

        # slice into the byte array to get just the timestamp
        timestamp_bytes = receipt_bytes[TIMESTAMP_START:TIMESTAMP_END]

        # convert those bytes to an integer
        # (it's a 64-bit "unsigned long long int" in C)
        timestamp_int = struct.unpack(">Q", timestamp_bytes)[0]

        # and with an integer, it's trivial to produce a datetime object
        issued_at = datetime.datetime.utcfromtimestamp(timestamp_int)

        return issued_at

    def create_receipt(self, user_id, methods, expires_at):
        """Given a set of payload attributes, generate a Fernet receipt."""
        payload = ReceiptPayload.assemble(user_id, methods, expires_at)

        serialized_payload = msgpack.packb(payload)
        receipt = self.pack(serialized_payload)

        # NOTE(lbragstad): We should warn against Fernet receipts that are over
        # 255 characters in length. This is mostly due to persisting the
        # receipts in a backend store of some kind that might have a limit of
        # 255 characters. Even though Keystone isn't storing a Fernet receipt
        # anywhere, we can't say it isn't being stored somewhere else with
        # those kind of backend constraints.
        if len(receipt) > 255:
            LOG.info('Fernet receipt created with length of %d '
                     'characters, which exceeds 255 characters',
                     len(receipt))

        return receipt

    def validate_receipt(self, receipt):
        """Validate a Fernet receipt and returns the payload attributes.

        :type receipt: str

        """
        serialized_payload = self.unpack(receipt)
        payload = msgpack.unpackb(serialized_payload)

        (user_id, methods, expires_at) = ReceiptPayload.disassemble(payload)

        # rather than appearing in the payload, the creation time is encoded
        # into the receipt format itself
        issued_at = ReceiptFormatter.creation_time(receipt)
        issued_at = ks_utils.isotime(at=issued_at, subsecond=True)
        expires_at = timeutils.parse_isotime(expires_at)
        expires_at = ks_utils.isotime(at=expires_at, subsecond=True)

        return (user_id, methods, issued_at, expires_at)


class ReceiptPayload(object):

    @classmethod
    def assemble(cls, user_id, methods, expires_at):
        """Assemble the payload of a receipt.

        :param user_id: identifier of the user in the receipt request
        :param methods: list of authentication methods used
        :param expires_at: datetime of the receipt's expiration
        :returns: the payload of a receipt

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        return (b_user_id, methods, expires_at_int)

    @classmethod
    def disassemble(cls, payload):
        """Disassemble a payload into the component data.

        The tuple consists of::

            (user_id, methods, expires_at_str)

        * ``methods`` are the auth methods.

        :param payload: this variant of payload
        :returns: a tuple of the payloads component data

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        expires_at_str = cls._convert_float_to_time_string(payload[2])
        return (user_id, methods, expires_at_str)

    @classmethod
    def convert_uuid_hex_to_bytes(cls, uuid_string):
        """Compress UUID formatted strings to bytes.

        :param uuid_string: uuid string to compress to bytes
        :returns: a byte representation of the uuid

        """
        uuid_obj = uuid.UUID(uuid_string)
        return uuid_obj.bytes

    @classmethod
    def convert_uuid_bytes_to_hex(cls, uuid_byte_string):
        """Generate uuid.hex format based on byte string.

        :param uuid_byte_string: uuid string to generate from
        :returns: uuid hex formatted string

        """
        uuid_obj = uuid.UUID(bytes=uuid_byte_string)
        return uuid_obj.hex

    @classmethod
    def _convert_time_string_to_float(cls, time_string):
        """Convert a time formatted string to a float.

        :param time_string: time formatted string
        :returns: a timestamp as a float

        """
        time_object = timeutils.parse_isotime(time_string)
        return (timeutils.normalize_time(time_object) -
                datetime.datetime.utcfromtimestamp(0)).total_seconds()

    @classmethod
    def _convert_float_to_time_string(cls, time_float):
        """Convert a floating point timestamp to a string.

        :param time_float: integer representing timestamp
        :returns: a time formatted strings

        """
        time_object = datetime.datetime.utcfromtimestamp(time_float)
        return ks_utils.isotime(time_object, subsecond=True)

    @classmethod
    def attempt_convert_uuid_hex_to_bytes(cls, value):
        """Attempt to convert value to bytes or return value.

        :param value: value to attempt to convert to bytes
        :returns: tuple containing boolean indicating whether user_id was
                  stored as bytes and uuid value as bytes or the original value

        """
        try:
            return (True, cls.convert_uuid_hex_to_bytes(value))
        except ValueError:
            # this might not be a UUID, depending on the situation (i.e.
            # federation)
            return (False, value)

    @classmethod
    def base64_encode(cls, s):
        """Encode a URL-safe string.

        :type s: str
        :rtype: str

        """
        # urlsafe_b64encode() returns bytes so need to convert to
        # str, might as well do it before stripping.
        return base64.urlsafe_b64encode(s).decode('utf-8').rstrip('=')

    @classmethod
    def random_urlsafe_str_to_bytes(cls, s):
        """Convert string from :func:`random_urlsafe_str()` to bytes.

        :type s: str
        :rtype: bytes

        """
        # urlsafe_b64decode() requires str, unicode isn't accepted.
        s = str(s)

        # restore the padding (==) at the end of the string
        return base64.urlsafe_b64decode(s + '==')
