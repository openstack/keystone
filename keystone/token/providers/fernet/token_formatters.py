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
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import six
from six.moves import map
from six.moves import urllib

from keystone.auth import plugins as auth_plugins
from keystone.common import utils as ks_utils
from keystone import exception
from keystone.i18n import _, _LI
from keystone.token import provider
from keystone.token.providers.fernet import utils


CONF = cfg.CONF
LOG = log.getLogger(__name__)

# Fernet byte indexes as as computed by pypi/keyless_fernet and defined in
# https://github.com/fernet/spec
TIMESTAMP_START = 1
TIMESTAMP_END = 9


class TokenFormatter(object):
    """Packs and unpacks payloads into tokens for transport."""

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

        fernet_instances = [fernet.Fernet(key) for key in keys]
        return fernet.MultiFernet(fernet_instances)

    def pack(self, payload):
        """Pack a payload for transport as a token."""
        # base64 padding (if any) is not URL-safe
        return self.crypto.encrypt(payload).rstrip('=')

    def unpack(self, token):
        """Unpack a token, and validate the payload."""
        token = six.binary_type(token)

        # TODO(lbragstad): Restore padding on token before decoding it.
        # Initially in Kilo, Fernet tokens were returned to the user with
        # padding appended to the token. Later in Liberty this padding was
        # removed and restored in the Fernet provider. The following if
        # statement ensures that we can validate tokens with and without token
        # padding, in the event of an upgrade and the tokens that are issued
        # throughout the upgrade. Remove this if statement when Mitaka opens
        # for development and exclusively use the restore_padding() class
        # method.
        if token.endswith('%3D'):
            token = urllib.parse.unquote(token)
        else:
            token = TokenFormatter.restore_padding(token)

        try:
            return self.crypto.decrypt(token)
        except fernet.InvalidToken:
            raise exception.ValidationError(
                _('This is not a recognized Fernet token'))

    @classmethod
    def restore_padding(cls, token):
        """Restore padding based on token size.

        :param token: token to restore padding on
        :returns: token with correct padding

        """
        # Re-inflate the padding
        mod_returned = len(token) % 4
        if mod_returned:
            missing_padding = 4 - mod_returned
            token += b'=' * missing_padding
        return token

    @classmethod
    def creation_time(cls, fernet_token):
        """Returns the creation time of a valid Fernet token."""
        # tokens may be transmitted as Unicode, but they're just ASCII
        # (pypi/cryptography will refuse to operate on Unicode input)
        fernet_token = six.binary_type(fernet_token)

        # Restore padding on token before decoding it
        fernet_token = TokenFormatter.restore_padding(fernet_token)

        # fernet tokens are base64 encoded, so we need to unpack them first
        token_bytes = base64.urlsafe_b64decode(fernet_token)

        # slice into the byte array to get just the timestamp
        timestamp_bytes = token_bytes[TIMESTAMP_START:TIMESTAMP_END]

        # convert those bytes to an integer
        # (it's a 64-bit "unsigned long long int" in C)
        timestamp_int = struct.unpack(">Q", timestamp_bytes)[0]

        # and with an integer, it's trivial to produce a datetime object
        created_at = datetime.datetime.utcfromtimestamp(timestamp_int)

        return created_at

    def create_token(self, user_id, expires_at, audit_ids, methods=None,
                     domain_id=None, project_id=None, trust_id=None,
                     federated_info=None):
        """Given a set of payload attributes, generate a Fernet token."""
        if trust_id:
            version = TrustScopedPayload.version
            payload = TrustScopedPayload.assemble(
                user_id,
                methods,
                project_id,
                expires_at,
                audit_ids,
                trust_id)
        elif project_id and federated_info:
            version = FederatedProjectScopedPayload.version
            payload = FederatedProjectScopedPayload.assemble(
                user_id,
                methods,
                project_id,
                expires_at,
                audit_ids,
                federated_info)
        elif domain_id and federated_info:
            version = FederatedDomainScopedPayload.version
            payload = FederatedDomainScopedPayload.assemble(
                user_id,
                methods,
                domain_id,
                expires_at,
                audit_ids,
                federated_info)
        elif federated_info:
            version = FederatedUnscopedPayload.version
            payload = FederatedUnscopedPayload.assemble(
                user_id,
                methods,
                expires_at,
                audit_ids,
                federated_info)
        elif project_id:
            version = ProjectScopedPayload.version
            payload = ProjectScopedPayload.assemble(
                user_id,
                methods,
                project_id,
                expires_at,
                audit_ids)
        elif domain_id:
            version = DomainScopedPayload.version
            payload = DomainScopedPayload.assemble(
                user_id,
                methods,
                domain_id,
                expires_at,
                audit_ids)
        else:
            version = UnscopedPayload.version
            payload = UnscopedPayload.assemble(
                user_id,
                methods,
                expires_at,
                audit_ids)

        versioned_payload = (version,) + payload
        serialized_payload = msgpack.packb(versioned_payload)
        token = self.pack(serialized_payload)

        # NOTE(lbragstad): We should warn against Fernet tokens that are over
        # 255 characters in length. This is mostly due to persisting the tokens
        # in a backend store of some kind that might have a limit of 255
        # characters. Even though Keystone isn't storing a Fernet token
        # anywhere, we can't say it isn't being stored somewhere else with
        # those kind of backend constraints.
        if len(token) > 255:
            LOG.info(_LI('Fernet token created with length of %d '
                         'characters, which exceeds 255 characters'),
                     len(token))

        return token

    def validate_token(self, token):
        """Validates a Fernet token and returns the payload attributes."""
        # Convert v2 unicode token to a string
        if not isinstance(token, six.binary_type):
            token = token.encode('ascii')

        serialized_payload = self.unpack(token)
        versioned_payload = msgpack.unpackb(serialized_payload)
        version, payload = versioned_payload[0], versioned_payload[1:]

        # depending on the formatter, these may or may not be defined
        domain_id = None
        project_id = None
        trust_id = None
        federated_info = None

        if version == UnscopedPayload.version:
            (user_id, methods, expires_at, audit_ids) = (
                UnscopedPayload.disassemble(payload))
        elif version == DomainScopedPayload.version:
            (user_id, methods, domain_id, expires_at, audit_ids) = (
                DomainScopedPayload.disassemble(payload))
        elif version == ProjectScopedPayload.version:
            (user_id, methods, project_id, expires_at, audit_ids) = (
                ProjectScopedPayload.disassemble(payload))
        elif version == TrustScopedPayload.version:
            (user_id, methods, project_id, expires_at, audit_ids, trust_id) = (
                TrustScopedPayload.disassemble(payload))
        elif version == FederatedUnscopedPayload.version:
            (user_id, methods, expires_at, audit_ids, federated_info) = (
                FederatedUnscopedPayload.disassemble(payload))
        elif version == FederatedProjectScopedPayload.version:
            (user_id, methods, project_id, expires_at, audit_ids,
             federated_info) = FederatedProjectScopedPayload.disassemble(
                payload)
        elif version == FederatedDomainScopedPayload.version:
            (user_id, methods, domain_id, expires_at, audit_ids,
             federated_info) = FederatedDomainScopedPayload.disassemble(
                payload)
        else:
            # If the token_format is not recognized, raise ValidationError.
            raise exception.ValidationError(_(
                'This is not a recognized Fernet payload version: %s') %
                version)

        # rather than appearing in the payload, the creation time is encoded
        # into the token format itself
        created_at = TokenFormatter.creation_time(token)
        created_at = ks_utils.isotime(at=created_at, subsecond=True)
        expires_at = timeutils.parse_isotime(expires_at)
        expires_at = ks_utils.isotime(at=expires_at, subsecond=True)

        return (user_id, methods, audit_ids, domain_id, project_id, trust_id,
                federated_info, created_at, expires_at)


class BasePayload(object):
    # each payload variant should have a unique version
    version = None

    @classmethod
    def assemble(cls, *args):
        """Assemble the payload of a token.

        :param args: whatever data should go into the payload
        :returns: the payload of a token

        """
        raise NotImplementedError()

    @classmethod
    def disassemble(cls, payload):
        """Disassemble an unscoped payload into the component data.

        :param payload: this variant of payload
        :returns: a tuple of the payloads component data

        """
        raise NotImplementedError()

    @classmethod
    def convert_uuid_hex_to_bytes(cls, uuid_string):
        """Compress UUID formatted strings to bytes.

        :param uuid_string: uuid string to compress to bytes
        :returns: a byte representation of the uuid

        """
        # TODO(lbragstad): Wrap this in an exception. Not sure what the case
        # would be where we couldn't handle what we've been given but incase
        # the integrity of the token has been compromised.
        uuid_obj = uuid.UUID(uuid_string)
        return uuid_obj.bytes

    @classmethod
    def convert_uuid_bytes_to_hex(cls, uuid_byte_string):
        """Generate uuid.hex format based on byte string.

        :param uuid_byte_string: uuid string to generate from
        :returns: uuid hex formatted string

        """
        # TODO(lbragstad): Wrap this in an exception. Not sure what the case
        # would be where we couldn't handle what we've been given but incase
        # the integrity of the token has been compromised.
        uuid_obj = uuid.UUID(bytes=uuid_byte_string)
        return uuid_obj.hex

    @classmethod
    def _convert_time_string_to_int(cls, time_string):
        """Convert a time formatted string to a timestamp integer.

        :param time_string: time formatted string
        :returns: an integer timestamp

        """
        time_object = timeutils.parse_isotime(time_string)
        return (timeutils.normalize_time(time_object) -
                datetime.datetime.utcfromtimestamp(0)).total_seconds()

    @classmethod
    def _convert_int_to_time_string(cls, time_int):
        """Convert a timestamp integer to a string.

        :param time_int: integer representing timestamp
        :returns: a time formatted strings

        """
        time_object = datetime.datetime.utcfromtimestamp(time_int)
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
    def attempt_convert_uuid_bytes_to_hex(cls, value):
        """Attempt to convert value to hex or return value.

        :param value: value to attempt to convert to hex
        :returns: uuid value in hex or value

        """
        try:
            return cls.convert_uuid_bytes_to_hex(value)
        except ValueError:
            return value


class UnscopedPayload(BasePayload):
    version = 0

    @classmethod
    def assemble(cls, user_id, methods, expires_at, audit_ids):
        """Assemble the payload of an unscoped token.

        :param user_id: identifier of the user in the token request
        :param methods: list of authentication methods used
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :returns: the payload of an unscoped token

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        """Disassemble an unscoped payload into the component data.

        :param payload: the payload of an unscoped token
        :return: a tuple containing the user_id, auth methods, expires_at, and
                 audit_ids

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        expires_at_str = cls._convert_int_to_time_string(payload[2])
        audit_ids = list(map(provider.base64_encode, payload[3]))
        return (user_id, methods, expires_at_str, audit_ids)


class DomainScopedPayload(BasePayload):
    version = 1

    @classmethod
    def assemble(cls, user_id, methods, domain_id, expires_at, audit_ids):
        """Assemble the payload of a domain-scoped token.

        :param user_id: ID of the user in the token request
        :param methods: list of authentication methods used
        :param domain_id: ID of the domain to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :returns: the payload of a domain-scoped token

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        try:
            b_domain_id = cls.convert_uuid_hex_to_bytes(domain_id)
        except ValueError:
            # the default domain ID is configurable, and probably isn't a UUID
            if domain_id == CONF.identity.default_domain_id:
                b_domain_id = domain_id
            else:
                raise
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_domain_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        """Disassemble a payload into the component data.

        :param payload: the payload of a token
        :return: a tuple containing the user_id, auth methods, domain_id,
                 expires_at_str, and audit_ids

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        try:
            domain_id = cls.convert_uuid_bytes_to_hex(payload[2])
        except ValueError:
            # the default domain ID is configurable, and probably isn't a UUID
            if payload[2] == CONF.identity.default_domain_id:
                domain_id = payload[2]
            else:
                raise
        expires_at_str = cls._convert_int_to_time_string(payload[3])
        audit_ids = list(map(provider.base64_encode, payload[4]))

        return (user_id, methods, domain_id, expires_at_str, audit_ids)


class ProjectScopedPayload(BasePayload):
    version = 2

    @classmethod
    def assemble(cls, user_id, methods, project_id, expires_at, audit_ids):
        """Assemble the payload of a project-scoped token.

        :param user_id: ID of the user in the token request
        :param methods: list of authentication methods used
        :param project_id: ID of the project to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :returns: the payload of a project-scoped token

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        """Disassemble a payload into the component data.

        :param payload: the payload of a token
        :return: a tuple containing the user_id, auth methods, project_id,
                 expires_at_str, and audit_ids

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        if is_stored_as_bytes:
            project_id = cls.attempt_convert_uuid_bytes_to_hex(project_id)
        expires_at_str = cls._convert_int_to_time_string(payload[3])
        audit_ids = list(map(provider.base64_encode, payload[4]))

        return (user_id, methods, project_id, expires_at_str, audit_ids)


class TrustScopedPayload(BasePayload):
    version = 3

    @classmethod
    def assemble(cls, user_id, methods, project_id, expires_at, audit_ids,
                 trust_id):
        """Assemble the payload of a trust-scoped token.

        :param user_id: ID of the user in the token request
        :param methods: list of authentication methods used
        :param project_id: ID of the project to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param trust_id: ID of the trust in effect
        :returns: the payload of a trust-scoped token

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        b_trust_id = cls.convert_uuid_hex_to_bytes(trust_id)
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                           audit_ids))

        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids,
                b_trust_id)

    @classmethod
    def disassemble(cls, payload):
        """Validate a trust-based payload.

        :param token_string: a string representing the token
        :returns: a tuple containing the user_id, auth methods, project_id,
                  expires_at_str, audit_ids, and trust_id

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        if is_stored_as_bytes:
            project_id = cls.attempt_convert_uuid_bytes_to_hex(project_id)
        expires_at_str = cls._convert_int_to_time_string(payload[3])
        audit_ids = list(map(provider.base64_encode, payload[4]))
        trust_id = cls.convert_uuid_bytes_to_hex(payload[5])

        return (user_id, methods, project_id, expires_at_str, audit_ids,
                trust_id)


class FederatedUnscopedPayload(BasePayload):
    version = 4

    @classmethod
    def pack_group_id(cls, group_dict):
        return cls.attempt_convert_uuid_hex_to_bytes(group_dict['id'])

    @classmethod
    def unpack_group_id(cls, group_id_in_bytes):
        (is_stored_as_bytes, group_id) = group_id_in_bytes
        if is_stored_as_bytes:
            group_id = cls.attempt_convert_uuid_bytes_to_hex(group_id)
        return {'id': group_id}

    @classmethod
    def assemble(cls, user_id, methods, expires_at, audit_ids, federated_info):
        """Assemble the payload of a federated token.

        :param user_id: ID of the user in the token request
        :param methods: list of authentication methods used
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param federated_info: dictionary containing group IDs, the identity
                               provider ID, protocol ID, and federated domain
                               ID
        :returns: the payload of a federated token

        """

        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_group_ids = list(map(cls.pack_group_id,
                               federated_info['group_ids']))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(
            federated_info['idp_id'])
        protocol_id = federated_info['protocol_id']
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_group_ids, b_idp_id, protocol_id,
                expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        """Validate a federated payload.

        :param token_string: a string representing the token
        :return: a tuple containing the user_id, auth methods, audit_ids, and a
                 dictionary containing federated information such as the group
                 IDs, the identity provider ID, the protocol ID, and the
                 federated domain ID

        """

        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        group_ids = list(map(cls.unpack_group_id, payload[2]))
        (is_stored_as_bytes, idp_id) = payload[3]
        if is_stored_as_bytes:
            idp_id = cls.attempt_convert_uuid_bytes_to_hex(idp_id)
        protocol_id = payload[4]
        expires_at_str = cls._convert_int_to_time_string(payload[5])
        audit_ids = list(map(provider.base64_encode, payload[6]))
        federated_info = dict(group_ids=group_ids, idp_id=idp_id,
                              protocol_id=protocol_id)
        return (user_id, methods, expires_at_str, audit_ids, federated_info)


class FederatedScopedPayload(FederatedUnscopedPayload):
    version = None

    @classmethod
    def assemble(cls, user_id, methods, scope_id, expires_at, audit_ids,
                 federated_info):
        """Assemble the project-scoped payload of a federated token.

        :param user_id: ID of the user in the token request
        :param methods: list of authentication methods used
        :param scope_id: ID of the project or domain ID to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param federated_info: dictionary containing the identity provider ID,
                               protocol ID, federated domain ID and group IDs
        :returns: the payload of a federated token

        """
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_scope_id = cls.attempt_convert_uuid_hex_to_bytes(scope_id)
        b_group_ids = list(map(cls.pack_group_id,
                               federated_info['group_ids']))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(
            federated_info['idp_id'])
        protocol_id = federated_info['protocol_id']
        expires_at_int = cls._convert_time_string_to_int(expires_at)
        b_audit_ids = list(map(provider.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_scope_id, b_group_ids, b_idp_id,
                protocol_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        """Validate a project-scoped federated payload.

        :param token_string: a string representing the token
        :returns: a tuple containing the user_id, auth methods, scope_id,
                  expiration time (as str), audit_ids, and a dictionary
                  containing federated information such as the the identity
                  provider ID, the protocol ID, the federated domain ID and
                  group IDs

        """
        (is_stored_as_bytes, user_id) = payload[0]
        if is_stored_as_bytes:
            user_id = cls.attempt_convert_uuid_bytes_to_hex(user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, scope_id) = payload[2]
        if is_stored_as_bytes:
            scope_id = cls.attempt_convert_uuid_bytes_to_hex(scope_id)
        group_ids = list(map(cls.unpack_group_id, payload[3]))
        (is_stored_as_bytes, idp_id) = payload[4]
        if is_stored_as_bytes:
            idp_id = cls.attempt_convert_uuid_bytes_to_hex(idp_id)
        protocol_id = payload[5]
        expires_at_str = cls._convert_int_to_time_string(payload[6])
        audit_ids = list(map(provider.base64_encode, payload[7]))
        federated_info = dict(idp_id=idp_id, protocol_id=protocol_id,
                              group_ids=group_ids)
        return (user_id, methods, scope_id, expires_at_str, audit_ids,
                federated_info)


class FederatedProjectScopedPayload(FederatedScopedPayload):
    version = 5


class FederatedDomainScopedPayload(FederatedScopedPayload):
    version = 6
