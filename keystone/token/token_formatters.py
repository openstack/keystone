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
        fernet_utils = utils.FernetUtils(
            CONF.fernet_tokens.key_repository,
            CONF.fernet_tokens.max_active_keys,
            'fernet_tokens'
        )
        keys = fernet_utils.load_keys()

        if not keys:
            raise exception.KeysNotFound()

        fernet_instances = [fernet.Fernet(key) for key in keys]
        return fernet.MultiFernet(fernet_instances)

    def pack(self, payload):
        """Pack a payload for transport as a token.

        :type payload: bytes
        :rtype: str

        """
        # base64 padding (if any) is not URL-safe
        return self.crypto.encrypt(payload).rstrip(b'=').decode('utf-8')

    def unpack(self, token):
        """Unpack a token, and validate the payload.

        :type token: str
        :rtype: bytes

        """
        token = TokenFormatter.restore_padding(token)

        try:
            return self.crypto.decrypt(token.encode('utf-8'))
        except fernet.InvalidToken:
            raise exception.ValidationError(
                _('Could not recognize Fernet token'))

    @classmethod
    def restore_padding(cls, token):
        """Restore padding based on token size.

        :param token: token to restore padding on
        :type token: str
        :returns: token with correct padding

        """
        # Re-inflate the padding
        mod_returned = len(token) % 4
        if mod_returned:
            missing_padding = 4 - mod_returned
            token += '=' * missing_padding
        return token

    @classmethod
    def creation_time(cls, fernet_token):
        """Return the creation time of a valid Fernet token.

        :type fernet_token: str

        """
        fernet_token = TokenFormatter.restore_padding(fernet_token)
        # fernet_token is str

        # Fernet tokens are base64 encoded, so we need to unpack them first
        # urlsafe_b64decode() requires bytes
        token_bytes = base64.urlsafe_b64decode(fernet_token.encode('utf-8'))

        # slice into the byte array to get just the timestamp
        timestamp_bytes = token_bytes[TIMESTAMP_START:TIMESTAMP_END]

        # convert those bytes to an integer
        # (it's a 64-bit "unsigned long long int" in C)
        timestamp_int = struct.unpack(">Q", timestamp_bytes)[0]

        # and with an integer, it's trivial to produce a datetime object
        issued_at = datetime.datetime.utcfromtimestamp(timestamp_int)

        return issued_at

    def create_token(self, user_id, expires_at, audit_ids, payload_class,
                     methods=None, system=None, domain_id=None,
                     project_id=None, trust_id=None, federated_group_ids=None,
                     identity_provider_id=None, protocol_id=None,
                     access_token_id=None, app_cred_id=None):
        """Given a set of payload attributes, generate a Fernet token."""
        version = payload_class.version
        payload = payload_class.assemble(
            user_id, methods, system, project_id, domain_id, expires_at,
            audit_ids, trust_id, federated_group_ids, identity_provider_id,
            protocol_id, access_token_id, app_cred_id
        )

        versioned_payload = (version,) + payload
        serialized_payload = msgpack.packb(versioned_payload)
        token = self.pack(serialized_payload)

        # NOTE(lbragstad): We should warn against Fernet tokens that are over
        # 255 characters in length. This is mostly due to persisting the tokens
        # in a backend store of some kind that might have a limit of 255
        # characters. Even though Keystone isn't storing a Fernet token
        # anywhere, we can't say it isn't being stored somewhere else with
        # those kind of backend constraints.
        if len(token) > CONF.max_token_size:
            LOG.info(
                f'Fernet token created with length of {len(token)} '
                f'characters, which exceeds {CONF.max_token_size} characters',
            )

        return token

    def validate_token(self, token):
        """Validate a Fernet token and returns the payload attributes.

        :type token: str

        """
        serialized_payload = self.unpack(token)
        # TODO(melwitt): msgpack changed their data format in version 1.0, so
        # in order to support a rolling upgrade, we must pass raw=True to
        # support the old format. The try-except may be removed once the
        # N-1 release no longer supports msgpack < 1.0.
        try:
            versioned_payload = msgpack.unpackb(serialized_payload)
        except UnicodeDecodeError:
            versioned_payload = msgpack.unpackb(serialized_payload, raw=True)

        version, payload = versioned_payload[0], versioned_payload[1:]

        for payload_class in _PAYLOAD_CLASSES:
            if version == payload_class.version:
                (user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id) = payload_class.disassemble(payload)
                break
        else:
            # If the token_format is not recognized, raise ValidationError.
            raise exception.ValidationError(_(
                'This is not a recognized Fernet payload version: %s') %
                version)

        # FIXME(lbragstad): Without this, certain token validation tests fail
        # when running with python 3. Once we get further along in this
        # refactor, we should be better about handling string encoding/types at
        # the edges of the application.
        if isinstance(system, bytes):
            system = system.decode('utf-8')

        # rather than appearing in the payload, the creation time is encoded
        # into the token format itself
        issued_at = TokenFormatter.creation_time(token)
        issued_at = ks_utils.isotime(at=issued_at, subsecond=True)
        expires_at = timeutils.parse_isotime(expires_at)
        expires_at = ks_utils.isotime(at=expires_at, subsecond=True)

        return (user_id, methods, audit_ids, system, domain_id, project_id,
                trust_id, federated_group_ids, identity_provider_id,
                protocol_id, access_token_id, app_cred_id, issued_at,
                expires_at)


class BasePayload(object):
    # each payload variant should have a unique version
    version = None

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        """Assemble the payload of a token.

        :param user_id: identifier of the user in the token request
        :param methods: list of authentication methods used
        :param system: a string including system scope information
        :param project_id: ID of the project to scope to
        :param domain_id: ID of the domain to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param trust_id: ID of the trust in effect
        :param federated_group_ids: list of group IDs from SAML assertion
        :param identity_provider_id: ID of the user's identity provider
        :param protocol_id: federated protocol used for authentication
        :param access_token_id: ID of the secret in OAuth1 authentication
        :param app_cred_id: ID of the application credential in effect
        :returns: the payload of a token

        """
        raise NotImplementedError()

    @classmethod
    def disassemble(cls, payload):
        """Disassemble an unscoped payload into the component data.

        The tuple consists of::

            (user_id, methods, system, project_id, domain_id,
             expires_at_str, audit_ids, trust_id, federated_group_ids,
             identity_provider_id, protocol_id,` access_token_id, app_cred_id)

        * ``methods`` are the auth methods.

        Fields will be set to None if they didn't apply to this payload type.

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
        except (ValueError, TypeError):
            # ValueError: this might not be a UUID, depending on the
            # situation (i.e. federation)
            # TypeError: the provided value may be binary encoded
            # in which case just return the value (i.e. Python 3)
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

    @classmethod
    def _convert_or_decode(cls, is_stored_as_bytes, value):
        """Convert a value to text type, translating uuid -> hex if required.

        :param is_stored_as_bytes: whether value is already bytes
        :type is_stored_as_bytes: boolean
        :param value: value to attempt to convert to bytes
        :type value: str or bytes
        :rtype: str
        """
        if is_stored_as_bytes:
            return cls.convert_uuid_bytes_to_hex(value)
        elif isinstance(value, bytes):
            return value.decode('utf-8')
        return value


class UnscopedPayload(BasePayload):
    version = 0

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        expires_at_str = cls._convert_float_to_time_string(payload[2])
        audit_ids = list(map(cls.base64_encode, payload[3]))
        system = None
        project_id = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class DomainScopedPayload(BasePayload):
    version = 1

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
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
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_domain_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        try:
            domain_id = cls.convert_uuid_bytes_to_hex(payload[2])
        except ValueError:
            # the default domain ID is configurable, and probably isn't a UUID
            if isinstance(payload[2], bytes):
                payload[2] = payload[2].decode('utf-8')
            if payload[2] == CONF.identity.default_domain_id:
                domain_id = payload[2]
            else:
                raise
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        project_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class ProjectScopedPayload(BasePayload):
    version = 2

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class TrustScopedPayload(BasePayload):
    version = 3

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        b_trust_id = cls.convert_uuid_hex_to_bytes(trust_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))

        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids,
                b_trust_id)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        trust_id = cls.convert_uuid_bytes_to_hex(payload[5])
        system = None
        domain_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class FederatedUnscopedPayload(BasePayload):
    version = 4

    @classmethod
    def pack_group_id(cls, group_dict):
        return cls.attempt_convert_uuid_hex_to_bytes(group_dict['id'])

    @classmethod
    def unpack_group_id(cls, group_id_in_bytes):
        (is_stored_as_bytes, group_id) = group_id_in_bytes
        group_id = cls._convert_or_decode(is_stored_as_bytes, group_id)
        return {'id': group_id}

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_group_ids = list(map(cls.pack_group_id, federated_group_ids))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(identity_provider_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_group_ids, b_idp_id, protocol_id,
                expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        group_ids = list(map(cls.unpack_group_id, payload[2]))
        (is_stored_as_bytes, idp_id) = payload[3]
        idp_id = cls._convert_or_decode(is_stored_as_bytes, idp_id)
        protocol_id = payload[4]
        if isinstance(protocol_id, bytes):
            protocol_id = protocol_id.decode('utf-8')
        expires_at_str = cls._convert_float_to_time_string(payload[5])
        audit_ids = list(map(cls.base64_encode, payload[6]))
        system = None
        project_id = None
        domain_id = None
        trust_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, group_ids, idp_id,
                protocol_id, access_token_id, app_cred_id)


class FederatedScopedPayload(FederatedUnscopedPayload):
    version = None

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_scope_id = cls.attempt_convert_uuid_hex_to_bytes(
            project_id or domain_id)
        b_group_ids = list(map(cls.pack_group_id, federated_group_ids))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(identity_provider_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_scope_id, b_group_ids, b_idp_id,
                protocol_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, scope_id) = payload[2]
        scope_id = cls._convert_or_decode(is_stored_as_bytes, scope_id)
        project_id = (
            scope_id
            if cls.version == FederatedProjectScopedPayload.version else None)
        domain_id = (
            scope_id
            if cls.version == FederatedDomainScopedPayload.version else None)
        group_ids = list(map(cls.unpack_group_id, payload[3]))
        (is_stored_as_bytes, idp_id) = payload[4]
        idp_id = cls._convert_or_decode(is_stored_as_bytes, idp_id)
        protocol_id = payload[5]
        if isinstance(protocol_id, bytes):
            protocol_id = protocol_id.decode('utf-8')
        expires_at_str = cls._convert_float_to_time_string(payload[6])
        audit_ids = list(map(cls.base64_encode, payload[7]))
        system = None
        trust_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, group_ids, idp_id,
                protocol_id, access_token_id, app_cred_id)


class FederatedProjectScopedPayload(FederatedScopedPayload):
    version = 5


class FederatedDomainScopedPayload(FederatedScopedPayload):
    version = 6


class OauthScopedPayload(BasePayload):
    version = 7

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        b_access_token_id = cls.attempt_convert_uuid_hex_to_bytes(
            access_token_id)
        return (b_user_id, methods, b_project_id, b_access_token_id,
                expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        (is_stored_as_bytes, access_token_id) = payload[3]
        access_token_id = cls._convert_or_decode(is_stored_as_bytes,
                                                 access_token_id)
        expires_at_str = cls._convert_float_to_time_string(payload[4])
        audit_ids = list(map(cls.base64_encode, payload[5]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        app_cred_id = None

        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class SystemScopedPayload(BasePayload):
    version = 8

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, system, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        system = payload[2]
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        project_id = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


class ApplicationCredentialScopedPayload(BasePayload):
    version = 9

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = auth_plugins.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        b_app_cred_id = cls.attempt_convert_uuid_hex_to_bytes(app_cred_id)
        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids,
                b_app_cred_id)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = auth_plugins.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        (is_stored_as_bytes, app_cred_id) = payload[5]
        app_cred_id = cls._convert_or_decode(is_stored_as_bytes, app_cred_id)
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id)


_PAYLOAD_CLASSES = [
    UnscopedPayload,
    DomainScopedPayload,
    ProjectScopedPayload,
    TrustScopedPayload,
    FederatedUnscopedPayload,
    FederatedProjectScopedPayload,
    FederatedDomainScopedPayload,
    OauthScopedPayload,
    SystemScopedPayload,
    ApplicationCredentialScopedPayload,
]
