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

import msgpack
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils

from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from keystone.token.providers import common
from keystone.token.providers.fernet import token_formatters as tf


CONF = cfg.CONF
LOG = log.getLogger(__name__)


# Fernet byte indexes as as computed by pypi/keyless_fernet and defined in
# https://github.com/fernet/spec
TIMESTAMP_START = 1
TIMESTAMP_END = 9


@dependency.requires('trust_api')
class Provider(common.BaseProvider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

        self.token_formatter = tf.TokenFormatter()

    def needs_persistence(self):
        """Should the token be written to a backend."""
        return False

    def issue_v2_token(self, token_ref, roles_ref=None, catalog_ref=None):
        """Issue a V2 formatted token.

        :param token_ref: reference describing the token
        :param roles_ref: reference describing the roles for the token
        :param catalog_ref: reference describing the token's catalog
        :raises keystone.exception.NotImplemented: when called

        """
        raise exception.NotImplemented()

    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       trust=None, metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):
        """Issue a V3 formatted token.

        Here is where we need to detect what is given to us, and what kind of
        token the user is expecting. Depending on the outcome of that, we can
        pass all the information to be packed to the proper token format
        handler.

        :param user_id: ID of the user
        :param method_names: method of authentication
        :param expires_at: token expiration time
        :param project_id: ID of the project being scoped to
        :param domain_id: ID of the domain being scoped to
        :param auth_context: authentication context
        :param trust: ID of the trust
        :param metadata_ref: metadata reference
        :param include_catalog: return the catalog in the response if True,
                                otherwise don't return the catalog
        :param parent_audit_id: ID of the patent audit entity
        :returns: tuple containing the id of the token and the token data

        """
        token_ref = None
        if auth_context and self._is_mapped_token(auth_context):
            token_ref = self._handle_mapped_tokens(
                auth_context, project_id, domain_id)

        token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            auth_context.get('extras') if auth_context else None,
            domain_id=domain_id,
            project_id=project_id,
            expires=expires_at,
            trust=trust,
            bind=auth_context.get('bind') if auth_context else None,
            token=token_ref,
            include_catalog=include_catalog,
            audit_info=parent_audit_id)

        if trust:
            version = tf.TrustScopedPayload.version
            payload = tf.TrustScopedPayload.assemble(
                user_id,
                project_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'],
                token_data['token']['OS-TRUST:trust']['id'])
        elif project_id:
            version = tf.ProjectScopedPayload.version
            payload = tf.ProjectScopedPayload.assemble(
                user_id,
                project_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'])
        elif domain_id:
            version = tf.DomainScopedPayload.version
            payload = tf.DomainScopedPayload.assemble(
                user_id,
                domain_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'])
        else:
            version = tf.UnscopedPayload.version
            payload = tf.UnscopedPayload.assemble(
                user_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'])

        versioned_payload = (version,) + payload
        serialized_payload = msgpack.packb(versioned_payload)
        token = self.token_formatter.pack(serialized_payload)

        return token, token_data

    def validate_v2_token(self, token_ref):
        """Validate a V2 formatted token.

        :param token_ref: reference describing the token to validate
        :returns: the token data
        :raises keystone.exception.NotImplemented: when called

        """
        raise exception.NotImplemented()

    @classmethod
    def _creation_time(cls, fernet_token):
        """Returns the creation time of a valid Fernet token."""
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

    def validate_v3_token(self, token):
        """Validate a V3 formatted token.

        :param token: a string describing the token to validate
        :returns: the token data
        :raises: keystone.exception.Unauthorized

        """
        serialized_payload = self.token_formatter.unpack(token)
        versioned_payload = msgpack.unpackb(serialized_payload)
        version, payload = versioned_payload[0], versioned_payload[1:]

        # depending on the formatter, these may or may not be defined
        domain_id = None
        project_id = None
        trust_ref = None

        if version == tf.UnscopedPayload.version:
            (user_id, expires_at, audit_ids) = (
                tf.UnscopedPayload.disassemble(payload))
        elif version == tf.DomainScopedPayload.version:
            (user_id, domain_id, expires_at, audit_ids) = (
                tf.DomainScopedPayload.disassemble(payload))
        elif version == tf.ProjectScopedPayload.version:
            (user_id, project_id, expires_at, audit_ids) = (
                tf.ProjectScopedPayload.disassemble(payload))
        elif version == tf.TrustScopedPayload.version:
            (user_id, project_id, expires_at, audit_ids, trust_id) = (
                tf.TrustScopedPayload.disassemble(payload))

            trust_ref = self.trust_api.get_trust(trust_id)
        else:
            # If the token_format is not recognized, raise Unauthorized.
            raise exception.Unauthorized(_(
                'This is not a recognized Fernet payload version: %s') %
                version)

        # rather than appearing in the payload, the creation time is encoded
        # into the token format itself
        created_at = Provider._creation_time(token)

        return self.v3_token_data_helper.get_token_data(
            user_id,
            method_names=['password', 'token'],
            project_id=project_id,
            expires=expires_at,
            issued_at=timeutils.isotime(created_at),
            trust=trust_ref,
            audit_info=audit_ids)

    def _get_token_id(self, token_data):
        """Generate the token_id based upon the data in token_data.

        :param token_data: token information
        :type token_data: dict
        :raises keystone.exception.NotImplemented: when called
        """
        raise exception.NotImplemented()
