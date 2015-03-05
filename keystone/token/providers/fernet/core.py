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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils

from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from keystone.token.providers import common
from keystone.token.providers.fernet import format_map as fm
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

        self.token_format_map = {
            fm.UNSCOPED_TOKEN_PREFIX: tf.UnscopedTokenFormatter(),
            fm.SCOPED_TOKEN_PREFIX: tf.ScopedTokenFormatter(),
            fm.TRUST_TOKEN_PREFIX: tf.TrustTokenFormatter()}

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

        token_format = None

        if trust:
            token_format = self.token_format_map[fm.TRUST_TOKEN_PREFIX]
            token_id = token_format.create_token(
                user_id,
                project_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'],
                token_data['token']['OS-TRUST:trust']['id'])
        elif domain_id is None and project_id is None:
            token_format = self.token_format_map[fm.UNSCOPED_TOKEN_PREFIX]
            token_id = token_format.create_token(
                user_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'])
        else:
            token_format = self.token_format_map[fm.SCOPED_TOKEN_PREFIX]
            token_id = token_format.create_token(
                user_id,
                project_id,
                token_data['token']['expires_at'],
                token_data['token']['audit_ids'])

        return token_id, token_data

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

    def validate_v3_token(self, token_ref):
        """Validate a V3 formatted token.

        :param token_ref: a string describing the token to validate
        :returns: the token data
        :raises: keystone.exception.Unauthorized

        """
        # Determine and look up the token formatter.
        token_prefix_length = len(fm.SCOPED_TOKEN_PREFIX)
        token_format = token_ref[:token_prefix_length]
        token_formatter = self.token_format_map.get(token_format)
        if not token_formatter:
            # If the token_format is not recognized, raise Unauthorized.
            raise exception.Unauthorized(_(
                'This is not a recognized Fernet formatted token: %s') %
                token_format)

        # If we recognize the token format pass the rest of the token
        # string to the correct token_formatter.
        token_str = token_ref[token_prefix_length:]

        # depending on the formatter, these may or may not be defined
        project_id = None
        trust_ref = None

        if token_format == fm.UNSCOPED_TOKEN_PREFIX:
            (user_id, expires_at, audit_ids) = (
                token_formatter.validate_token(token_str))
        elif token_format == fm.SCOPED_TOKEN_PREFIX:
            (user_id, project_id, expires_at, audit_ids) = (
                token_formatter.validate_token(token_str))
        elif token_format == fm.TRUST_TOKEN_PREFIX:
            (user_id, project_id, expires_at, audit_ids, trust_id) = (
                token_formatter.validate_token(token_str))

            trust_ref = self.trust_api.get_trust(trust_id)

        # rather than appearing in the payload, the creation time is encoded
        # into the token format itself
        created_at = Provider._creation_time(token_str)

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
