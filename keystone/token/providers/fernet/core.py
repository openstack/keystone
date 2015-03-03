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

from oslo_config import cfg
from oslo_log import log

from keystone import exception
from keystone.token.providers import common
from keystone.token.providers.fernet import token_formatters


CONF = cfg.CONF
LOG = log.getLogger(__name__)

TOKEN_PREFIX = 'F00'
TRUST_TOKEN_PREFIX = 'F01'


class Provider(common.BaseProvider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

        self.token_format_map = {
            TOKEN_PREFIX: token_formatters.StandardTokenFormatter(),
            TRUST_TOKEN_PREFIX: token_formatters.TrustTokenFormatter()}

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
        token_format = None

        if trust:
            token_format = self.token_format_map[TRUST_TOKEN_PREFIX]
        else:
            token_format = self.token_format_map[TOKEN_PREFIX]

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

        token_id = token_format.create_token(user_id, project_id, token_data)

        return token_id, token_data

    def validate_v2_token(self, token_ref):
        """Validate a V2 formatted token.

        :param token_ref: reference describing the token to validate
        :returns: the token data
        :raises keystone.exception.NotImplemented: when called

        """
        raise exception.NotImplemented()

    def validate_v3_token(self, token_ref):
        """Validate a V3 formatted token.

        :param token_ref: a string describing the token to validate
        :returns: the token data
        :raises: keystone.exception.Unauthorized

        """
        # Determine and look up the token formatter.
        token_prefix_length = len(TOKEN_PREFIX)
        token_format = token_ref[:token_prefix_length]
        token_formatter = self.token_format_map.get(token_format)
        if token_formatter:
            # If we recognize the token format pass the rest of the token
            # string to the correct token_formatter class.
            token_str = token_ref[token_prefix_length:]
            (user_id, project_id, token_data) = (
                token_formatter.validate_token(token_str))
            return token_data
        # If the token_format is not recognized, raise Unauthorized.
        msg = ('This is not a recognized Fernet formatted token: %s',
               token_format)
        raise exception.Unauthorized(msg)

    def _get_token_id(self, token_data):
        """Generate the token_id based upon the data in token_data.

        :param token_data: token information
        :type token_data: dict
        :raises keystone.exception.NotImplemented: when called
        """
        raise exception.NotImplemented()
