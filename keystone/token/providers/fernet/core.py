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

from keystone.common import dependency
from keystone.common import utils as ks_utils
from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone.i18n import _
from keystone.token import provider
from keystone.token.providers import common
from keystone.token.providers.fernet import token_formatters as tf


CONF = cfg.CONF
LOG = log.getLogger(__name__)


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
        :returns: tuple containing the ID of the token and the token data

        """
        # TODO(lbragstad): Currently, Fernet tokens don't support bind in the
        # token format. Raise a 501 if we're dealing with bind.
        if token_ref.get('bind'):
            raise exception.NotImplemented()

        user_id = token_ref['user']['id']
        # Default to password since methods not provided by token_ref
        method_names = ['password']
        project_id = None
        # Verify that tenant is not None in token_ref
        if token_ref.get('tenant'):
            project_id = token_ref['tenant']['id']

        # maintain expiration time across rescopes
        expires = token_ref.get('expires')

        parent_audit_id = token_ref.get('parent_audit_id')
        # If parent_audit_id is defined then a token authentication was made
        if parent_audit_id:
            method_names.append('token')

        audit_ids = provider.audit_info(parent_audit_id)

        # Get v3 token data and exclude building v3 specific catalog. This is
        # due to the fact that the V2TokenDataHelper.format_token() method
        # doesn't build any of the token_reference from other Keystone APIs.
        # Instead, it builds it from what is persisted in the token reference.
        # Here we are going to leverage the V3TokenDataHelper.get_token_data()
        # method written for V3 because it goes through and populates the token
        # reference dynamically. Once we have a V3 token reference, we can
        # attempt to convert it to a V2 token response.
        v3_token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            project_id=project_id,
            token=token_ref,
            include_catalog=False,
            audit_info=audit_ids,
            expires=expires)

        expires_at = v3_token_data['token']['expires_at']
        token_id = self.token_formatter.create_token(user_id, expires_at,
                                                     audit_ids,
                                                     methods=method_names,
                                                     project_id=project_id)
        self._build_issued_at_info(token_id, v3_token_data)
        # Convert v3 to v2 token data and build v2 catalog
        token_data = self.v2_token_data_helper.v3_to_v2_token(v3_token_data)
        token_data['access']['token']['id'] = token_id

        return token_id, token_data

    def issue_v3_token(self, *args, **kwargs):
        token_id, token_data = super(Provider, self).issue_v3_token(
            *args, **kwargs)
        self._build_issued_at_info(token_id, token_data)
        return token_id, token_data

    def _build_issued_at_info(self, token_id, token_data):
        # NOTE(roxanaghe, lbragstad): We must use the creation time that
        # Fernet builds into it's token. The Fernet spec details that the
        # token creation time is built into the token, outside of the payload
        # provided by Keystone. This is the reason why we don't pass the
        # issued_at time in the payload. This also means that we shouldn't
        # return a token reference with a creation time that we created
        # when Fernet uses a different creation time. We should use the
        # creation time provided by Fernet because it's the creation time
        # that we have to rely on when we validate the token.
        fernet_creation_datetime_obj = self.token_formatter.creation_time(
            token_id)
        token_data['token']['issued_at'] = ks_utils.isotime(
            at=fernet_creation_datetime_obj, subsecond=True)

    def _build_federated_info(self, token_data):
        """Extract everything needed for federated tokens.

        This dictionary is passed to federated token formatters, which unpack
        the values and build federated Fernet tokens.

        """
        idp_id = token_data['token'].get('user', {}).get(
            federation_constants.FEDERATION, {}).get(
                'identity_provider', {}).get('id')
        protocol_id = token_data['token'].get('user', {}).get(
            federation_constants.FEDERATION, {}).get('protocol', {}).get('id')
        # If we don't have an identity provider ID and a protocol ID, it's safe
        # to assume we aren't dealing with a federated token.
        if not (idp_id and protocol_id):
            return None

        group_ids = token_data['token'].get('user', {}).get(
            federation_constants.FEDERATION, {}).get('groups')

        return {'group_ids': group_ids,
                'idp_id': idp_id,
                'protocol_id': protocol_id}

    def _rebuild_federated_info(self, federated_dict, user_id):
        """Format federated information into the token reference.

        The federated_dict is passed back from the federated token formatters.
        The responsibility of this method is to format the information passed
        back from the token formatter into the token reference before
        constructing the token data from the V3TokenDataHelper.

        """
        g_ids = federated_dict['group_ids']
        idp_id = federated_dict['idp_id']
        protocol_id = federated_dict['protocol_id']

        federated_info = {
            'groups': g_ids,
            'identity_provider': {'id': idp_id},
            'protocol': {'id': protocol_id}
        }

        token_dict = {
            'user': {
                federation_constants.FEDERATION: federated_info,
                'id': user_id,
                'name': user_id,
                'domain': {'id': CONF.federation.federated_domain_name,
                           'name': CONF.federation.federated_domain_name, },
            }
        }

        return token_dict

    def _rebuild_federated_token_roles(self, token_dict, federated_dict,
                                       user_id, project_id, domain_id):
        """Populate roles based on (groups, project/domain) pair.

        We must populate roles from (groups, project/domain) as ephemeral users
        don't exist in the backend. Upon success, a ``roles`` key will be added
        to ``token_dict``.

        :param token_dict: dictionary with data used for building token
        :param federated_dict: federated information such as identity provider
            protocol and set of group IDs
        :param user_id: user ID
        :param project_id: project ID the token is being scoped to
        :param domain_id: domain ID the token is being scoped to

        """
        group_ids = [x['id'] for x in federated_dict['group_ids']]
        self.v3_token_data_helper.populate_roles_for_groups(
            token_dict, group_ids, project_id, domain_id, user_id)

    def validate_v2_token(self, token_ref):
        """Validate a V2 formatted token.

        :param token_ref: reference describing the token to validate
        :returns: the token data
        :raises keystone.exception.TokenNotFound: if token format is invalid
        :raises keystone.exception.Unauthorized: if v3 token is used

        """
        try:
            (user_id, methods,
             audit_ids, domain_id,
             project_id, trust_id,
             federated_info, created_at,
             expires_at) = self.token_formatter.validate_token(token_ref)
        except exception.ValidationError as e:
            raise exception.TokenNotFound(e)

        if trust_id or domain_id or federated_info:
            msg = _('This is not a v2.0 Fernet token. Use v3 for trust, '
                    'domain, or federated tokens.')
            raise exception.Unauthorized(msg)

        v3_token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            methods,
            project_id=project_id,
            expires=expires_at,
            issued_at=created_at,
            token=token_ref,
            include_catalog=False,
            audit_info=audit_ids)
        token_data = self.v2_token_data_helper.v3_to_v2_token(v3_token_data)
        token_data['access']['token']['id'] = token_ref
        return token_data

    def validate_v3_token(self, token):
        """Validate a V3 formatted token.

        :param token: a string describing the token to validate
        :returns: the token data
        :raises keystone.exception.TokenNotFound: if token format version isn't
                                                 supported

        """
        try:
            (user_id, methods, audit_ids, domain_id, project_id, trust_id,
                federated_info, created_at, expires_at) = (
                    self.token_formatter.validate_token(token))
        except exception.ValidationError as e:
            raise exception.TokenNotFound(e)

        token_dict = None
        trust_ref = None
        if federated_info:
            token_dict = self._rebuild_federated_info(federated_info, user_id)
            if project_id or domain_id:
                self._rebuild_federated_token_roles(token_dict, federated_info,
                                                    user_id, project_id,
                                                    domain_id)
        if trust_id:
            trust_ref = self.trust_api.get_trust(trust_id)

        return self.v3_token_data_helper.get_token_data(
            user_id,
            method_names=methods,
            domain_id=domain_id,
            project_id=project_id,
            issued_at=created_at,
            expires=expires_at,
            trust=trust_ref,
            token=token_dict,
            audit_info=audit_ids)

    def _get_token_id(self, token_data):
        """Generate the token_id based upon the data in token_data.

        :param token_data: token information
        :type token_data: dict
        :raises keystone.exception.NotImplemented: when called
        """
        return self.token_formatter.create_token(
            token_data['token']['user']['id'],
            token_data['token']['expires_at'],
            token_data['token']['audit_ids'],
            methods=token_data['token'].get('methods'),
            domain_id=token_data['token'].get('domain', {}).get('id'),
            project_id=token_data['token'].get('project', {}).get('id'),
            trust_id=token_data['token'].get('OS-TRUST:trust', {}).get('id'),
            federated_info=self._build_federated_info(token_data)
        )

    @property
    def _supports_bind_authentication(self):
        """Return if the token provider supports bind authentication methods.

        :returns: False
        """
        return False
