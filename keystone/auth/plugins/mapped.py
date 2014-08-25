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

from six.moves.urllib import parse

from keystone import auth
from keystone.common import dependency
from keystone.contrib import federation
from keystone.contrib.federation import utils
from keystone.models import token_model
from keystone.openstack.common import jsonutils


@dependency.requires('federation_api', 'identity_api', 'token_provider_api')
class Mapped(auth.AuthMethodHandler):

    def authenticate(self, context, auth_payload, auth_context):
        """Authenticate mapped user and return an authentication context.

        :param context: keystone's request context
        :param auth_payload: the content of the authentication for a
                             given method
        :param auth_context: user authentication context, a dictionary
                             shared by all plugins.

        In addition to ``user_id`` in ``auth_context``, this plugin sets
        ``group_ids``, ``OS-FEDERATION:identity_provider`` and
        ``OS-FEDERATION:protocol``
        """

        if 'id' in auth_payload:
            fields = self._handle_scoped_token(auth_payload)
        else:
            fields = self._handle_unscoped_token(context, auth_payload)

        auth_context.update(fields)

    def _handle_scoped_token(self, auth_payload):
        token_ref = token_model.KeystoneToken(
            token_id=auth_payload['id'],
            token_data=self.token_provider_api.validate_token(
                auth_payload['id']))
        utils.validate_expiration(token_ref)
        mapping = self.federation_api.get_mapping_from_idp_and_protocol(
            token_ref.federation_idp_id, token_ref.federation_protocol_id)
        utils.validate_groups(token_ref.federation_group_ids,
                              mapping['id'], self.identity_api)
        return {
            'user_id': token_ref.user_id,
            'group_ids': token_ref.federation_group_ids,
            federation.IDENTITY_PROVIDER: token_ref.federation_idp_id,
            federation.PROTOCOL: token_ref.federation_protocol_id
        }

    def _handle_unscoped_token(self, context, auth_payload):
        user_id, assertion = self._extract_assertion_data(context)
        if user_id:
            assertion['user_id'] = user_id
        identity_provider = auth_payload['identity_provider']
        protocol = auth_payload['protocol']

        mapped_properties = self._apply_mapping_filter(identity_provider,
                                                       protocol,
                                                       assertion)

        if not user_id:
            user_id = parse.quote(mapped_properties['name'])

        return {
            'user_id': user_id,
            'group_ids': mapped_properties['group_ids'],
            federation.IDENTITY_PROVIDER: identity_provider,
            federation.PROTOCOL: protocol
        }

    def _extract_assertion_data(self, context):
        assertion = dict(utils.get_assertion_params_from_env(context))
        user_id = context['environment'].get('REMOTE_USER')
        return user_id, assertion

    def _apply_mapping_filter(self, identity_provider, protocol, assertion):
        mapping = self.federation_api.get_mapping_from_idp_and_protocol(
            identity_provider, protocol)
        rules = jsonutils.loads(mapping['rules'])
        rule_processor = utils.RuleProcessor(rules)
        mapped_properties = rule_processor.process(assertion)
        utils.validate_groups(mapped_properties['group_ids'],
                              mapping['id'], self.identity_api)
        return mapped_properties
