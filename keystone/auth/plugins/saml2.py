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
from keystone.openstack.common import jsonutils


@dependency.requires('federation_api', 'identity_api', 'token_api')
class Saml2(auth.AuthMethodHandler):

    method = 'saml2'

    def authenticate(self, context, auth_payload, auth_context):
        """Authenticate federated user and return an authentication context.

        :param context: keystone's request context
        :param auth_payload: the content of the authentication for a
                             given method
        :param auth_context: user authentication context, a dictionary
                             shared by all plugins.

        In addition to ``user_id`` in ``auth_context``, the ``saml2``
        plugin sets ``group_ids``. When handling unscoped tokens,
        ``OS-FEDERATION:identity_provider`` and ``OS-FEDERATION:protocol``
        are set as well.

        """

        if 'id' in auth_payload:
            fields = self._handle_scoped_token(auth_payload)
        else:
            fields = self._handle_unscoped_token(context, auth_payload)

        auth_context.update(fields)

    def _handle_scoped_token(self, auth_payload):
        token_ref = self.token_api.get_token(auth_payload['id'])
        utils.validate_expiration(token_ref)
        _federation = token_ref['user'][federation.FEDERATION]
        identity_provider = _federation['identity_provider']['id']
        protocol = _federation['protocol']['id']
        group_ids = [group['id'] for group in _federation['groups']]
        mapping = self.federation_api.get_mapping_from_idp_and_protocol(
            identity_provider, protocol)
        utils.validate_groups(group_ids, mapping['id'], self.identity_api)
        return {
            'user_id': token_ref['user_id'],
            'group_ids': group_ids
        }

    def _handle_unscoped_token(self, context, auth_payload):
        assertion = dict(utils.get_assertion_params_from_env(context))

        identity_provider = auth_payload['identity_provider']
        protocol = auth_payload['protocol']

        mapping = self.federation_api.get_mapping_from_idp_and_protocol(
            identity_provider, protocol)
        rules = jsonutils.loads(mapping['rules'])
        rule_processor = utils.RuleProcessor(rules)
        mapped_properties = rule_processor.process(assertion)
        utils.validate_groups(mapped_properties['group_ids'],
                              mapping['id'], self.identity_api)

        return {
            'user_id': parse.quote(mapped_properties['name']),
            'group_ids': mapped_properties['group_ids'],
            federation.IDENTITY_PROVIDER: identity_provider,
            federation.PROTOCOL: protocol
        }
