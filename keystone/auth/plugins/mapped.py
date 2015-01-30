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

import functools

from oslo.serialization import jsonutils
from pycadf import cadftaxonomy as taxonomy
from six.moves.urllib import parse

from keystone import auth
from keystone.common import dependency
from keystone.contrib import federation
from keystone.contrib.federation import utils
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone import notifications
from keystone.openstack.common import log


LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'federation_api', 'identity_api',
                     'token_provider_api')
class Mapped(auth.AuthMethodHandler):

    def _get_token_ref(self, auth_payload):
        token_id = auth_payload['id']
        response = self.token_provider_api.validate_token(token_id)
        return token_model.KeystoneToken(token_id=token_id,
                                         token_data=response)

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
            token_ref = self._get_token_ref(auth_payload)
            handle_scoped_token(context, auth_payload, auth_context, token_ref,
                                self.federation_api,
                                self.identity_api,
                                self.token_provider_api)
        else:
            handle_unscoped_token(context, auth_payload, auth_context,
                                  self.assignment_api, self.federation_api,
                                  self.identity_api)


def handle_scoped_token(context, auth_payload, auth_context, token_ref,
                        federation_api, identity_api, token_provider_api):
    utils.validate_expiration(token_ref)
    token_audit_id = token_ref.audit_id
    identity_provider = token_ref.federation_idp_id
    protocol = token_ref.federation_protocol_id
    user_id = token_ref.user_id
    group_ids = token_ref.federation_group_ids
    send_notification = functools.partial(
        notifications.send_saml_audit_notification, 'authenticate',
        context, user_id, group_ids, identity_provider, protocol,
        token_audit_id)

    utils.assert_enabled_identity_provider(federation_api, identity_provider)

    try:
        mapping = federation_api.get_mapping_from_idp_and_protocol(
            identity_provider, protocol)
        utils.validate_groups(group_ids, mapping['id'], identity_api)

    except Exception:
        # NOTE(topol): Diaper defense to catch any exception, so we can
        # send off failed authentication notification, raise the exception
        # after sending the notification
        send_notification(taxonomy.OUTCOME_FAILURE)
        raise
    else:
        send_notification(taxonomy.OUTCOME_SUCCESS)

    auth_context['user_id'] = user_id
    auth_context['group_ids'] = group_ids
    auth_context[federation.IDENTITY_PROVIDER] = identity_provider
    auth_context[federation.PROTOCOL] = protocol


def handle_unscoped_token(context, auth_payload, auth_context,
                          assignment_api, federation_api, identity_api):
    assertion = extract_assertion_data(context)
    identity_provider = auth_payload['identity_provider']
    protocol = auth_payload['protocol']

    utils.assert_enabled_identity_provider(federation_api, identity_provider)

    group_ids = None
    # NOTE(topol): The user is coming in from an IdP with a SAML assertion
    # instead of from a token, so we set token_id to None
    token_id = None
    # NOTE(marek-denis): This variable is set to None and there is a
    # possibility that it will be used in the CADF notification. This means
    # operation will not be mapped to any user (even ephemeral).
    user_id = None

    try:
        mapped_properties = apply_mapping_filter(identity_provider, protocol,
                                                 assertion, assignment_api,
                                                 federation_api, identity_api)
        user_id = setup_username(context, mapped_properties)
        group_ids = mapped_properties['group_ids']

    except Exception:
        # NOTE(topol): Diaper defense to catch any exception, so we can
        # send off failed authentication notification, raise the exception
        # after sending the notification
        outcome = taxonomy.OUTCOME_FAILURE
        notifications.send_saml_audit_notification('authenticate', context,
                                                   user_id, group_ids,
                                                   identity_provider,
                                                   protocol, token_id,
                                                   outcome)
        raise
    else:
        outcome = taxonomy.OUTCOME_SUCCESS
        notifications.send_saml_audit_notification('authenticate', context,
                                                   user_id, group_ids,
                                                   identity_provider,
                                                   protocol, token_id,
                                                   outcome)

    auth_context['user_id'] = user_id
    auth_context['group_ids'] = group_ids
    auth_context[federation.IDENTITY_PROVIDER] = identity_provider
    auth_context[federation.PROTOCOL] = protocol


def extract_assertion_data(context):
    assertion = dict(utils.get_assertion_params_from_env(context))
    return assertion


def apply_mapping_filter(identity_provider, protocol, assertion,
                         assignment_api, federation_api, identity_api):
    mapping = federation_api.get_mapping_from_idp_and_protocol(
        identity_provider, protocol)
    rules = jsonutils.loads(mapping['rules'])
    LOG.debug('using the following rules: %s', rules)
    rule_processor = utils.RuleProcessor(rules)
    mapped_properties = rule_processor.process(assertion)

    # NOTE(marek-denis): We update group_ids only here to avoid fetching
    # groups identified by name/domain twice.
    # NOTE(marek-denis): Groups are translated from name/domain to their
    # corresponding ids in the auth plugin, as we need information what
    # ``mapping_id`` was used as well as idenity_api and assignment_api
    # objects.
    group_ids = mapped_properties['group_ids']
    utils.validate_groups_in_backend(group_ids,
                                     mapping['id'],
                                     identity_api)
    group_ids.extend(
        utils.transform_to_group_ids(
            mapped_properties['group_names'], mapping['id'],
            identity_api, assignment_api))
    utils.validate_groups_cardinality(group_ids, mapping['id'])
    mapped_properties['group_ids'] = list(set(group_ids))
    return mapped_properties


def setup_username(context, mapped_properties):
    """Setup federated username.

    If ``user_name`` is specified in the mapping_properties use this
    value.Otherwise try fetching value from an environment variable
    ``REMOTE_USER``.
    This method also url encodes user_name and saves this value in user_id.
    If user_name cannot be mapped raise exception.Unauthorized.

    :param context: authentication context
    :param mapped_properties: Properties issued by a RuleProcessor.
    :type: dictionary

    :raises: exception.Unauthorized
    :returns: tuple with user_name and user_id values.

    """
    user_name = mapped_properties['name']
    if user_name is None:
        user_name = context['environment'].get('REMOTE_USER')
        if user_name is None:
            raise exception.Unauthorized(_("Could not map user"))
    user_id = parse.quote(user_name)
    return user_id
