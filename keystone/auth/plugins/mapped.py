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

from oslo_log import log
from pycadf import cadftaxonomy as taxonomy
from six.moves.urllib import parse

from keystone import auth
from keystone.auth import plugins as auth_plugins
from keystone.common import dependency
from keystone.contrib.federation import constants as federation_constants
from keystone.contrib.federation import utils
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone import notifications


LOG = log.getLogger(__name__)

METHOD_NAME = 'mapped'


@dependency.requires('federation_api', 'identity_api',
                     'resource_api', 'token_provider_api')
class Mapped(auth.AuthMethodHandler):

    def _get_token_ref(self, auth_payload):
        token_id = auth_payload['id']
        response = self.token_provider_api.validate_token(token_id)
        return token_model.KeystoneToken(token_id=token_id,
                                         token_data=response)

    def authenticate(self, context, auth_payload, auth_context):
        """Authenticate mapped user and set an authentication context.

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
                                  self.resource_api, self.federation_api,
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
    auth_context[federation_constants.IDENTITY_PROVIDER] = identity_provider
    auth_context[federation_constants.PROTOCOL] = protocol


def handle_unscoped_token(context, auth_payload, auth_context,
                          resource_api, federation_api, identity_api):

    def is_ephemeral_user(mapped_properties):
        return mapped_properties['user']['type'] == utils.UserType.EPHEMERAL

    def build_ephemeral_user_context(auth_context, user, mapped_properties,
                                     identity_provider, protocol):
        auth_context['user_id'] = user['id']
        auth_context['group_ids'] = mapped_properties['group_ids']
        auth_context[federation_constants.IDENTITY_PROVIDER] = (
            identity_provider)
        auth_context[federation_constants.PROTOCOL] = protocol

    def build_local_user_context(auth_context, mapped_properties):
        user_info = auth_plugins.UserAuthInfo.create(mapped_properties,
                                                     METHOD_NAME)
        auth_context['user_id'] = user_info.user_id

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
        mapped_properties, mapping_id = apply_mapping_filter(
            identity_provider, protocol, assertion, resource_api,
            federation_api, identity_api)

        if is_ephemeral_user(mapped_properties):
            user = setup_username(context, mapped_properties)
            user_id = user['id']
            group_ids = mapped_properties['group_ids']
            utils.validate_groups_cardinality(group_ids, mapping_id)
            build_ephemeral_user_context(auth_context, user,
                                         mapped_properties,
                                         identity_provider, protocol)
        else:
            build_local_user_context(auth_context, mapped_properties)

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


def extract_assertion_data(context):
    assertion = dict(utils.get_assertion_params_from_env(context))
    return assertion


def apply_mapping_filter(identity_provider, protocol, assertion,
                         resource_api, federation_api, identity_api):
    idp = federation_api.get_idp(identity_provider)
    utils.validate_idp(idp, protocol, assertion)

    mapped_properties, mapping_id = federation_api.evaluate(
        identity_provider, protocol, assertion)

    # NOTE(marek-denis): We update group_ids only here to avoid fetching
    # groups identified by name/domain twice.
    # NOTE(marek-denis): Groups are translated from name/domain to their
    # corresponding ids in the auth plugin, as we need information what
    # ``mapping_id`` was used as well as idenity_api and resource_api
    # objects.
    group_ids = mapped_properties['group_ids']
    utils.validate_groups_in_backend(group_ids,
                                     mapping_id,
                                     identity_api)
    group_ids.extend(
        utils.transform_to_group_ids(
            mapped_properties['group_names'], mapping_id,
            identity_api, resource_api))
    mapped_properties['group_ids'] = list(set(group_ids))
    return mapped_properties, mapping_id


def setup_username(context, mapped_properties):
    """Setup federated username.

    Function covers all the cases for properly setting user id, a primary
    identifier for identity objects. Initial version of the mapping engine
    assumed user is identified by ``name`` and his ``id`` is built from the
    name. We, however need to be able to accept local rules that identify user
    by either id or name/domain.

    The following use-cases are covered:

    1) If neither user_name nor user_id is set raise exception.Unauthorized
    2) If user_id is set and user_name not, set user_name equal to user_id
    3) If user_id is not set and user_name is, set user_id as url safe version
       of user_name.

    :param context: authentication context
    :param mapped_properties: Properties issued by a RuleProcessor.
    :type: dictionary

    :raises: exception.Unauthorized
    :returns: dictionary with user identification
    :rtype: dict

    """
    user = mapped_properties['user']

    user_id = user.get('id')
    user_name = user.get('name') or context['environment'].get('REMOTE_USER')

    if not any([user_id, user_name]):
        msg = _("Could not map user while setting ephemeral user identity. "
                "Either mapping rules must specify user id/name or "
                "REMOTE_USER environment variable must be set.")
        raise exception.Unauthorized(msg)

    elif not user_name:
        user['name'] = user_id

    elif not user_id:
        user_id = user_name

    user['id'] = parse.quote(user_id)

    return user
