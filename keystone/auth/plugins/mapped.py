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
import uuid

import flask
from oslo_log import log
from pycadf import cadftaxonomy as taxonomy
from urllib import parse

from keystone.auth import plugins as auth_plugins
from keystone.auth.plugins import base
from keystone.common import provider_api
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils
from keystone.i18n import _
from keystone import notifications

LOG = log.getLogger(__name__)

METHOD_NAME = 'mapped'
PROVIDERS = provider_api.ProviderAPIs


class Mapped(base.AuthMethodHandler):

    def _get_token_ref(self, auth_payload):
        token_id = auth_payload['id']
        return PROVIDERS.token_provider_api.validate_token(token_id)

    def authenticate(self, auth_payload):
        """Authenticate mapped user and set an authentication context.

        :param auth_payload: the content of the authentication for a
                             given method

        In addition to ``user_id`` in ``response_data``, this plugin sets
        ``group_ids``, ``OS-FEDERATION:identity_provider`` and
        ``OS-FEDERATION:protocol``

        """
        if 'id' in auth_payload:
            token_ref = self._get_token_ref(auth_payload)
            response_data = handle_scoped_token(token_ref,
                                                PROVIDERS.federation_api,
                                                PROVIDERS.identity_api)
        else:
            response_data = handle_unscoped_token(auth_payload,
                                                  PROVIDERS.resource_api,
                                                  PROVIDERS.federation_api,
                                                  PROVIDERS.identity_api,
                                                  PROVIDERS.assignment_api,
                                                  PROVIDERS.role_api)

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)


def handle_scoped_token(token, federation_api, identity_api):
    response_data = {}
    utils.validate_expiration(token)
    token_audit_id = token.audit_id
    identity_provider = token.identity_provider_id
    protocol = token.protocol_id
    user_id = token.user_id
    group_ids = []
    for group_dict in token.federated_groups:
        group_ids.append(group_dict['id'])
    send_notification = functools.partial(
        notifications.send_saml_audit_notification, 'authenticate',
        user_id, group_ids, identity_provider, protocol,
        token_audit_id)

    utils.assert_enabled_identity_provider(federation_api, identity_provider)

    try:
        mapping = federation_api.get_mapping_from_idp_and_protocol(
            identity_provider, protocol)
        utils.validate_mapped_group_ids(group_ids, mapping['id'], identity_api)

    except Exception:
        # NOTE(topol): Diaper defense to catch any exception, so we can
        # send off failed authentication notification, raise the exception
        # after sending the notification
        send_notification(taxonomy.OUTCOME_FAILURE)
        raise
    else:
        send_notification(taxonomy.OUTCOME_SUCCESS)

    response_data['user_id'] = user_id
    response_data['group_ids'] = group_ids
    response_data[federation_constants.IDENTITY_PROVIDER] = identity_provider
    response_data[federation_constants.PROTOCOL] = protocol

    return response_data


def handle_unscoped_token(auth_payload, resource_api, federation_api,
                          identity_api, assignment_api, role_api):

    def validate_shadow_mapping(shadow_projects, existing_roles, idp_domain_id,
                                idp_id):
        # Validate that the roles in the shadow mapping actually exist. If
        # they don't we should bail early before creating anything.
        for shadow_project in shadow_projects:
            for shadow_role in shadow_project['roles']:
                # The role in the project mapping must exist in order for it to
                # be useful.
                if shadow_role['name'] not in existing_roles:
                    LOG.error(
                        'Role %s was specified in the mapping but does '
                        'not exist. All roles specified in a mapping must '
                        'exist before assignment.',
                        shadow_role['name']
                    )
                    # NOTE(lbragstad): The RoleNotFound exception usually
                    # expects a role_id as the parameter, but in this case we
                    # only have a name so we'll pass that instead.
                    raise exception.RoleNotFound(shadow_role['name'])
                role = existing_roles[shadow_role['name']]
                if (role['domain_id'] is not None and
                        role['domain_id'] != idp_domain_id):
                    LOG.error(
                        'Role %(role)s is a domain-specific role and '
                        'cannot be assigned within %(domain)s.',
                        {'role': shadow_role['name'], 'domain': idp_domain_id}
                    )
                    raise exception.DomainSpecificRoleNotWithinIdPDomain(
                        role_name=shadow_role['name'],
                        identity_provider=idp_id
                    )

    def create_projects_from_mapping(shadow_projects, idp_domain_id,
                                     existing_roles, user, assignment_api,
                                     resource_api):
        for shadow_project in shadow_projects:
            try:
                # Check and see if the project already exists and if it
                # does not, try to create it.
                project = resource_api.get_project_by_name(
                    shadow_project['name'], idp_domain_id
                )
            except exception.ProjectNotFound:
                LOG.info(
                    'Project %(project_name)s does not exist. It will be '
                    'automatically provisioning for user %(user_id)s.',
                    {'project_name': shadow_project['name'],
                     'user_id': user['id']}
                )
                project_ref = {
                    'id': uuid.uuid4().hex,
                    'name': shadow_project['name'],
                    'domain_id': idp_domain_id
                }
                project = resource_api.create_project(
                    project_ref['id'],
                    project_ref
                )

            shadow_roles = shadow_project['roles']
            for shadow_role in shadow_roles:
                assignment_api.create_grant(
                    existing_roles[shadow_role['name']]['id'],
                    user_id=user['id'],
                    project_id=project['id']
                )

    def is_ephemeral_user(mapped_properties):
        return mapped_properties['user']['type'] == utils.UserType.EPHEMERAL

    def build_ephemeral_user_context(user, mapped_properties,
                                     identity_provider, protocol):
        resp = {}
        resp['user_id'] = user['id']
        resp['group_ids'] = mapped_properties['group_ids']
        resp[federation_constants.IDENTITY_PROVIDER] = identity_provider
        resp[federation_constants.PROTOCOL] = protocol

        return resp

    def build_local_user_context(mapped_properties):
        resp = {}
        user_info = auth_plugins.UserAuthInfo.create(mapped_properties,
                                                     METHOD_NAME)
        resp['user_id'] = user_info.user_id

        return resp

    assertion = extract_assertion_data()
    try:
        identity_provider = auth_payload['identity_provider']
    except KeyError:
        raise exception.ValidationError(
            attribute='identity_provider', target='mapped')
    try:
        protocol = auth_payload['protocol']
    except KeyError:
        raise exception.ValidationError(
            attribute='protocol', target='mapped')

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
        try:
            mapped_properties, mapping_id = apply_mapping_filter(
                identity_provider, protocol, assertion, resource_api,
                federation_api, identity_api)
        except exception.ValidationError as e:
            # if mapping is either invalid or yield no valid identity,
            # it is considered a failed authentication
            raise exception.Unauthorized(e)

        if is_ephemeral_user(mapped_properties):
            unique_id, display_name = (
                get_user_unique_id_and_display_name(mapped_properties)
            )
            email = mapped_properties['user'].get('email')
            user = identity_api.shadow_federated_user(
                identity_provider,
                protocol, unique_id,
                display_name,
                email,
                group_ids=mapped_properties['group_ids'])

            if 'projects' in mapped_properties:
                idp_domain_id = federation_api.get_idp(
                    identity_provider
                )['domain_id']
                existing_roles = {
                    role['name']: role for role in role_api.list_roles()
                }
                # NOTE(lbragstad): If we are dealing with a shadow mapping,
                # then we need to make sure we validate all pieces of the
                # mapping and what it's saying to create. If there is something
                # wrong with how the mapping is, we should bail early before we
                # create anything.
                validate_shadow_mapping(
                    mapped_properties['projects'],
                    existing_roles,
                    idp_domain_id,
                    identity_provider
                )
                create_projects_from_mapping(
                    mapped_properties['projects'],
                    idp_domain_id,
                    existing_roles,
                    user,
                    assignment_api,
                    resource_api
                )

            user_id = user['id']
            group_ids = mapped_properties['group_ids']
            response_data = build_ephemeral_user_context(
                user, mapped_properties, identity_provider, protocol)
        else:
            response_data = build_local_user_context(mapped_properties)

    except Exception:
        # NOTE(topol): Diaper defense to catch any exception, so we can
        # send off failed authentication notification, raise the exception
        # after sending the notification
        outcome = taxonomy.OUTCOME_FAILURE
        notifications.send_saml_audit_notification('authenticate',
                                                   user_id, group_ids,
                                                   identity_provider,
                                                   protocol, token_id,
                                                   outcome)
        raise
    else:
        outcome = taxonomy.OUTCOME_SUCCESS
        notifications.send_saml_audit_notification('authenticate',
                                                   user_id, group_ids,
                                                   identity_provider,
                                                   protocol, token_id,
                                                   outcome)

    return response_data


def extract_assertion_data():
    assertion = dict(utils.get_assertion_params_from_env())
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
    utils.validate_mapped_group_ids(group_ids, mapping_id, identity_api)
    group_ids.extend(
        utils.transform_to_group_ids(
            mapped_properties['group_names'], mapping_id,
            identity_api, resource_api))
    mapped_properties['group_ids'] = list(set(group_ids))
    return mapped_properties, mapping_id


def get_user_unique_id_and_display_name(mapped_properties):
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

    :param mapped_properties: Properties issued by a RuleProcessor.
    :type: dictionary

    :raises keystone.exception.Unauthorized: If neither `user_name` nor
        `user_id` is set.
    :returns: tuple with user identification
    :rtype: tuple

    """
    user = mapped_properties['user']

    user_id = user.get('id')
    user_name = user.get('name') or flask.request.remote_user

    if not any([user_id, user_name]):
        msg = _("Could not map user while setting ephemeral user identity. "
                "Either mapping rules must specify user id/name or "
                "REMOTE_USER environment variable must be set.")
        raise exception.Unauthorized(msg)

    elif not user_name:
        user['name'] = user_id

    elif not user_id:
        user_id = user_name

    if user_name:
        user['name'] = user_name
    user['id'] = parse.quote(user_id)
    return (user['id'], user['name'])
