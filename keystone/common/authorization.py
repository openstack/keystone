# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_log import log
from oslo_utils import strutils

from keystone.common.policies import base as pol_base
from keystone.common import utils
from keystone import conf
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model


CONF = conf.CONF
AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'
"""Environment variable used to convey the Keystone auth context.

Auth context is essentially the user credential used for policy enforcement.
It is a dictionary with the following attributes:

* ``token``: Token from the request
* ``user_id``: user ID of the principal
* ``user_domain_id`` (optional): Domain ID of the principal if the principal
                                 has a domain.
* ``project_id`` (optional): project ID of the scoped project if auth is
                             project-scoped
* ``project_domain_id`` (optional): Domain ID of the scoped project if auth is
                                    project-scoped.
* ``domain_id`` (optional): domain ID of the scoped domain if auth is
                            domain-scoped
* ``domain_name`` (optional): domain name of the scoped domain if auth is
                              domain-scoped
* ``is_delegated_auth``: True if this is delegated (via trust or oauth)
* ``trust_id``: Trust ID if trust-scoped, or None
* ``trustor_id``: Trustor ID if trust-scoped, or None
* ``trustee_id``: Trustee ID if trust-scoped, or None
* ``consumer_id``: OAuth consumer ID, or None
* ``access_token_id``: OAuth access token ID, or None
* ``roles`` (optional): list of role names for the given scope
* ``group_ids`` (optional): list of group IDs for which the API user has
                            membership if token was for a federated user

"""

LOG = log.getLogger(__name__)


def token_to_auth_context(token):
    if not isinstance(token, token_model.KeystoneToken):
        raise exception.UnexpectedError(_('token reference must be a '
                                          'KeystoneToken type, got: %s') %
                                        type(token))
    auth_context = {'token': token,
                    'is_delegated_auth': False}
    try:
        auth_context['user_id'] = token.user_id
    except KeyError:
        LOG.warning('RBAC: Invalid user data in token')
        raise exception.Unauthorized(_('No user_id in token'))
    auth_context['user_domain_id'] = token.user_domain_id

    if token.project_scoped:
        auth_context['project_id'] = token.project_id
        auth_context['project_domain_id'] = token.project_domain_id
        auth_context['is_domain'] = token.is_domain
    elif token.domain_scoped:
        auth_context['domain_id'] = token.domain_id
        auth_context['domain_name'] = token.domain_name
    else:
        LOG.debug('RBAC: Proceeding without project or domain scope')

    if token.trust_scoped:
        auth_context['is_delegated_auth'] = True
        auth_context['trust_id'] = token.trust_id
        auth_context['trustor_id'] = token.trustor_user_id
        auth_context['trustee_id'] = token.trustee_user_id
    else:
        # NOTE(lbragstad): These variables will already be set to None but we
        # add the else statement here for readability.
        auth_context['trust_id'] = None
        auth_context['trustor_id'] = None
        auth_context['trustee_id'] = None

    roles = token.role_names
    if roles:
        auth_context['roles'] = roles

    if token.oauth_scoped:
        auth_context['is_delegated_auth'] = True
        auth_context['consumer_id'] = token.oauth_consumer_id
        auth_context['access_token_id'] = token.oauth_access_token_id
    else:
        # NOTE(lbragstad): These variables will already be set to None but we
        # add the else statement here for readability.
        auth_context['consumer_id'] = None
        auth_context['access_token_id'] = None

    if token.is_federated_user:
        auth_context['group_ids'] = token.federation_group_ids

    auth_context['is_admin_project'] = token.is_admin_project
    return auth_context


def assert_admin(app, request):
    """Ensure the user is an admin.

    :raises keystone.exception.Unauthorized: if a token could not be
        found/authorized, a user is invalid, or a tenant is
        invalid/not scoped.
    :raises keystone.exception.Forbidden: if the user is not an admin and
        does not have the admin role

    """
    check_policy(app, request, 'admin_required', input_attr={})


def _build_policy_check_credentials(action, context, kwargs):
    kwargs_str = ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])
    kwargs_str = strutils.mask_password(kwargs_str)
    msg = 'RBAC: Authorizing %(action)s(%(kwargs)s)'
    LOG.debug(msg, {'action': action, 'kwargs': kwargs_str})

    return context['environment'].get(AUTH_CONTEXT_ENV, {})


def _handle_member_from_driver(self, policy_dict, **kwargs):
    # Check to see if we need to include the target entity in our
    # policy checks.  We deduce this by seeing if the class has
    # specified a get_member() method and that kwargs contains the
    # appropriate entity id.
    if (hasattr(self, 'get_member_from_driver') and
            self.get_member_from_driver is not None):
        key = '%s_id' % self.member_name
        if key in kwargs:
            ref = self.get_member_from_driver(kwargs[key])
            policy_dict['target'] = {self.member_name: ref}


def token_validation_window(request):
    # NOTE(jamielennox): it's dumb that i have to put this here. We should
    # only validate subject token in one place.

    allow_expired = request.params.get('allow_expired')
    allow_expired = strutils.bool_from_string(allow_expired, default=False)
    return CONF.token.allow_expired_window if allow_expired else 0


def _handle_subject_token_id(self, request, policy_dict):
    if request.context_dict.get('subject_token_id') is not None:
        window_seconds = token_validation_window(request)

        token_ref = token_model.KeystoneToken(
            token_id=request.context_dict['subject_token_id'],
            token_data=self.token_provider_api.validate_token(
                request.context_dict['subject_token_id'],
                window_seconds=window_seconds))
        policy_dict.setdefault('target', {})
        policy_dict['target'].setdefault(self.member_name, {})
        policy_dict['target'][self.member_name]['user_id'] = (
            token_ref.user_id)
        try:
            user_domain_id = token_ref.user_domain_id
        except exception.UnexpectedError:
            user_domain_id = None
        if user_domain_id:
            policy_dict['target'][self.member_name].setdefault(
                'user', {})
            policy_dict['target'][self.member_name][
                'user'].setdefault('domain', {})
            policy_dict['target'][self.member_name]['user'][
                'domain']['id'] = (
                    user_domain_id)


def check_protection(controller, request, prep_info, target_attr=None,
                     *args, **kwargs):
    """Provide call protection for complex target attributes.

    As well as including the standard parameters from the original API
    call (which is passed in prep_info), this call will add in any
    additional entities or attributes (passed in target_attr), so that
    they can be referenced by policy rules.

    """
    check_policy(controller, request,
                 pol_base.IDENTITY % prep_info['f_name'],
                 prep_info.get('filter_attr'),
                 prep_info.get('input_attr'),
                 target_attr,
                 *args, **kwargs)


def check_policy(controller, request, action,
                 filter_attr=None, input_attr=None, target_attr=None,
                 *args, **kwargs):
    # Makes the arguments from check protection explicit.
    request.assert_authenticated()
    if request.context.is_admin:
        LOG.warning('RBAC: Bypassing authorization')
        return

    # TODO(henry-nash) need to log the target attributes as well
    creds = _build_policy_check_credentials(
        action, request.context_dict, input_attr)
    # Build the dict the policy engine will check against from both the
    # parameters passed into the call we are protecting plus the target
    # attributes provided.
    policy_dict = {}
    _handle_member_from_driver(controller, policy_dict, **kwargs)
    _handle_subject_token_id(controller, request, policy_dict)

    if target_attr:
        policy_dict = {'target': target_attr}
    if input_attr:
        policy_dict.update(input_attr)
    if filter_attr:
        policy_dict.update(filter_attr)

    for key in kwargs:
        policy_dict[key] = kwargs[key]
    controller.policy_api.enforce(creds,
                                  action,
                                  utils.flatten_dict(policy_dict))
    LOG.debug('RBAC: Authorization granted')


def get_token_ref(context):
    """Retrieve KeystoneToken object from the auth context and returns it.

    :param dict context: The request context.
    :raises keystone.exception.Unauthorized: If auth context cannot be found.
    :returns: The KeystoneToken object.
    """
    try:
        # Retrieve the auth context that was prepared by AuthContextMiddleware.
        auth_context = (context['environment'][AUTH_CONTEXT_ENV])
        return auth_context['token']
    except KeyError:
        LOG.warning("Couldn't find the auth context.")
        raise exception.Unauthorized()
