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


# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'


# Header used to transmit the subject token
SUBJECT_TOKEN_HEADER = 'X-Subject-Token'


CONF = conf.CONF

# Environment variable used to convey the Keystone auth context,
# the user credential used for policy enforcement.
AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'

LOG = log.getLogger(__name__)


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
    if request.subject_token is not None:
        window_seconds = token_validation_window(request)

        token = self.token_provider_api.validate_token(
            request.subject_token, window_seconds=window_seconds
        )
        policy_dict.setdefault('target', {})
        policy_dict['target'].setdefault(self.member_name, {})
        policy_dict['target'][self.member_name]['user_id'] = (token.user_id)
        try:
            user_domain_id = token.user_domain['id']
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
    """Retrieve TokenModel object from the auth context and returns it.

    :param dict context: The request context.
    :raises keystone.exception.Unauthorized: If auth context cannot be found.
    :returns: The TokenModel object.
    """
    try:
        # Retrieve the auth context that was prepared by AuthContextMiddleware.
        auth_context = (context['environment'][AUTH_CONTEXT_ENV])
        return auth_context['token']
    except KeyError:
        LOG.warning("Couldn't find the auth context.")
        raise exception.Unauthorized()
