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

# Shared code for Authentication flows. This module is where actual auth
# happens. The code here is shared between Federation and Auth.

# TODO(morgan): Deprecate all auth flows in /v3/OS-FEDERATION, merge this code
# into keystone.api.auth. For now this is the best place for the code to
# exist.

import flask
from oslo_log import log

from keystone.auth import core
from keystone.common import provider_api
from keystone import exception
from keystone.federation import constants
from keystone.i18n import _
from keystone.receipt import handlers as receipt_handlers


LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


def _check_and_set_default_scoping(auth_info, auth_context):
    (domain_id, project_id, trust, unscoped, system) = (
        auth_info.get_scope()
    )
    if trust:
        project_id = trust['project_id']
    if system or domain_id or project_id or trust:
        # scope is specified
        return

    # Skip scoping when unscoped federated token is being issued
    if constants.IDENTITY_PROVIDER in auth_context:
        return

    # Do not scope if request is for explicitly unscoped token
    if unscoped is not None:
        return

    # fill in default_project_id if it is available
    try:
        user_ref = PROVIDERS.identity_api.get_user(auth_context['user_id'])
    except exception.UserNotFound as e:
        LOG.warning(e)
        raise exception.Unauthorized(e)

    default_project_id = user_ref.get('default_project_id')
    if not default_project_id:
        # User has no default project. He shall get an unscoped token.
        return

    # make sure user's default project is legit before scoping to it
    try:
        default_project_ref = PROVIDERS.resource_api.get_project(
            default_project_id)
        default_project_domain_ref = PROVIDERS.resource_api.get_domain(
            default_project_ref['domain_id'])
        if (default_project_ref.get('enabled', True) and
                default_project_domain_ref.get('enabled', True)):
            if PROVIDERS.assignment_api.get_roles_for_user_and_project(
                    user_ref['id'], default_project_id):
                auth_info.set_scope(project_id=default_project_id)
            else:
                msg = ("User %(user_id)s doesn't have access to"
                       " default project %(project_id)s. The token"
                       " will be unscoped rather than scoped to the"
                       " project.")
                LOG.debug(msg,
                          {'user_id': user_ref['id'],
                           'project_id': default_project_id})
        else:
            msg = ("User %(user_id)s's default project %(project_id)s"
                   " is disabled. The token will be unscoped rather"
                   " than scoped to the project.")
            LOG.debug(msg,
                      {'user_id': user_ref['id'],
                       'project_id': default_project_id})
    except (exception.ProjectNotFound, exception.DomainNotFound):
        # default project or default project domain doesn't exist,
        # will issue unscoped token instead
        msg = ("User %(user_id)s's default project %(project_id)s not"
               " found. The token will be unscoped rather than"
               " scoped to the project.")
        LOG.debug(msg, {'user_id': user_ref['id'],
                        'project_id': default_project_id})


def authenticate(auth_info, auth_context):
    """Authenticate user."""
    # NOTE(notmorgan): This is not super pythonic, but we lean on the
    # __setitem__ method in auth_context to handle edge cases and security
    # of the attributes set by the plugins. This check to ensure
    # `auth_context` is an instance of AuthContext is extra insurance and
    # will prevent regressions.

    if not isinstance(auth_context, core.AuthContext):
        LOG.error(
            '`auth_context` passed to the Auth controller '
            '`authenticate` method is not of type '
            '`keystone.auth.core.AuthContext`. For security '
            'purposes this is required. This is likely a programming '
            'error. Received object of type `%s`', type(auth_context))
        raise exception.Unauthorized(
            _('Cannot Authenticate due to internal error.'))
    # The 'external' method allows any 'REMOTE_USER' based authentication
    # In some cases the server can set REMOTE_USER as '' instead of
    # dropping it, so this must be filtered out
    if flask.request.remote_user:
        try:
            external = core.get_auth_method('external')
            resp = external.authenticate(auth_info)
            if resp and resp.status:
                # NOTE(notmorgan): ``external`` plugin cannot be multi-step
                # it is either a plain success/fail.
                auth_context.setdefault(
                    'method_names', []).insert(0, 'external')
                # NOTE(notmorgan): All updates to auth_context is handled
                # here in the .authenticate method.
                auth_context.update(resp.response_data or {})

        except exception.AuthMethodNotSupported:
            # This will happen there is no 'external' plugin registered
            # and the container is performing authentication.
            # The 'kerberos'  and 'saml' methods will be used this way.
            # In those cases, it is correct to not register an
            # 'external' plugin;  if there is both an 'external' and a
            # 'kerberos' plugin, it would run the check on identity twice.
            LOG.debug("No 'external' plugin is registered.")
        except exception.Unauthorized:
            # If external fails then continue and attempt to determine
            # user identity using remaining auth methods
            LOG.debug("Authorization failed for 'external' auth method.")

    # need to aggregate the results in case two or more methods
    # are specified
    auth_response = {'methods': []}
    for method_name in auth_info.get_method_names():
        method = core.get_auth_method(method_name)
        resp = method.authenticate(auth_info.get_method_data(method_name))
        if resp:
            if resp.status:
                auth_context.setdefault(
                    'method_names', []).insert(0, method_name)
                # NOTE(notmorgan): All updates to auth_context is handled
                # here in the .authenticate method. If the auth attempt was
                # not successful do not update the auth_context
                resp_method_names = resp.response_data.pop(
                    'method_names', [])
                auth_context['method_names'].extend(resp_method_names)
                auth_context.update(resp.response_data or {})
            elif resp.response_body:
                auth_response['methods'].append(method_name)
                auth_response[method_name] = resp.response_body

    if auth_response["methods"]:
        # authentication continuation required
        raise exception.AdditionalAuthRequired(auth_response)

    if 'user_id' not in auth_context:
        msg = 'User not found by auth plugin; authentication failed'
        tr_msg = _('User not found by auth plugin; authentication failed')
        LOG.warning(msg)
        raise exception.Unauthorized(tr_msg)


def authenticate_for_token(auth=None):
    """Authenticate user and issue a token."""
    try:
        auth_info = core.AuthInfo.create(auth=auth)
        auth_context = core.AuthContext(method_names=[],
                                        bind={})
        authenticate(auth_info, auth_context)
        if auth_context.get('access_token_id'):
            auth_info.set_scope(None, auth_context['project_id'], None)
        _check_and_set_default_scoping(auth_info, auth_context)
        (domain_id, project_id, trust, unscoped, system) = (
            auth_info.get_scope()
        )
        trust_id = trust.get('id') if trust else None

        receipt = receipt_handlers.extract_receipt(auth_context)

        # NOTE(notmorgan): only methods that actually run and succeed will
        # be in the auth_context['method_names'] list. Do not blindly take
        # the values from auth_info, look at the authoritative values. Make
        # sure the set is unique.
        # NOTE(adriant): The set of methods will also include any methods from
        # the given receipt.
        if receipt:
            method_names_set = set(
                auth_context.get('method_names', []) + receipt.methods)
        else:
            method_names_set = set(auth_context.get('method_names', []))
        method_names = list(method_names_set)

        app_cred_id = None
        if 'application_credential' in method_names:
            token_auth = auth_info.auth['identity']
            app_cred_id = token_auth['application_credential']['id']

        # Do MFA Rule Validation for the user
        if not core.UserMFARulesValidator.check_auth_methods_against_rules(
                auth_context['user_id'], method_names_set):
            raise exception.InsufficientAuthMethods(
                user_id=auth_context['user_id'],
                methods=method_names)

        expires_at = auth_context.get('expires_at')
        token_audit_id = auth_context.get('audit_id')

        token = PROVIDERS.token_provider_api.issue_token(
            auth_context['user_id'], method_names, expires_at=expires_at,
            system=system, project_id=project_id, domain_id=domain_id,
            auth_context=auth_context, trust_id=trust_id,
            app_cred_id=app_cred_id, parent_audit_id=token_audit_id)

        # NOTE(wanghong): We consume a trust use only when we are using
        # trusts and have successfully issued a token.
        if trust:
            PROVIDERS.trust_api.consume_use(token.trust_id)

        return token
    except exception.TrustNotFound as e:
        LOG.warning(e)
        raise exception.Unauthorized(e)


def federated_authenticate_for_token(identity_provider, protocol_id):
    auth = {
        'identity': {
            'methods': [protocol_id],
            protocol_id: {
                'identity_provider': identity_provider,
                'protocol': protocol_id
            }
        }
    }
    return authenticate_for_token(auth)
