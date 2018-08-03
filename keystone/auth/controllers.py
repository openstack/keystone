# Copyright 2013 OpenStack Foundation
#
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

from oslo_log import log
import six

from keystone.auth import core
from keystone.auth import schema
from keystone.common import authorization
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.federation import constants
from keystone.i18n import _
from keystone.resource import controllers as resource_controllers


LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class Auth(controller.V3Controller):

    # Note(atiwari): From V3 auth controller code we are
    # calling protection() wrappers, so we need to setup
    # the member_name and  collection_name attributes of
    # auth controller code.
    # In the absence of these attributes, default 'entity'
    # string will be used to represent the target which is
    # generic. Policy can be defined using 'entity' but it
    # would not reflect the exact entity that is in context.
    # We are defining collection_name = 'tokens' and
    # member_name = 'token' to facilitate policy decisions.
    collection_name = 'tokens'
    member_name = 'token'

    def __init__(self, *args, **kw):
        super(Auth, self).__init__(*args, **kw)
        keystone.conf.auth.setup_authentication()
        self._mfa_rules_validator = core.UserMFARulesValidator()

    def authenticate_for_token(self, request, auth=None):
        """Authenticate user and issue a token."""
        include_catalog = 'nocatalog' not in request.params

        schema.validate_issue_token_auth(auth)

        try:
            auth_info = core.AuthInfo.create(auth=auth)
            auth_context = core.AuthContext(method_names=[],
                                            bind={})
            self.authenticate(request, auth_info, auth_context)
            if auth_context.get('access_token_id'):
                auth_info.set_scope(None, auth_context['project_id'], None)
            self._check_and_set_default_scoping(auth_info, auth_context)
            (domain_id, project_id, trust, unscoped, system) = (
                auth_info.get_scope()
            )
            trust_id = trust.get('id') if trust else None

            # NOTE(notmorgan): only methods that actually run and succeed will
            # be in the auth_context['method_names'] list. Do not blindly take
            # the values from auth_info, look at the authoritative values. Make
            # sure the set is unique.
            method_names_set = set(auth_context.get('method_names', []))
            method_names = list(method_names_set)

            app_cred_id = None
            if 'application_credential' in method_names:
                token_auth = auth_info.auth['identity']
                app_cred_id = token_auth['application_credential']['id']

            # Do MFA Rule Validation for the user
            if not self._mfa_rules_validator.check_auth_methods_against_rules(
                    auth_context['user_id'], method_names_set):
                raise exception.InsufficientAuthMethods(
                    user_id=auth_context['user_id'],
                    methods='[%s]' % ','.join(auth_info.get_method_names()))

            expires_at = auth_context.get('expires_at')
            token_audit_id = auth_context.get('audit_id')

            token = PROVIDERS.token_provider_api.issue_token(
                auth_context['user_id'], method_names, expires_at=expires_at,
                system=system, project_id=project_id, domain_id=domain_id,
                auth_context=auth_context, trust_id=trust_id,
                app_cred_id=app_cred_id, parent_audit_id=token_audit_id)
            token_reference = controller.render_token_response_from_model(
                token, include_catalog=include_catalog
            )

            # NOTE(wanghong): We consume a trust use only when we are using
            # trusts and have successfully issued a token.
            if trust:
                PROVIDERS.trust_api.consume_use(token.trust_id)

            return render_token_data_response(token.id, token_reference,
                                              created=True)
        except exception.TrustNotFound as e:
            LOG.warning(six.text_type(e))
            raise exception.Unauthorized(e)

    def _check_and_set_default_scoping(self, auth_info, auth_context):
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
            LOG.warning(six.text_type(e))
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

    def authenticate(self, request, auth_info, auth_context):
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
        if request.remote_user:
            try:
                external = core.get_auth_method('external')
                resp = external.authenticate(request,
                                             auth_info)
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
            resp = method.authenticate(request,
                                       auth_info.get_method_data(method_name))
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
            msg = _('User not found by auth plugin; authentication failed')
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

    @controller.protected()
    def check_token(self, request):
        token_id = request.subject_token
        window_seconds = authorization.token_validation_window(request)
        include_catalog = 'nocatalog' not in request.params
        token = PROVIDERS.token_provider_api.validate_token(
            token_id, window_seconds=window_seconds)
        token_reference = controller.render_token_response_from_model(
            token, include_catalog=include_catalog
        )
        # NOTE(morganfainberg): The code in
        # ``keystone.common.wsgi.render_response`` will remove the content
        # body.

        return render_token_data_response(token.id, token_reference)

    @controller.protected()
    def revoke_token(self, request):
        return PROVIDERS.token_provider_api.revoke_token(request.subject_token)

    @controller.protected()
    def validate_token(self, request):
        token_id = request.subject_token
        window_seconds = authorization.token_validation_window(request)
        include_catalog = 'nocatalog' not in request.params

        token = PROVIDERS.token_provider_api.validate_token(
            token_id, window_seconds=window_seconds)
        token_reference = controller.render_token_response_from_model(
            token, include_catalog=include_catalog
        )

        return render_token_data_response(token.id, token_reference)

    def revocation_list(self, request):
        if not CONF.token.revoke_by_id:
            raise exception.Gone()
        # NOTE(lbragstad): This API is deprecated and isn't supported. Keystone
        # also doesn't store tokens, so returning a list of revoked tokens
        # would require keystone to write invalid tokens to disk, which defeats
        # the purpose. Return a 403 instead of removing the API all together.
        # The alternative would be to return a signed response of just an empty
        # list.
        raise exception.Forbidden()

    def _combine_lists_uniquely(self, a, b):
        # it's most likely that only one of these will be filled so avoid
        # the combination if possible.
        if a and b:
            return {x['id']: x for x in a + b}.values()
        else:
            return a or b

    @controller.protected()
    def get_auth_projects(self, request):
        user_id = request.auth_context.get('user_id')
        group_ids = request.auth_context.get('group_ids')

        user_refs = []
        if user_id:
            try:
                user_refs = PROVIDERS.assignment_api.list_projects_for_user(
                    user_id
                )
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        grp_refs = []
        if group_ids:
            grp_refs = PROVIDERS.assignment_api.list_projects_for_groups(
                group_ids
            )

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.ProjectV3.wrap_collection(
            request.context_dict, refs)

    @controller.protected()
    def get_auth_domains(self, request):
        user_id = request.auth_context.get('user_id')
        group_ids = request.auth_context.get('group_ids')

        user_refs = []
        if user_id:
            try:
                user_refs = PROVIDERS.assignment_api.list_domains_for_user(
                    user_id
                )
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        grp_refs = []
        if group_ids:
            grp_refs = PROVIDERS.assignment_api.list_domains_for_groups(
                group_ids
            )

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.DomainV3.wrap_collection(
            request.context_dict, refs)

    @controller.protected()
    def get_auth_system(self, request):
        user_id = request.auth_context.get('user_id')
        group_ids = request.auth_context.get('group_ids')

        user_assignments = []
        if user_id:
            try:
                user_assignments = (
                    PROVIDERS.assignment_api.list_system_grants_for_user(
                        user_id
                    )
                )
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        group_assignments = []
        if group_ids:
            group_assignments = (
                PROVIDERS.assignment_api.list_system_grants_for_group(
                    group_ids
                )
            )

        assignments = self._combine_lists_uniquely(
            user_assignments, group_assignments
        )
        if assignments:
            response = {
                'system': [{'all': True}],
                'links': {
                    'self': self.base_url(
                        request.context_dict, path='auth/system'
                    )
                }
            }
        else:
            response = {
                'system': [],
                'links': {
                    'self': self.base_url(
                        request.context_dict, path='auth/system'
                    )
                }
            }
        return response

    @controller.protected()
    def get_auth_catalog(self, request):
        user_id = request.auth_context.get('user_id')
        project_id = request.auth_context.get('project_id')

        if not project_id:
            raise exception.Forbidden(
                _('A project-scoped token is required to produce a service '
                  'catalog.'))

        # The V3Controller base methods mostly assume that you're returning
        # either a collection or a single element from a collection, neither of
        # which apply to the catalog. Because this is a special case, this
        # re-implements a tiny bit of work done by the base controller (such as
        # self-referential link building) to avoid overriding or refactoring
        # several private methods.
        return {
            'catalog': PROVIDERS.catalog_api.get_v3_catalog(
                user_id, project_id
            ),
            'links': {'self': self.base_url(request.context_dict,
                                            path='auth/catalog')}
        }


# FIXME(gyee): not sure if it belongs here or keystone.common. Park it here
# for now.
def render_token_data_response(token_id, token_data, created=False):
    """Render token data HTTP response.

    Stash token ID into the X-Subject-Token header.

    """
    headers = [('X-Subject-Token', token_id)]

    if created:
        status = (201, 'Created')
    else:
        status = (200, 'OK')

    return wsgi.render_response(body=token_data,
                                status=status, headers=headers)
