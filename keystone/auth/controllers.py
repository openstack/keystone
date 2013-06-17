# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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


from keystone.common import controller
from keystone.common import dependency
from keystone.common import logging
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
from keystone.openstack.common import importutils
from keystone import token
from keystone import trust


LOG = logging.getLogger(__name__)

CONF = config.CONF

# registry of authentication methods
AUTH_METHODS = {}


def load_auth_method(method_name):
    if method_name not in CONF.auth.methods:
        raise exception.AuthMethodNotSupported()
    driver = CONF.auth.get(method_name)
    return importutils.import_object(driver)


def get_auth_method(method_name):
    global AUTH_METHODS
    if method_name not in AUTH_METHODS:
        AUTH_METHODS[method_name] = load_auth_method(method_name)
    return AUTH_METHODS[method_name]


class AuthInfo(object):
    """Encapsulation of "auth" request."""

    def __init__(self, context, auth=None):
        self.identity_api = identity.Manager()
        self.trust_api = trust.Manager()
        self.context = context
        self.auth = auth
        self._scope_data = (None, None, None)
        # self._scope_data is (domain_id, project_id, trust_ref)
        # project scope: (None, project_id, None)
        # domain scope: (domain_id, None, None)
        # trust scope: (None, None, trust_ref)
        # unscoped: (None, None, None)
        self._validate_and_normalize_auth_data()

    def _assert_project_is_enabled(self, project_ref):
        # ensure the project is enabled
        if not project_ref.get('enabled', True):
            msg = _('Project is disabled: %s') % project_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

    def _assert_domain_is_enabled(self, domain_ref):
        if not domain_ref.get('enabled'):
            msg = _('Domain is disabled: %s') % (domain_ref['id'])
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

    def _assert_user_is_enabled(self, user_ref):
        if not user_ref.get('enabled', True):
            msg = _('User is disabled: %s') % (user_ref['id'])
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

    def _lookup_domain(self, domain_info):
        domain_id = domain_info.get('id')
        domain_name = domain_info.get('name')
        domain_ref = None
        if not domain_id and not domain_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='domain')
        try:
            if domain_name:
                domain_ref = self.identity_api.get_domain_by_name(domain_name)
            else:
                domain_ref = self.identity_api.get_domain(domain_id)
        except exception.DomainNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_domain_is_enabled(domain_ref)
        return domain_ref

    def _lookup_project(self, project_info):
        project_id = project_info.get('id')
        project_name = project_info.get('name')
        project_ref = None
        if not project_id and not project_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='project')
        try:
            if project_name:
                if 'domain' not in project_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='project')
                domain_ref = self._lookup_domain(project_info['domain'])
                project_ref = self.identity_api.get_project_by_name(
                    project_name, domain_ref['id'])
            else:
                project_ref = self.identity_api.get_project(project_id)
        except exception.ProjectNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_project_is_enabled(project_ref)
        return project_ref

    def _lookup_trust(self, trust_info):
        trust_id = trust_info.get('id')
        if not trust_id:
            raise exception.ValidationError(attribute='trust_id',
                                            target='trust')
        trust = self.trust_api.get_trust(trust_id)
        if not trust:
            raise exception.TrustNotFound(trust_id=trust_id)
        return trust

    def lookup_user(self, user_info):
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        user_ref = None
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        try:
            if user_name:
                if 'domain' not in user_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='user')
                domain_ref = self._lookup_domain(user_info['domain'])
                user_ref = self.identity_api.get_user_by_name(
                    user_name, domain_ref['id'])
            else:
                user_ref = self.identity_api.get_user(user_id)
        except exception.UserNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_user_is_enabled(user_ref)
        return user_ref

    def _validate_and_normalize_scope_data(self):
        """Validate and normalize scope data."""
        if 'scope' not in self.auth:
            return
        if sum(['project' in self.auth['scope'],
                'domain' in self.auth['scope'],
                'OS-TRUST:trust' in self.auth['scope']]) != 1:
            raise exception.ValidationError(
                attribute='project, domain, or OS-TRUST:trust',
                target='scope')

        if 'project' in self.auth['scope']:
            project_ref = self._lookup_project(self.auth['scope']['project'])
            self._scope_data = (None, project_ref['id'], None)
        elif 'domain' in self.auth['scope']:
            domain_ref = self._lookup_domain(self.auth['scope']['domain'])
            self._scope_data = (domain_ref['id'], None, None)
        elif 'OS-TRUST:trust' in self.auth['scope']:
            if not CONF.trust.enabled:
                raise exception.Forbidden('Trusts are disabled.')
            trust_ref = self._lookup_trust(
                self.auth['scope']['OS-TRUST:trust'])
            # TODO(ayoung): when trusts support domains, fill in domain data
            if 'project_id' in trust_ref:
                project_ref = self._lookup_project(
                    {'id': trust_ref['project_id']})
                self._scope_data = (None, project_ref['id'], trust_ref)
            else:
                self._scope_data = (None, None, trust_ref)

    def _validate_auth_methods(self):
        if 'identity' not in self.auth:
            raise exception.ValidationError(attribute='identity',
                                            target='auth')

        # make sure auth methods are provided
        if 'methods' not in self.auth['identity']:
            raise exception.ValidationError(attribute='methods',
                                            target='identity')

        # make sure all the method data/payload are provided
        for method_name in self.get_method_names():
            if method_name not in self.auth['identity']:
                raise exception.ValidationError(attribute=method_name,
                                                target='identity')

        # make sure auth method is supported
        for method_name in self.get_method_names():
            if method_name not in CONF.auth.methods:
                raise exception.AuthMethodNotSupported()

    def _validate_and_normalize_auth_data(self):
        """Make sure "auth" is valid."""
        # make sure "auth" exist
        if not self.auth:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')

        self._validate_auth_methods()
        self._validate_and_normalize_scope_data()

    def get_method_names(self):
        """Returns the identity method names.

        :returns: list of auth method names

        """
        return self.auth['identity']['methods'] or []

    def get_method_data(self, method):
        """Get the auth method payload.

        :returns: auth method payload

        """
        if method not in self.auth['identity']['methods']:
            raise exception.ValidationError(attribute=method,
                                            target='identity')
        return self.auth['identity'][method]

    def get_scope(self):
        """Get scope information.

        Verify and return the scoping information.

        :returns: (domain_id, project_id, trust_ref).
                   If scope to a project, (None, project_id, None)
                   will be returned.
                   If scoped to a domain, (domain_id, None,None)
                   will be returned.
                   If scoped to a trust, (None, project_id, trust_ref),
                   Will be returned, where the project_id comes from the
                   trust definition.
                   If unscoped, (None, None, None) will be returned.

        """
        return self._scope_data

    def set_scope(self, domain_id=None, project_id=None, trust=None):
        """Set scope information."""
        if domain_id and project_id:
            msg = _('Scoping to both domain and project is not allowed')
            raise ValueError(msg)
        if domain_id and trust:
            msg = _('Scoping to both domain and trust is not allowed')
            raise ValueError(msg)
        if project_id and trust:
            msg = _('Scoping to both project and trust is not allowed')
            raise ValueError(msg)
        self._scope_data = (domain_id, project_id, trust)


@dependency.requires('token_provider_api')
class Auth(controller.V3Controller):
    def __init__(self, *args, **kw):
        super(Auth, self).__init__(*args, **kw)
        self.token_controllers_ref = token.controllers.Auth()
        config.setup_authentication()

    def authenticate_for_token(self, context, auth=None):
        """Authenticate user and issue a token."""
        include_catalog = 'nocatalog' not in context['query_string']

        try:
            auth_info = AuthInfo(context, auth=auth)
            auth_context = {'extras': {}, 'method_names': [], 'bind': {}}
            self.authenticate(context, auth_info, auth_context)
            self._check_and_set_default_scoping(auth_info, auth_context)
            (domain_id, project_id, trust) = auth_info.get_scope()
            method_names = auth_info.get_method_names()
            method_names += auth_context.get('method_names', [])
            # make sure the list is unique
            method_names = list(set(method_names))

            (token_id, token_data) = self.token_provider_api.issue_token(
                user_id=auth_context['user_id'],
                method_names=method_names,
                expires_at=auth_context.get('expires_at'),
                project_id=project_id,
                domain_id=domain_id,
                auth_context=auth_context,
                trust=trust,
                include_catalog=include_catalog)
            return render_token_data_response(token_id, token_data,
                                              created=True)
        except exception.TrustNotFound as e:
            raise exception.Unauthorized(e)

    def _check_and_set_default_scoping(self, auth_info, auth_context):
        (domain_id, project_id, trust) = auth_info.get_scope()
        if trust:
            project_id = trust['project_id']
        if domain_id or project_id or trust:
            # scope is specified
            return

        # fill in default_project_id if it is available
        try:
            user_ref = self.identity_api.get_user(auth_context['user_id'])
            default_project_id = user_ref.get('default_project_id')
            if default_project_id:
                auth_info.set_scope(domain_id=None,
                                    project_id=default_project_id)
        except exception.UserNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)

    def authenticate(self, context, auth_info, auth_context):
        """Authenticate user."""

        # user have been authenticated externally
        if 'REMOTE_USER' in context:
            external = get_auth_method('external')
            external.authenticate(context, auth_info, auth_context)

        # need to aggregate the results in case two or more methods
        # are specified
        auth_response = {'methods': []}
        for method_name in auth_info.get_method_names():
            method = get_auth_method(method_name)
            resp = method.authenticate(context,
                                       auth_info.get_method_data(method_name),
                                       auth_context)
            if resp:
                auth_response['methods'].append(method_name)
                auth_response[method_name] = resp

        if len(auth_response["methods"]) > 0:
            # authentication continuation required
            raise exception.AdditionalAuthRequired(auth_response)

        if 'user_id' not in auth_context:
            msg = _('User not found')
            raise exception.Unauthorized(msg)

    @controller.protected
    def check_token(self, context):
        token_id = context.get('subject_token_id')
        self.token_provider_api.check_token(token_id)

    @controller.protected
    def revoke_token(self, context):
        token_id = context.get('subject_token_id')
        return self.token_provider_api.revoke_token(token_id)

    @controller.protected
    def validate_token(self, context):
        token_id = context.get('subject_token_id')
        token_data = self.token_provider_api.validate_token(token_id)
        return render_token_data_response(token_id, token_data)

    @controller.protected
    def revocation_list(self, context, auth=None):
        return self.token_controllers_ref.revocation_list(context, auth)


#FIXME(gyee): not sure if it belongs here or keystone.common. Park it here
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
