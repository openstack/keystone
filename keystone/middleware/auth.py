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

from oslo_config import cfg
from oslo_context import context as oslo_context
from oslo_log import log
from oslo_log import versionutils

from keystone.common import authorization
from keystone.common import tokenless_auth
from keystone.common import wsgi
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils
from keystone.i18n import _, _LI, _LW
from keystone.middleware import core
from keystone.models import token_model
from keystone.token.providers import common

CONF = cfg.CONF
LOG = log.getLogger(__name__)

__all__ = ('AuthContextMiddleware',)


class AuthContextMiddleware(wsgi.Middleware):
    """Build the authentication context from the request auth token."""

    def _build_auth_context(self, request):

        # NOTE(gyee): token takes precedence over SSL client certificates.
        # This will preserve backward compatibility with the existing
        # behavior. Tokenless authorization with X.509 SSL client
        # certificate is effectively disabled if no trusted issuers are
        # provided.

        token_id = None
        if core.AUTH_TOKEN_HEADER in request.headers:
            token_id = request.headers[core.AUTH_TOKEN_HEADER].strip()

        is_admin = request.environ.get(core.CONTEXT_ENV, {}).get('is_admin',
                                                                 False)
        if is_admin:
            # NOTE(gyee): no need to proceed any further as we already know
            # this is an admin request.
            auth_context = {}
            return auth_context, token_id, is_admin

        if token_id:
            # In this case the client sent in a token.
            auth_context, is_admin = self._build_token_auth_context(
                request, token_id)
            return auth_context, token_id, is_admin

        # No token, maybe the client presented an X.509 certificate.

        if self._validate_trusted_issuer(request.environ):
            auth_context = self._build_tokenless_auth_context(
                request.environ)
            return auth_context, None, False

        LOG.debug('There is either no auth token in the request or '
                  'the certificate issuer is not trusted. No auth '
                  'context will be set.')

        return None, None, False

    def _build_token_auth_context(self, request, token_id):
        if CONF.admin_token and token_id == CONF.admin_token:
            versionutils.report_deprecated_feature(
                LOG,
                _LW('build_auth_context middleware checking for the admin '
                    'token is deprecated as of the Mitaka release and will be '
                    'removed in the O release. If your deployment requires '
                    'use of the admin token, update keystone-paste.ini so '
                    'that admin_token_auth is before build_auth_context in '
                    'the paste pipelines, otherwise remove the '
                    'admin_token_auth middleware from the paste pipelines.'))
            return {}, True

        context = {'token_id': token_id}
        context['environment'] = request.environ

        try:
            token_ref = token_model.KeystoneToken(
                token_id=token_id,
                token_data=self.token_provider_api.validate_token(token_id))
            # TODO(gyee): validate_token_bind should really be its own
            # middleware
            wsgi.validate_token_bind(context, token_ref)
            return authorization.token_to_auth_context(token_ref), False
        except exception.TokenNotFound:
            LOG.warning(_LW('RBAC: Invalid token'))
            raise exception.Unauthorized()

    def _build_tokenless_auth_context(self, env):
        """Build the authentication context.

        The context is built from the attributes provided in the env,
        such as certificate and scope attributes.
        """
        tokenless_helper = tokenless_auth.TokenlessAuthHelper(env)

        (domain_id, project_id, trust_ref, unscoped) = (
            tokenless_helper.get_scope())
        user_ref = tokenless_helper.get_mapped_user(
            project_id,
            domain_id)

        # NOTE(gyee): if it is an ephemeral user, the
        # given X.509 SSL client cert does not need to map to
        # an existing user.
        if user_ref['type'] == utils.UserType.EPHEMERAL:
            auth_context = {}
            auth_context['group_ids'] = user_ref['group_ids']
            auth_context[federation_constants.IDENTITY_PROVIDER] = (
                user_ref[federation_constants.IDENTITY_PROVIDER])
            auth_context[federation_constants.PROTOCOL] = (
                user_ref[federation_constants.PROTOCOL])
            if domain_id and project_id:
                msg = _('Scoping to both domain and project is not allowed')
                raise ValueError(msg)
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = user_ref['roles']
        else:
            # it's the local user, so token data is needed.
            token_helper = common.V3TokenDataHelper()
            token_data = token_helper.get_token_data(
                user_id=user_ref['id'],
                method_names=[CONF.tokenless_auth.protocol],
                domain_id=domain_id,
                project_id=project_id)

            auth_context = {'user_id': user_ref['id']}
            auth_context['is_delegated_auth'] = False
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = [role['name'] for role
                                     in token_data['token']['roles']]
        return auth_context

    def _validate_trusted_issuer(self, env):
        """To further filter the certificates that are trusted.

        If the config option 'trusted_issuer' is absent or does
        not contain the trusted issuer DN, no certificates
        will be allowed in tokenless authorization.

        :param env: The env contains the client issuer's attributes
        :type env: dict
        :returns: True if client_issuer is trusted; otherwise False
        """
        if not CONF.tokenless_auth.trusted_issuer:
            return False

        client_issuer = env.get(CONF.tokenless_auth.issuer_attribute)
        if not client_issuer:
            msg = _LI('Cannot find client issuer in env by the '
                      'issuer attribute - %s.')
            LOG.info(msg, CONF.tokenless_auth.issuer_attribute)
            return False

        if client_issuer in CONF.tokenless_auth.trusted_issuer:
            return True

        msg = _LI('The client issuer %(client_issuer)s does not match with '
                  'the trusted issuer %(trusted_issuer)s')
        LOG.info(
            msg, {'client_issuer': client_issuer,
                  'trusted_issuer': CONF.tokenless_auth.trusted_issuer})

        return False

    def process_request(self, request):

        # The request context stores itself in thread-local memory for logging.
        request_context = oslo_context.RequestContext(
            request_id=request.environ.get('openstack.request_id'))

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = _LW('Auth context already exists in the request '
                      'environment; it will be used for authorization '
                      'instead of creating a new one.')
            LOG.warning(msg)
            return

        auth_context, token_id, is_admin = self._build_auth_context(request)

        request_context.auth_token = token_id
        request_context.is_admin = is_admin

        if auth_context is None:
            # The client didn't send any auth info, so don't set auth context.
            return

        # The attributes of request_context are put into the logs. This is a
        # common pattern for all the OpenStack services. In all the other
        # projects these are IDs, so set the attributes to IDs here rather than
        # the name.
        request_context.user = auth_context.get('user_id')
        request_context.tenant = auth_context.get('project_id')
        request_context.domain = auth_context.get('domain_id')
        request_context.user_domain = auth_context.get('user_domain_id')
        request_context.project_domain = auth_context.get('project_domain_id')
        request_context.update_store()

        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context
