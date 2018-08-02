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

from keystonemiddleware import auth_token
from oslo_log import log

from keystone.common import authorization
from keystone.common import context
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import tokenless_auth
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils
from keystone.i18n import _
from keystone.models import token_model

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

__all__ = ('AuthContextMiddleware',)


class AuthContextMiddleware(provider_api.ProviderAPIMixin,
                            auth_token.BaseAuthProtocol):
    """Build the authentication context from the request auth token."""

    kwargs_to_fetch_token = True

    def __init__(self, app):
        super(AuthContextMiddleware, self).__init__(app, log=LOG)

    def fetch_token(self, token, **kwargs):
        try:
            token_model = self.token_provider_api.validate_token(token)
            return controller.render_token_response_from_model(token_model)
        except exception.TokenNotFound:
            raise auth_token.InvalidToken(_('Could not find token'))

    def _build_tokenless_auth_context(self, request):
        """Build the authentication context.

        The context is built from the attributes provided in the env,
        such as certificate and scope attributes.
        """
        tokenless_helper = tokenless_auth.TokenlessAuthHelper(request.environ)

        (domain_id, project_id, trust_ref, unscoped, system) = (
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
            token = token_model.TokenModel()
            token.user_id = user_ref['id']
            token.methods = [CONF.tokenless_auth.protocol]
            token.domain_id = domain_id
            token.project_id = project_id

            auth_context = {'user_id': user_ref['id']}
            auth_context['is_delegated_auth'] = False
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = [role['name'] for role in token.roles]
        return auth_context

    def _validate_trusted_issuer(self, request):
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

        issuer = request.environ.get(CONF.tokenless_auth.issuer_attribute)
        if not issuer:
            msg = ('Cannot find client issuer in env by the '
                   'issuer attribute - %s.')
            LOG.info(msg, CONF.tokenless_auth.issuer_attribute)
            return False

        if issuer in CONF.tokenless_auth.trusted_issuer:
            return True

        msg = ('The client issuer %(client_issuer)s does not match with '
               'the trusted issuer %(trusted_issuer)s')
        LOG.info(
            msg, {'client_issuer': issuer,
                  'trusted_issuer': CONF.tokenless_auth.trusted_issuer})

        return False

    @wsgi.middleware_exceptions
    def process_request(self, request):
        context_env = request.environ.get(wsgi.CONTEXT_ENV, {})

        # NOTE(notmorgan): This code is merged over from the admin token
        # middleware and now emits the security warning when the
        # conf.admin_token value is set.
        token = request.headers.get(authorization.AUTH_TOKEN_HEADER)
        if CONF.admin_token and (token == CONF.admin_token):
            context_env['is_admin'] = True
            LOG.warning(
                "The use of the '[DEFAULT] admin_token' configuration"
                "option presents a significant security risk and should "
                "not be set. This option is deprecated in favor of using "
                "'keystone-manage bootstrap' and will be removed in a "
                "future release.")
            request.environ[wsgi.CONTEXT_ENV] = context_env

        if not context_env.get('is_admin', False):
            resp = super(AuthContextMiddleware, self).process_request(request)

            if resp:
                return resp
            if request.token_auth.user is not None:
                request.set_user_headers(request.token_auth.user)

        # NOTE(jamielennox): function is split so testing can check errors from
        # fill_context. There is no actual reason for fill_context to raise
        # errors rather than return a resp, simply that this is what happened
        # before refactoring and it was easier to port. This can be fixed up
        # and the middleware_exceptions helper removed.
        self.fill_context(request)

    def _keystone_specific_values(self, token, request_context):
        if token.domain_scoped:
            # Domain scoped tokens should never have is_admin_project set
            # Even if KSA defaults it otherwise.  The two mechanisms are
            # parallel; only ione or the other should be used for access.
            request_context.is_admin_project = False
            request_context.domain_id = token.domain_id
            request_context.domain_name = token.domain['name']
        if token.oauth_scoped:
            request_context.is_delegated_auth = True
            request_context.oauth_consumer_id = (
                token.access_token['consumer_id']
            )
            request_context.oauth_access_token_id = token.access_token_id
        if token.trust_scoped:
            request_context.is_delegated_auth = True
            request_context.trust_id = token.trust_id
        if token.is_federated:
            request_context.group_ids = []
            for group in token.federated_groups:
                request_context.group_ids.append(group['id'])
        else:
            request_context.group_ids = []

    def fill_context(self, request):
        # The request context stores itself in thread-local memory for logging.

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = ('Auth context already exists in the request '
                   'environment; it will be used for authorization '
                   'instead of creating a new one.')
            LOG.warning(msg)
            return

        kwargs = {
            'authenticated': False,
            'overwrite': True}
        request_context = context.RequestContext.from_environ(
            request.environ, **kwargs)
        request.environ[context.REQUEST_CONTEXT_ENV] = request_context

        # NOTE(gyee): token takes precedence over SSL client certificates.
        # This will preserve backward compatibility with the existing
        # behavior. Tokenless authorization with X.509 SSL client
        # certificate is effectively disabled if no trusted issuers are
        # provided.

        if request.environ.get(wsgi.CONTEXT_ENV, {}).get('is_admin', False):
            request_context.is_admin = True
            auth_context = {}

        elif request.token_auth.has_user_token:
            # Keystone enforces policy on some values that other services
            # do not, and should not, use.  This adds them in to the context.
            token = PROVIDERS.token_provider_api.validate_token(
                request.user_token
            )
            self._keystone_specific_values(token, request_context)
            request_context.auth_token = request.user_token
            auth_context = request_context.to_policy_values()
            additional = {
                'trust_id': request_context.trust_id,
                'trustor_id': request_context.trustor_id,
                'trustee_id': request_context.trustee_id,
                'domain_id': request_context._domain_id,
                'domain_name': request_context.domain_name,
                'group_ids': request_context.group_ids,
                'token': token
            }
            auth_context.update(additional)

        elif self._validate_trusted_issuer(request):
            auth_context = self._build_tokenless_auth_context(request)

        else:
            # There is either no auth token in the request or the certificate
            # issuer is not trusted. No auth context will be set. This
            # typically happens on an initial token request.
            return

        # set authenticated to flag to keystone that a token has been validated
        request_context.authenticated = True

        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for loading in middleware (holdover from paste.deploy)."""
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory
