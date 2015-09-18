# Copyright 2012 OpenStack Foundation
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

from oslo_config import cfg
from oslo_context import context as oslo_context
from oslo_log import log
from oslo_log import versionutils
from oslo_middleware import sizelimit
from oslo_serialization import jsonutils

from keystone.common import authorization
from keystone.common import tokenless_auth
from keystone.common import wsgi
from keystone.contrib.federation import constants as federation_constants
from keystone.contrib.federation import utils
from keystone import exception
from keystone.i18n import _, _LI, _LW
from keystone.models import token_model
from keystone.token.providers import common


CONF = cfg.CONF
LOG = log.getLogger(__name__)


# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'


# Header used to transmit the subject token
SUBJECT_TOKEN_HEADER = 'X-Subject-Token'


# Environment variable used to pass the request context
CONTEXT_ENV = wsgi.CONTEXT_ENV


# Environment variable used to pass the request params
PARAMS_ENV = wsgi.PARAMS_ENV


class TokenAuthMiddleware(wsgi.Middleware):
    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        context = request.environ.get(CONTEXT_ENV, {})
        context['token_id'] = token
        if SUBJECT_TOKEN_HEADER in request.headers:
            context['subject_token_id'] = request.headers[SUBJECT_TOKEN_HEADER]
        request.environ[CONTEXT_ENV] = context


class AdminTokenAuthMiddleware(wsgi.Middleware):
    """A trivial filter that checks for a pre-defined admin token.

    Sets 'is_admin' to true in the context, expected to be checked by
    methods that are admin-only.

    """

    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        context = request.environ.get(CONTEXT_ENV, {})
        context['is_admin'] = (token == CONF.admin_token)
        request.environ[CONTEXT_ENV] = context


class PostParamsMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as POST parameters.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """

    def process_request(self, request):
        params_parsed = request.params
        params = {}
        for k, v in params_parsed.items():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ[PARAMS_ENV] = params


class JsonBodyMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as serialized JSON.

    Accepting arguments as JSON is useful for accepting data that may be more
    complex than simple primitives.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """
    def process_request(self, request):
        # Abort early if we don't have any work to do
        params_json = request.body
        if not params_json:
            return

        # Reject unrecognized content types. Empty string indicates
        # the client did not explicitly set the header
        if request.content_type not in ('application/json', ''):
            e = exception.ValidationError(attribute='application/json',
                                          target='Content-Type header')
            return wsgi.render_exception(e, request=request)

        params_parsed = {}
        try:
            params_parsed = jsonutils.loads(params_json)
        except ValueError:
            e = exception.ValidationError(attribute='valid JSON',
                                          target='request body')
            return wsgi.render_exception(e, request=request)
        finally:
            if not params_parsed:
                params_parsed = {}

        if not isinstance(params_parsed, dict):
            e = exception.ValidationError(attribute='valid JSON object',
                                          target='request body')
            return wsgi.render_exception(e, request=request)

        params = {}
        for k, v in params_parsed.items():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ[PARAMS_ENV] = params


class NormalizingFilter(wsgi.Middleware):
    """Middleware filter to handle URL normalization."""

    def process_request(self, request):
        """Normalizes URLs."""
        # Removes a trailing slash from the given path, if any.
        if (len(request.environ['PATH_INFO']) > 1 and
                request.environ['PATH_INFO'][-1] == '/'):
            request.environ['PATH_INFO'] = request.environ['PATH_INFO'][:-1]
        # Rewrites path to root if no path is given.
        elif not request.environ['PATH_INFO']:
            request.environ['PATH_INFO'] = '/'


class RequestBodySizeLimiter(sizelimit.RequestBodySizeLimiter):
    @versionutils.deprecated(
        versionutils.deprecated.KILO,
        in_favor_of='oslo_middleware.sizelimit.RequestBodySizeLimiter',
        remove_in=+1,
        what='keystone.middleware.RequestBodySizeLimiter')
    def __init__(self, *args, **kwargs):
        super(RequestBodySizeLimiter, self).__init__(*args, **kwargs)


class AuthContextMiddleware(wsgi.Middleware):
    """Build the authentication context from the request auth token."""

    def _build_auth_context(self, request):
        token_id = request.headers.get(AUTH_TOKEN_HEADER).strip()

        if token_id == CONF.admin_token:
            # NOTE(gyee): no need to proceed any further as the special admin
            # token is being handled by AdminTokenAuthMiddleware. This code
            # will not be impacted even if AdminTokenAuthMiddleware is removed
            # from the pipeline as "is_admin" is default to "False". This code
            # is independent of AdminTokenAuthMiddleware.
            return {}

        context = {'token_id': token_id}
        context['environment'] = request.environ

        try:
            token_ref = token_model.KeystoneToken(
                token_id=token_id,
                token_data=self.token_provider_api.validate_token(token_id))
            # TODO(gyee): validate_token_bind should really be its own
            # middleware
            wsgi.validate_token_bind(context, token_ref)
            return authorization.token_to_auth_context(token_ref)
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
        oslo_context.RequestContext(
            request_id=request.environ.get('openstack.request_id'))

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = _LW('Auth context already exists in the request '
                      'environment; it will be used for authorization '
                      'instead of creating a new one.')
            LOG.warning(msg)
            return

        # NOTE(gyee): token takes precedence over SSL client certificates.
        # This will preserve backward compatibility with the existing
        # behavior. Tokenless authorization with X.509 SSL client
        # certificate is effectively disabled if no trusted issuers are
        # provided.
        if AUTH_TOKEN_HEADER in request.headers:
            auth_context = self._build_auth_context(request)
        elif self._validate_trusted_issuer(request.environ):
            auth_context = self._build_tokenless_auth_context(
                request.environ)
        else:
            LOG.debug('There is either no auth token in the request or '
                      'the certificate issuer is not trusted. No auth '
                      'context will be set.')
            return
        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context
