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
from oslo_log import log
from oslo_middleware import sizelimit
from oslo_serialization import jsonutils
import six

from keystone.common import authorization
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _LW
from keystone.models import token_model
from keystone.openstack.common import versionutils

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
            context['subject_token_id'] = (
                request.headers.get(SUBJECT_TOKEN_HEADER))
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
        for k, v in six.iteritems(params_parsed):
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
        for k, v in six.iteritems(params_parsed):
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ[PARAMS_ENV] = params


class XmlBodyMiddleware(wsgi.Middleware):
    """De/serialize XML to/from JSON."""

    def print_warning(self):
        LOG.warning(_LW('XML support has been removed as of the Kilo release '
                        'and should not be referenced or used in deployment. '
                        'Please remove references to XmlBodyMiddleware from '
                        'your configuration. This compatibility stub will be '
                        'removed in the L release'))

    def __init__(self, *args, **kwargs):
        super(XmlBodyMiddleware, self).__init__(*args, **kwargs)
        self.print_warning()


class XmlBodyMiddlewareV2(XmlBodyMiddleware):
    """De/serialize XML to/from JSON for v2.0 API."""

    def __init__(self, *args, **kwargs):
        pass


class XmlBodyMiddlewareV3(XmlBodyMiddleware):
    """De/serialize XML to/from JSON for v3 API."""

    def __init__(self, *args, **kwargs):
        pass


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

    def process_request(self, request):
        if AUTH_TOKEN_HEADER not in request.headers:
            LOG.debug(('Auth token not in the request header. '
                       'Will not build auth context.'))
            return

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = _LW('Auth context already exists in the request environment')
            LOG.warning(msg)
            return

        auth_context = self._build_auth_context(request)
        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context
