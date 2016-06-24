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

from oslo_log import log
from oslo_serialization import jsonutils

from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _LW


CONF = keystone.conf.CONF
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

    def __init__(self, application):
        super(AdminTokenAuthMiddleware, self).__init__(application)
        LOG.warning(_LW("The admin_token_auth middleware presents a security "
                        "risk and should be removed from the "
                        "[pipeline:api_v3], [pipeline:admin_api], and "
                        "[pipeline:public_api] sections of your paste ini "
                        "file."))

    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        context = request.environ.get(CONTEXT_ENV, {})
        context['is_admin'] = CONF.admin_token and (token == CONF.admin_token)
        request.environ[CONTEXT_ENV] = context


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
        """Normalize URLs."""
        # Removes a trailing slash from the given path, if any.
        if (len(request.environ['PATH_INFO']) > 1 and
                request.environ['PATH_INFO'][-1] == '/'):
            request.environ['PATH_INFO'] = request.environ['PATH_INFO'][:-1]
        # Rewrites path to root if no path is given.
        elif not request.environ['PATH_INFO']:
            request.environ['PATH_INFO'] = '/'
