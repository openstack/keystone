# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import webob.dec

from keystone.common import config
from keystone.common import serializer
from keystone.common import utils
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


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
        for k, v in params_parsed.iteritems():
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

    In this case we accept it as urlencoded data under the key 'json' as in
    json=<urlencoded_json> but this could be extended to accept raw JSON
    in the POST body.

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
            return wsgi.render_exception(e)

        params_parsed = {}
        try:
            params_parsed = jsonutils.loads(params_json)
        except ValueError:
            e = exception.ValidationError(attribute='valid JSON',
                                          target='request body')
            return wsgi.render_exception(e)
        finally:
            if not params_parsed:
                params_parsed = {}

        params = {}
        for k, v in params_parsed.iteritems():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ[PARAMS_ENV] = params


class XmlBodyMiddleware(wsgi.Middleware):
    """De/serializes XML to/from JSON."""

    def process_request(self, request):
        """Transform the request from XML to JSON."""
        incoming_xml = 'application/xml' in str(request.content_type)
        if incoming_xml and request.body:
            request.content_type = 'application/json'
            try:
                request.body = jsonutils.dumps(
                    serializer.from_xml(request.body))
            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid XML',
                                              target='request body')
                return wsgi.render_exception(e)

    def process_response(self, request, response):
        """Transform the response from JSON to XML."""
        outgoing_xml = 'application/xml' in str(request.accept)
        if outgoing_xml and response.body:
            response.content_type = 'application/xml'
            try:
                body_obj = jsonutils.loads(response.body)
                response.body = serializer.to_xml(body_obj)
            except Exception:
                LOG.exception('Serializer failed')
                raise exception.Error(message=response.body)
        return response


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


class RequestBodySizeLimiter(wsgi.Middleware):
    """Limit the size of an incoming request."""

    def __init__(self, *args, **kwargs):
        super(RequestBodySizeLimiter, self).__init__(*args, **kwargs)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):

        if req.content_length > CONF.max_request_body_size:
            raise exception.RequestTooLarge()
        if req.content_length is None and req.is_body_readable:
            limiter = utils.LimitingReader(req.body_file,
                                           CONF.max_request_body_size)
            req.body_file = limiter
        return self.application
