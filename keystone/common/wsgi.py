# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2010 OpenStack Foundation
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

"""Utility methods for working with WSGI servers."""

import functools
import itertools
import re
import wsgiref.util

import oslo_i18n
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import strutils
import routes.middleware
import six
from six.moves import http_client
import webob.dec
import webob.exc

from keystone.common import authorization
from keystone.common import json_home
from keystone.common import request as request_mod
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

# Environment variable used to pass the request context
CONTEXT_ENV = 'openstack.context'

# Environment variable used to pass the request params
PARAMS_ENV = 'openstack.params'

JSON_ENCODE_CONTENT_TYPES = set(['application/json',
                                 'application/json-home'])


def best_match_language(req):
    """Determine the best available locale.

    This returns best available locale based on the Accept-Language HTTP
    header passed in the request.
    """
    if not req.accept_language:
        return None
    return req.accept_language.best_match(
        oslo_i18n.get_available_languages('keystone'))


class BaseApplication(object):
    """Base WSGI application wrapper. Subclasses need to implement __call__."""

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for loading in middleware (holdover from paste.deploy)."""
        return cls(**local_config)

    def __call__(self, environ, start_response):
        r"""Provide subclasses on how to implement __call__.

        Probably like this:

        @webob.dec.wsgify()
        def __call__(self, req):
          # Any of the following objects work as responses:

          # Option 1: simple string
          res = 'message\n'

          # Option 2: a nicely formatted HTTP exception page
          res = exc.HTTPForbidden(explanation='Nice try')

          # Option 3: a webob Response object (in case you need to play with
          # headers, or you want to be treated like an iterable, or or or)
          res = Response();
          res.app_iter = open('somefile')

          # Option 4: any wsgi app to be run next
          res = self.application

          # Option 5: you can get a Response object for a wsgi app, too, to
          # play with headers etc
          res = req.get_response(self.application)

          # You can then just return your response...
          return res
          # ... or set req.response and return None.
          req.response = res

        See the end of http://pythonpaste.org/webob/modules/dec.html
        for more info.

        NOTE: this is now strictly used in conversion from old wsgi
        implementation to flask. Once the flask implementation is complete,
        the __call__ will not be needed as the flask app will handle
        dispatching and __call__.

        """
        raise NotImplementedError('You must implement __call__')


class Application(BaseApplication):

    @webob.dec.wsgify(RequestClass=request_mod.Request)
    def __call__(self, req):
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict.pop('action')
        del arg_dict['controller']

        params = req.environ.get(PARAMS_ENV, {})
        params.update(arg_dict)

        # TODO(termie): do some basic normalization on methods
        method = getattr(self, action)

        # NOTE(morganfainberg): use the request method to normalize the
        # response code between GET and HEAD requests. The HTTP status should
        # be the same.
        LOG.info('%(req_method)s %(uri)s', {
            'req_method': req.method.upper(),
            'uri': wsgiref.util.request_uri(req.environ),
        })

        params = self._normalize_dict(params)

        try:
            result = method(req, **params)
        except exception.Unauthorized as e:
            LOG.warning(
                "Authorization failed. %(exception)s from "
                "%(remote_addr)s",
                {'exception': e, 'remote_addr': req.environ['REMOTE_ADDR']})
            return render_exception(e,
                                    context=req.context_dict,
                                    user_locale=best_match_language(req))
        except exception.Error as e:
            if isinstance(e, exception.UnexpectedError):
                LOG.exception(six.text_type(e))
            else:
                LOG.warning(six.text_type(e))
            return render_exception(e,
                                    context=req.context_dict,
                                    user_locale=best_match_language(req))
        except TypeError as e:
            LOG.exception(six.text_type(e))
            return render_exception(exception.ValidationError(e),
                                    context=req.context_dict,
                                    user_locale=best_match_language(req))
        except Exception as e:
            LOG.exception(six.text_type(e))
            return render_exception(exception.UnexpectedError(exception=e),
                                    context=req.context_dict,
                                    user_locale=best_match_language(req))

        if result is None:
            return render_response(
                status=(http_client.NO_CONTENT,
                        http_client.responses[http_client.NO_CONTENT]))
        elif isinstance(result, six.string_types):
            return result
        elif isinstance(result, webob.Response):
            return result
        elif isinstance(result, webob.exc.WSGIHTTPException):
            return result

        response_code = self._get_response_code(req)
        return render_response(body=result,
                               status=response_code,
                               method=req.method)

    def _get_response_code(self, req):
        req_method = req.environ['REQUEST_METHOD']
        controller = importutils.import_class('keystone.common.controller')
        code = None
        if isinstance(self, controller.V3Controller) and req_method == 'POST':
            code = (http_client.CREATED,
                    http_client.responses[http_client.CREATED])
        return code

    def _normalize_arg(self, arg):
        return arg.replace(':', '_').replace('-', '_')

    def _normalize_dict(self, d):
        return {self._normalize_arg(k): v for (k, v) in d.items()}

    def assert_admin(self, request):
        """Ensure the user is an admin.

        :raises keystone.exception.Unauthorized: if a token could not be
            found/authorized, a user is invalid, or a tenant is
            invalid/not scoped.
        :raises keystone.exception.Forbidden: if the user is not an admin and
            does not have the admin role

        """
        authorization.assert_admin(self, request)

    def _attribute_is_empty(self, ref, attribute):
        """Determine if the attribute in ref is empty or None."""
        return ref.get(attribute) is None or ref.get(attribute) == ''

    def _require_attribute(self, ref, attribute):
        """Ensure the reference contains the specified attribute.

        Raise a ValidationError if the given attribute is not present
        """
        if self._attribute_is_empty(ref, attribute):
            msg = _('%s field is required and cannot be empty') % attribute
            raise exception.ValidationError(message=msg)

    def _require_attributes(self, ref, attrs):
        """Ensure the reference contains the specified attributes.

        Raise a ValidationError if any of the given attributes is not present
        """
        missing_attrs = [attribute for attribute in attrs
                         if self._attribute_is_empty(ref, attribute)]

        if missing_attrs:
            msg = _('%s field(s) cannot be empty') % ', '.join(missing_attrs)
            raise exception.ValidationError(message=msg)

    @classmethod
    def base_url(cls, context, endpoint_type=None):
        url = CONF['public_endpoint']

        if url:
            substitutions = dict(
                itertools.chain(CONF.items(), CONF.eventlet_server.items()))

            url = url % substitutions
        elif 'environment' in context:
            url = wsgiref.util.application_uri(context['environment'])
            # remove version from the URL as it may be part of SCRIPT_NAME but
            # it should not be part of base URL
            url = re.sub(r'/v(3|(2\.0))/*$', '', url)

            # now remove the standard port
            url = utils.remove_standard_port(url)
        else:
            # if we don't have enough information to come up with a base URL,
            # then fall back to localhost. This should never happen in
            # production environment.
            url = 'http://localhost:%d' % CONF.eventlet_server.public_port

        return url.rstrip('/')


def middleware_exceptions(method):

    @functools.wraps(method)
    def _inner(self, request):
        try:
            return method(self, request)
        except exception.Error as e:
            LOG.warning(six.text_type(e))
            return render_exception(e, request=request,
                                    user_locale=best_match_language(request))
        except TypeError as e:
            LOG.exception(six.text_type(e))
            return render_exception(exception.ValidationError(e),
                                    request=request,
                                    user_locale=best_match_language(request))
        except Exception as e:
            LOG.exception(six.text_type(e))
            return render_exception(exception.UnexpectedError(exception=e),
                                    request=request,
                                    user_locale=best_match_language(request))

    return _inner


class Middleware(Application):
    """Base WSGI middleware.

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.

    """

    @classmethod
    def factory(cls, global_config):
        """Used for paste app factories in paste.deploy config files."""
        def _factory(app):
            return cls(app)
        return _factory

    def __init__(self, application, conf=None):
        super(Middleware, self).__init__()
        self.application = application

    def process_request(self, request):
        """Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.

        """
        return None

    def process_response(self, request, response):
        """Do whatever you'd like to the response, based on the request."""
        return response

    @webob.dec.wsgify(RequestClass=request_mod.Request)
    @middleware_exceptions
    def __call__(self, request):
        response = self.process_request(request)
        if response:
            return response
        response = request.get_response(self.application)
        return self.process_response(request, response)


class Debug(Middleware):
    """Helper class for debugging a WSGI application.

    Can be inserted into any WSGI application chain to get information
    about the request and response.

    """

    @webob.dec.wsgify(RequestClass=request_mod.Request)
    def __call__(self, req):
        if not hasattr(LOG, 'isEnabledFor') or LOG.isEnabledFor(LOG.debug):
            LOG.debug('%s %s %s', ('*' * 20), 'REQUEST ENVIRON', ('*' * 20))
            for key, value in req.environ.items():
                LOG.debug('%s = %s', key,
                          strutils.mask_password(value))
            LOG.debug('')
            LOG.debug('%s %s %s', ('*' * 20), 'REQUEST BODY', ('*' * 20))
            for line in req.body_file:
                LOG.debug('%s', strutils.mask_password(line))
            LOG.debug('')

        resp = req.get_response(self.application)
        if not hasattr(LOG, 'isEnabledFor') or LOG.isEnabledFor(LOG.debug):
            LOG.debug('%s %s %s', ('*' * 20), 'RESPONSE HEADERS', ('*' * 20))
            for (key, value) in resp.headers.items():
                LOG.debug('%s = %s', key, value)
            LOG.debug('')

        resp.app_iter = self.print_generator(resp.app_iter)

        return resp

    @staticmethod
    def print_generator(app_iter):
        """Iterator that prints the contents of a wrapper string."""
        LOG.debug('%s %s %s', ('*' * 20), 'RESPONSE BODY', ('*' * 20))
        for part in app_iter:
            LOG.debug(part)
            yield part


class Router(object):
    """WSGI middleware that maps incoming requests to WSGI apps."""

    def __init__(self, mapper):
        """Create a router for the given routes.Mapper.

        Each route in `mapper` must specify a 'controller', which is a
        WSGI app to call.  You'll probably want to specify an 'action' as
        well and have your controller be an object that can route
        the request to the action-specific method.

        Examples:
          mapper = routes.Mapper()
          sc = ServerController()

          # Explicit mapping of one route to a controller+action
          mapper.connect(None, '/svrlist', controller=sc, action='list')

          # Actions are all implicitly defined
          mapper.resource('server', 'servers', controller=sc)

          # Pointing to an arbitrary WSGI app.  You can specify the
          # {path_info:.*} parameter so the target app can be handed just that
          # section of the URL.
          mapper.connect(None, '/v1.0/{path_info:.*}', controller=BlogApp())

        """
        self.map = mapper
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          self.map)

    @webob.dec.wsgify(RequestClass=request_mod.Request)
    def __call__(self, req):
        """Route the incoming request to a controller based on self.map.

        If no match, return a 404.

        """
        return self._router

    @staticmethod
    @webob.dec.wsgify(RequestClass=request_mod.Request)
    def _dispatch(req):
        """Dispatch the request to the appropriate controller.

        Called by self._router after matching the incoming request to a route
        and putting the information into req.environ.  Either returns 404
        or the routed WSGI app's response.

        """
        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            msg = (_('(%(url)s): The resource could not be found.') %
                   {'url': req.url})
            return render_exception(exception.NotFound(msg),
                                    request=req,
                                    user_locale=best_match_language(req))
        app = match['controller']
        return app


class ComposingRouter(Router):
    def __init__(self, mapper=None, routers=None):
        if mapper is None:
            mapper = routes.Mapper()
        if routers is None:
            routers = []
        for router in routers:
            router.add_routes(mapper)
        super(ComposingRouter, self).__init__(mapper)


class ComposableRouter(Router):
    """Router that supports use by ComposingRouter."""

    def __init__(self, mapper=None):
        if mapper is None:
            mapper = routes.Mapper()
        self.add_routes(mapper)
        super(ComposableRouter, self).__init__(mapper)

    def add_routes(self, mapper):
        """Add routes to given mapper."""
        pass


class ExtensionRouter(Router):
    """A router that allows extensions to supplement or overwrite routes.

    Expects to be subclassed.
    """

    def __init__(self, application, mapper=None):
        if mapper is None:
            mapper = routes.Mapper()
        self.application = application
        self.add_routes(mapper)
        mapper.connect('/{path_info:.*}', controller=self.application)
        super(ExtensionRouter, self).__init__(mapper)

    def add_routes(self, mapper):
        pass

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for loading in middleware (holdover from paste.deploy)."""
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory


class RoutersBase(object):
    """Base class for Routers."""

    def __init__(self):
        self.v3_resources = []

    def append_v3_routers(self, mapper, routers):
        """Append v3 routers.

        Subclasses should override this method to map its routes.

        Use self._add_resource() to map routes for a resource.
        """

    def _add_resource(self, mapper, controller, path, rel,
                      get_action=None, head_action=None, get_head_action=None,
                      put_action=None, post_action=None, patch_action=None,
                      delete_action=None, get_post_action=None,
                      path_vars=None, status=json_home.Status.STABLE,
                      new_path=None):
        if get_head_action:
            getattr(controller, get_head_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=get_head_action,
                           conditions=dict(method=['GET', 'HEAD']))
        if get_action:
            getattr(controller, get_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=get_action,
                           conditions=dict(method=['GET']))
        if head_action:
            getattr(controller, head_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=head_action,
                           conditions=dict(method=['HEAD']))
        if put_action:
            getattr(controller, put_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=put_action,
                           conditions=dict(method=['PUT']))
        if post_action:
            getattr(controller, post_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=post_action,
                           conditions=dict(method=['POST']))
        if patch_action:
            getattr(controller, patch_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=patch_action,
                           conditions=dict(method=['PATCH']))
        if delete_action:
            getattr(controller, delete_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=delete_action,
                           conditions=dict(method=['DELETE']))
        if get_post_action:
            getattr(controller, get_post_action)  # ensure the attribute exists
            mapper.connect(path, controller=controller, action=get_post_action,
                           conditions=dict(method=['GET', 'POST']))

        resource_data = dict()

        if path_vars:
            resource_data['href-template'] = new_path or path
            resource_data['href-vars'] = path_vars
        else:
            resource_data['href'] = new_path or path

        json_home.Status.update_resource_data(resource_data, status)

        self.v3_resources.append((rel, resource_data))
        json_home.JsonHomeResources.append_resource(rel, resource_data)


class V3ExtensionRouter(ExtensionRouter, RoutersBase):
    """Base class for V3 extension router."""

    def __init__(self, application, mapper=None):
        self.v3_resources = list()
        super(V3ExtensionRouter, self).__init__(application, mapper)

    def _update_version_response(self, response_data):
        response_data['resources'].update(self.v3_resources)

    @webob.dec.wsgify(RequestClass=request_mod.Request)
    def __call__(self, request):
        if request.path_info != '/':
            # Not a request for version info so forward to super.
            return super(V3ExtensionRouter, self).__call__(request)

        response = request.get_response(self.application)

        if response.status_code != http_client.OK:
            # The request failed, so don't update the response.
            return response

        if response.headers['Content-Type'] != 'application/json-home':
            # Not a request for JSON Home document, so don't update the
            # response.
            return response

        response_data = jsonutils.loads(response.body)
        self._update_version_response(response_data)
        response.body = jsonutils.dump_as_bytes(response_data,
                                                cls=utils.SmarterEncoder)
        return response


def render_response(body=None, status=None, headers=None, method=None):
    """Form a WSGI response."""
    if headers is None:
        headers = []
    else:
        headers = list(headers)
    headers.append(('Vary', 'X-Auth-Token'))

    if body is None:
        body = b''
        status = status or (http_client.NO_CONTENT,
                            http_client.responses[http_client.NO_CONTENT])
    else:
        content_types = [v for h, v in headers if h == 'Content-Type']
        if content_types:
            content_type = content_types[0]
        else:
            content_type = None

        if content_type is None or content_type in JSON_ENCODE_CONTENT_TYPES:
            body = jsonutils.dump_as_bytes(body, cls=utils.SmarterEncoder)
            if content_type is None:
                headers.append(('Content-Type', 'application/json'))
        status = status or (http_client.OK,
                            http_client.responses[http_client.OK])

    # NOTE(davechen): `mod_wsgi` follows the standards from pep-3333 and
    # requires the value in response header to be binary type(str) on python2,
    # unicode based string(str) on python3, or else keystone will not work
    # under apache with `mod_wsgi`.
    # keystone needs to check the data type of each header and convert the
    # type if needed.
    # see bug:
    # https://bugs.launchpad.net/keystone/+bug/1528981
    # see pep-3333:
    # https://www.python.org/dev/peps/pep-3333/#a-note-on-string-types
    # see source from mod_wsgi:
    # https://github.com/GrahamDumpleton/mod_wsgi(methods:
    # wsgi_convert_headers_to_bytes(...), wsgi_convert_string_to_bytes(...)
    # and wsgi_validate_header_value(...)).
    def _convert_to_str(headers):
        str_headers = []
        for header in headers:
            str_header = []
            for value in header:
                if not isinstance(value, str):
                    str_header.append(str(value))
                else:
                    str_header.append(value)
            # convert the list to the immutable tuple to build the headers.
            # header's key/value will be guaranteed to be str type.
            str_headers.append(tuple(str_header))
        return str_headers

    headers = _convert_to_str(headers)

    resp = webob.Response(body=body,
                          status='%d %s' % status,
                          headerlist=headers,
                          charset='utf-8')

    if method and method.upper() == 'HEAD':
        # NOTE(morganfainberg): HEAD requests should return the same status
        # as a GET request and same headers (including content-type and
        # content-length). The webob.Response object automatically changes
        # content-length (and other headers) if the body is set to b''. Capture
        # all headers and reset them on the response object after clearing the
        # body. The body can only be set to a binary-type (not TextType or
        # NoneType), so b'' is used here and should be compatible with
        # both py2x and py3x.
        stored_headers = resp.headers.copy()
        resp.body = b''
        for header, value in stored_headers.items():
            resp.headers[header] = value

    return resp


def render_exception(error, context=None, request=None, user_locale=None):
    """Form a WSGI response based on the current error."""
    error_message = error.args[0]
    message = oslo_i18n.translate(error_message, desired_locale=user_locale)
    if message is error_message:
        # translate() didn't do anything because it wasn't a Message,
        # convert to a string.
        message = six.text_type(message)

    body = {'error': {
        'code': error.code,
        'title': error.title,
        'message': message,
    }}
    headers = []
    if isinstance(error, exception.AuthPluginException):
        body['error']['identity'] = error.authentication
    elif isinstance(error, exception.Unauthorized):
        # NOTE(gyee): we only care about the request environment in the
        # context. Also, its OK to pass the environment as it is read-only in
        # Application.base_url()
        local_context = {}
        if request:
            local_context = {'environment': request.environ}
        elif context and 'environment' in context:
            local_context = {'environment': context['environment']}
        url = Application.base_url(local_context)

        headers.append(('WWW-Authenticate', 'Keystone uri="%s"' % url))
    return render_response(status=(error.code, error.title),
                           body=body,
                           headers=headers)
