# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2010 OpenStack LLC.
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

import re

import routes.middleware
import webob.dec
import webob.exc

from keystone.common import config
from keystone.common import utils
from keystone import exception
from keystone.openstack.common import gettextutils
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log as logging


CONF = config.CONF
LOG = logging.getLogger(__name__)

# Environment variable used to pass the request context
CONTEXT_ENV = 'openstack.context'


# Environment variable used to pass the request params
PARAMS_ENV = 'openstack.params'


_RE_PASS = re.compile(r'([\'"].*?password[\'"]\s*:\s*u?[\'"]).*?([\'"])',
                      re.DOTALL)


def mask_password(message, is_unicode=False, secret="***"):
    """Replace password with 'secret' in message.

    :param message: The string which include security information.
    :param is_unicode: Is unicode string ?
    :param secret: substitution string default to "***".
    :returns: The string

    For example:
       >>> mask_password('"password" : "aaaaa"')
       '"password" : "***"'
       >>> mask_password("'original_password' : 'aaaaa'")
       "'original_password' : '***'"
       >>> mask_password("u'original_password' :   u'aaaaa'")
       "u'original_password' :   u'***'"
    """
    if is_unicode:
        message = unicode(message)
    # Match the group 1,2 and replace all others with 'secret'
    secret = r"\g<1>" + secret + r"\g<2>"
    result = _RE_PASS.sub(secret, message)
    return result


def validate_token_bind(context, token_ref):
    bind_mode = CONF.token.enforce_token_bind

    if bind_mode == 'disabled':
        return

    bind = token_ref.get('bind', {})

    # permissive and strict modes don't require there to be a bind
    permissive = bind_mode in ('permissive', 'strict')

    # get the named mode if bind_mode is not one of the known
    name = None if permissive or bind_mode == 'required' else bind_mode

    if not bind:
        if permissive:
            # no bind provided and none required
            return
        else:
            LOG.info(_("No bind information present in token"))
            raise exception.Unauthorized()

    if name and name not in bind:
        LOG.info(_("Named bind mode %s not in bind information"), name)
        raise exception.Unauthorized()

    for bind_type, identifier in bind.iteritems():
        if bind_type == 'kerberos':
            if not context.get('AUTH_TYPE', '').lower() == 'negotiate':
                LOG.info(_("Kerberos credentials required and not present"))
                raise exception.Unauthorized()

            if not context.get('REMOTE_USER') == identifier:
                LOG.info(_("Kerberos credentials do not match those in bind"))
                raise exception.Unauthorized()

            LOG.info(_("Kerberos bind authentication successful"))

        elif bind_mode == 'permissive':
            LOG.debug(_("Ignoring unknown bind for permissive mode: "
                        "{%(bind_type)s: %(identifier)s}"),
                      {'bind_type': bind_type, 'identifier': identifier})
        else:
            LOG.info(_("Couldn't verify unknown bind: "
                       "{%(bind_type)s: %(identifier)s}"),
                     {'bind_type': bind_type, 'identifier': identifier})
            raise exception.Unauthorized()


class Request(webob.Request):
    def best_match_language(self):
        """Determines the best available locale from the Accept-Language
        HTTP header passed in the request.
        """

        if not self.accept_language:
            return None
        return self.accept_language.best_match(
            gettextutils.get_available_languages('keystone'))


class BaseApplication(object):
    """Base WSGI application wrapper. Subclasses need to implement __call__."""

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [app:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [app:wadl]
            latest_version = 1.3
            paste.app_factory = keystone.fancy_api:Wadl.factory

        which would result in a call to the `Wadl` class as

            import keystone.fancy_api
            keystone.fancy_api.Wadl(latest_version='1.3')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        return cls(**local_config)

    def __call__(self, environ, start_response):
        r"""Subclasses will probably want to implement __call__ like this:

        @webob.dec.wsgify(RequestClass=Request)
        def __call__(self, req):
          # Any of the following objects work as responses:

          # Option 1: simple string
          res = 'message\n'

          # Option 2: a nicely formatted HTTP exception page
          res = exc.HTTPForbidden(detail='Nice try')

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

        """
        raise NotImplementedError('You must implement __call__')


class Application(BaseApplication):
    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict.pop('action')
        del arg_dict['controller']
        LOG.debug(_('arg_dict: %s'), arg_dict)

        # allow middleware up the stack to provide context, params and headers.
        context = req.environ.get(CONTEXT_ENV, {})
        context['query_string'] = dict(req.params.iteritems())
        context['headers'] = dict(req.headers.iteritems())
        context['path'] = req.environ['PATH_INFO']
        params = req.environ.get(PARAMS_ENV, {})

        for name in ['REMOTE_USER', 'AUTH_TYPE']:
            try:
                context[name] = req.environ[name]
            except KeyError:
                try:
                    del context[name]
                except KeyError:
                    pass

        params.update(arg_dict)

        context.setdefault('is_admin', False)

        # TODO(termie): do some basic normalization on methods
        method = getattr(self, action)

        # NOTE(vish): make sure we have no unicode keys for py2.6.
        params = self._normalize_dict(params)

        try:
            result = method(context, **params)
        except exception.Unauthorized as e:
            LOG.warning(
                _('Authorization failed. %(exception)s from %(remote_addr)s') %
                {'exception': e, 'remote_addr': req.environ['REMOTE_ADDR']})
            return render_exception(e, user_locale=req.best_match_language())
        except exception.Error as e:
            LOG.warning(e)
            return render_exception(e, user_locale=req.best_match_language())
        except TypeError as e:
            LOG.exception(e)
            return render_exception(exception.ValidationError(e),
                                    user_locale=req.best_match_language())
        except Exception as e:
            LOG.exception(e)
            return render_exception(exception.UnexpectedError(exception=e),
                                    user_locale=req.best_match_language())

        if result is None:
            return render_response(status=(204, 'No Content'))
        elif isinstance(result, basestring):
            return result
        elif isinstance(result, webob.Response):
            return result
        elif isinstance(result, webob.exc.WSGIHTTPException):
            return result

        response_code = self._get_response_code(req)
        return render_response(body=result, status=response_code)

    def _get_response_code(self, req):
        req_method = req.environ['REQUEST_METHOD']
        controller = importutils.import_class('keystone.common.controller')
        code = None
        if isinstance(self, controller.V3Controller) and req_method == 'POST':
            code = (201, 'Created')
        return code

    def _normalize_arg(self, arg):
        return str(arg).replace(':', '_').replace('-', '_')

    def _normalize_dict(self, d):
        return dict([(self._normalize_arg(k), v)
                     for (k, v) in d.iteritems()])

    def assert_admin(self, context):
        if not context['is_admin']:
            try:
                user_token_ref = self.token_api.get_token(context['token_id'])
            except exception.TokenNotFound as e:
                raise exception.Unauthorized(e)

            validate_token_bind(context, user_token_ref)
            creds = user_token_ref['metadata'].copy()

            try:
                creds['user_id'] = user_token_ref['user'].get('id')
            except AttributeError:
                LOG.debug('Invalid user')
                raise exception.Unauthorized()

            try:
                creds['tenant_id'] = user_token_ref['tenant'].get('id')
            except AttributeError:
                LOG.debug('Invalid tenant')
                raise exception.Unauthorized()

            # NOTE(vish): this is pretty inefficient
            creds['roles'] = [self.identity_api.get_role(role)['name']
                              for role in creds.get('roles', [])]
            # Accept either is_admin or the admin role
            self.policy_api.enforce(creds, 'admin_required', {})


class Middleware(Application):
    """Base WSGI middleware.

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.

    """

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = keystone.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import keystone.analytics
            keystone.analytics.Analytics(app, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory

    def __init__(self, application):
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

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        try:
            response = self.process_request(request)
            if response:
                return response
            response = request.get_response(self.application)
            return self.process_response(request, response)
        except exception.Error as e:
            LOG.warning(e)
            return render_exception(e,
                                    user_locale=request.best_match_language())
        except TypeError as e:
            LOG.exception(e)
            return render_exception(exception.ValidationError(e),
                                    user_locale=request.best_match_language())
        except Exception as e:
            LOG.exception(e)
            return render_exception(exception.UnexpectedError(exception=e),
                                    user_locale=request.best_match_language())


class Debug(Middleware):
    """Helper class for debugging a WSGI application.

    Can be inserted into any WSGI application chain to get information
    about the request and response.

    """

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        if not hasattr(LOG, 'isEnabledFor') or LOG.isEnabledFor(LOG.debug):
            LOG.debug('%s %s %s', ('*' * 20), 'REQUEST ENVIRON', ('*' * 20))
            for key, value in req.environ.items():
                LOG.debug('%s = %s', key, mask_password(value,
                                                        is_unicode=True))
            LOG.debug('')
            LOG.debug('%s %s %s', ('*' * 20), 'REQUEST BODY', ('*' * 20))
            for line in req.body_file:
                LOG.debug(mask_password(line))
            LOG.debug('')

        resp = req.get_response(self.application)
        if not hasattr(LOG, 'isEnabledFor') or LOG.isEnabledFor(LOG.debug):
            LOG.debug('%s %s %s', ('*' * 20), 'RESPONSE HEADERS', ('*' * 20))
            for (key, value) in resp.headers.iteritems():
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
        # if we're only running in debug, bump routes' internal logging up a
        # notch, as it's very spammy
        if CONF.debug:
            logging.getLogger('routes.middleware')

        self.map = mapper
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          self.map)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Route the incoming request to a controller based on self.map.

        If no match, return a 404.

        """
        return self._router

    @staticmethod
    @webob.dec.wsgify(RequestClass=Request)
    def _dispatch(req):
        """Dispatch the request to the appropriate controller.

        Called by self._router after matching the incoming request to a route
        and putting the information into req.environ.  Either returns 404
        or the routed WSGI app's response.

        """
        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            return render_exception(
                exception.NotFound(_('The resource could not be found.')),
                user_locale=req.best_match_language())
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
        mapper.connect('{path_info:.*}', controller=self.application)
        super(ExtensionRouter, self).__init__(mapper)

    def add_routes(self, mapper):
        pass

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = keystone.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import keystone.analytics
            keystone.analytics.Analytics(app, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory


def render_response(body=None, status=None, headers=None):
    """Forms a WSGI response."""
    headers = headers or []
    headers.append(('Vary', 'X-Auth-Token'))

    if body is None:
        body = ''
        status = status or (204, 'No Content')
    else:
        body = jsonutils.dumps(body, cls=utils.SmarterEncoder)
        headers.append(('Content-Type', 'application/json'))
        status = status or (200, 'OK')

    return webob.Response(body=body,
                          status='%s %s' % status,
                          headerlist=headers)


def render_exception(error, user_locale=None):
    """Forms a WSGI response based on the current error."""
    body = {'error': {
        'code': error.code,
        'title': error.title,
        'message': unicode(gettextutils.get_localized_message(error.args[0],
                                                              user_locale)),
    }}
    if isinstance(error, exception.AuthPluginException):
        body['error']['identity'] = error.authentication
    return render_response(status=(error.code, error.title), body=body)
