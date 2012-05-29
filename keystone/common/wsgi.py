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

import json
import sys

import eventlet.wsgi
eventlet.patcher.monkey_patch(all=False, socket=True, time=True)
import routes.middleware
import ssl
import webob.dec
import webob.exc

from keystone import exception
from keystone.common import logging
from keystone.common import utils


LOG = logging.getLogger(__name__)


class WritableLogger(object):
    """A thin wrapper that responds to `write` and logs."""

    def __init__(self, logger, level=logging.DEBUG):
        self.logger = logger
        self.level = level

    def write(self, msg):
        self.logger.log(self.level, msg)


class Server(object):
    """Server class to manage multiple WSGI sockets and applications."""

    def __init__(self, application, host=None, port=None, threads=1000):
        self.application = application
        self.host = host or '0.0.0.0'
        self.port = port or 0
        self.pool = eventlet.GreenPool(threads)
        self.socket_info = {}
        self.greenthread = None
        self.do_ssl = False
        self.cert_required = False

    def start(self, key=None, backlog=128):
        """Run a WSGI server with the given application."""
        LOG.debug('Starting %(arg0)s on %(host)s:%(port)s' %
                      {'arg0': sys.argv[0],
                       'host': self.host,
                       'port': self.port})
        socket = eventlet.listen((self.host, self.port), backlog=backlog)
        if key:
            self.socket_info[key] = socket.getsockname()
        # SSL is enabled
        if self.do_ssl:
            if self.cert_required:
                cert_reqs = ssl.CERT_REQUIRED
            else:
                cert_reqs = ssl.CERT_NONE
            sslsocket = eventlet.wrap_ssl(socket, certfile=self.certfile,
                                          keyfile=self.keyfile,
                                          server_side=True,
                                          cert_reqs=cert_reqs,
                                          ca_certs=self.ca_certs)
            socket = sslsocket

        self.greenthread = self.pool.spawn(self._run, self.application, socket)

    def set_ssl(self, certfile, keyfile=None, ca_certs=None,
              cert_required=True):
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_certs = ca_certs
        self.cert_required = cert_required
        self.do_ssl = True

    def kill(self):
        if self.greenthread:
            self.greenthread.kill()

    def wait(self):
        """Wait until all servers have completed running."""
        try:
            self.pool.waitall()
        except KeyboardInterrupt:
            pass

    def _run(self, application, socket):
        """Start a WSGI server in a new green thread."""
        log = logging.getLogger('eventlet.wsgi.server')
        eventlet.wsgi.server(socket, application, custom_pool=self.pool,
                             log=WritableLogger(log))


class Request(webob.Request):
    pass


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
            paste.app_factory = nova.api.fancy_api:Wadl.factory

        which would result in a call to the `Wadl` class as

            import nova.api.fancy_api
            fancy_api.Wadl(latest_version='1.3')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        return cls()

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
    @webob.dec.wsgify
    def __call__(self, req):
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict.pop('action')
        del arg_dict['controller']
        LOG.debug('arg_dict: %s', arg_dict)

        # allow middleware up the stack to provide context & params
        context = req.environ.get('openstack.context', {})
        context['query_string'] = dict(req.params.iteritems())
        params = req.environ.get('openstack.params', {})
        params.update(arg_dict)

        # TODO(termie): do some basic normalization on methods
        method = getattr(self, action)

        # NOTE(vish): make sure we have no unicode keys for py2.6.
        params = self._normalize_dict(params)

        try:
            result = method(context, **params)
        except exception.Error as e:
            LOG.warning(e)
            return render_exception(e)
        except Exception as e:
            logging.exception(e)
            return render_exception(exception.UnexpectedError(exception=e))

        if result is None:
            return render_response(status=(204, 'No Content'))
        elif isinstance(result, basestring):
            return result
        elif isinstance(result, webob.Response):
            return result
        elif isinstance(result, webob.exc.WSGIHTTPException):
            return result
        return render_response(body=result)

    def _normalize_arg(self, arg):
        return str(arg).replace(':', '_').replace('-', '_')

    def _normalize_dict(self, d):
        return dict([(self._normalize_arg(k), v)
                     for (k, v) in d.iteritems()])

    def assert_admin(self, context):
        if not context['is_admin']:
            try:
                user_token_ref = self.token_api.get_token(
                        context=context, token_id=context['token_id'])
            except exception.TokenNotFound:
                raise exception.Unauthorized()

            creds = user_token_ref['metadata'].copy()

            try:
                creds['user_id'] = user_token_ref['user'].get('id')
            except AttributeError:
                logging.debug('Invalid user')
                raise exception.Unauthorized()

            try:
                creds['tenant_id'] = user_token_ref['tenant'].get('id')
            except AttributeError:
                logging.debug('Invalid tenant')
                raise exception.Unauthorized()

            # NOTE(vish): this is pretty inefficient
            creds['roles'] = [self.identity_api.get_role(context, role)['name']
                              for role in creds.get('roles', [])]
            # Accept either is_admin or the admin role
            self.policy_api.enforce(context, creds, 'admin_required', {})


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
            paste.filter_factory = nova.api.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import nova.api.analytics
            analytics.Analytics(app_from_paste, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app)
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

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        LOG.debug('%s %s %s', ('*' * 20), 'REQUEST ENVIRON', ('*' * 20))
        for key, value in req.environ.items():
            LOG.debug('%s = %s', key, value)
        LOG.debug('')
        LOG.debug('%s %s %s', ('*' * 20), 'REQUEST BODY', ('*' * 20))
        for line in req.body_file:
            LOG.debug(line)
        LOG.debug('')

        resp = req.get_response(self.application)

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
            #sys.stdout.write(part)
            LOG.debug(part)
            #sys.stdout.flush()
            yield part
        print


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
            return webob.exc.HTTPNotFound()
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
            paste.filter_factory = nova.api.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import nova.api.analytics
            analytics.Analytics(app_from_paste, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app)
        return _factory


def render_response(body=None, status=(200, 'OK'), headers=None):
    """Forms a WSGI response."""
    resp = webob.Response()
    resp.status = '%s %s' % status
    resp.headerlist = headers or [('Content-Type', 'application/json'),
                                  ('Vary', 'X-Auth-Token')]

    if body is not None:
        resp.body = json.dumps(body, cls=utils.SmarterEncoder)

    return resp


def render_exception(error):
    """Forms a WSGI response based on the current error."""
    return render_response(status=(error.code, error.title), body={
        'error': {
            'code': error.code,
            'title': error.title,
            'message': str(error),
        }
    })
