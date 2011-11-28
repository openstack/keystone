# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

"""
Utility methods for working with WSGI servers
"""

import json
import logging
import sys
import datetime
import ssl

import eventlet.wsgi
eventlet.patcher.monkey_patch(all=False, socket=True)
import routes.middleware
from webob import Response
import webob.dec


def find_console_handler(logger):
    """Returns a stream handler, if any"""
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and \
                handler.stream == sys.stderr:
            return handler


def add_console_handler(logger, level=logging.INFO):
    """
    Add a Handler which writes log messages to sys.stderr (usually the console)
    """
    console = find_console_handler(logger)

    if not console:
        console = logging.StreamHandler()
        console.setLevel(level)
        # set a format which is simpler for console use
        formatter = logging.Formatter(
            "%(name)-12s: %(levelname)-8s %(message)s")
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logger.addHandler(console)
    elif console.level != level:
        console.setLevel(level)
    return console


class WritableLogger(object):
    """A thin wrapper that responds to `write` and logs."""

    def __init__(self, logger, level=logging.INFO):
        self.logger = logger
        self.level = level
        # TODO(Ziad): figure out why root logger is not set to same level as
        # caller. Maybe something to do with paste?
        if level == logging.DEBUG:
            add_console_handler(logger, level)

    def write(self, msg):
        self.logger.log(self.level, msg.strip("\n"))


def run_server(application, port):
    """Run a WSGI server with the given application."""
    sock = eventlet.listen(('0.0.0.0', port))
    eventlet.wsgi.server(sock, application)


class Server(object):
    """Server class to manage multiple WSGI sockets and applications."""
    started = False

    def __init__(self, threads=1000):
        self.pool = eventlet.GreenPool(threads)
        self.socket_info = {}
        self.threads = {}

    def start(self, application, port, host='0.0.0.0', key=None, backlog=128):
        """Run a WSGI server with the given application."""
        socket = eventlet.listen((host, port), backlog=backlog)
        thread = self.pool.spawn(self._run, application, socket)
        if key:
            self.socket_info[key] = socket
            self.threads[key] = thread

    def wait(self):
        """Wait until all servers have completed running."""
        try:
            self.pool.waitall()
        except KeyboardInterrupt:
            pass

    def _run(self, application, socket):
        """Start a WSGI server in a new green thread."""
        logger = logging.getLogger('eventlet.wsgi.server')
        # TODO(Ziad): figure out why root logger is not set to same level as
        # caller. Maybe something to do with paste?
        eventlet.wsgi.server(socket, application, custom_pool=self.pool,
                             log=WritableLogger(logger, logging.root.level))


class SslServer(Server):
    """SSL Server class to manage multiple WSGI sockets and applications."""
    def start(self, application, port, host='0.0.0.0', backlog=128,
              certfile=None, keyfile=None, ca_certs=None,
              cert_required='True', key=None):
        """Run a 2-way SSL WSGI server with the given application."""
        socket = eventlet.listen((host, port), backlog=backlog)
        if cert_required == 'True':
            cert_reqs = ssl.CERT_REQUIRED
        else:
            cert_reqs = ssl.CERT_NONE
        sslsocket = eventlet.wrap_ssl(socket, certfile=certfile,
                                      keyfile=keyfile,
                                      server_side=True, cert_reqs=cert_reqs,
                                      ca_certs=ca_certs)
        thread = self.pool.spawn(self._run, application, sslsocket)
        if key:
            self.socket_info[key] = sslsocket
            self.threads[key] = thread


class Middleware(object):
    """
    Base WSGI middleware wrapper. These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.
    """

    def __init__(self, application):
        self.application = application

    def process_request(self, req):
        """
        Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.

        """
        return None

    def process_response(self, response):
        """Do whatever you'd like to the response."""
        return response

    @webob.dec.wsgify
    def __call__(self, req):
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self.application)
        return self.process_response(response)


class Debug(Middleware):
    """
    Helper class that can be inserted into any WSGI application chain
    to get information about the request and response.
    """

    @webob.dec.wsgify
    def __call__(self, req):
        print ("*" * 40) + " REQUEST ENVIRON"
        for key, value in req.environ.items():
            print key, "=", value
        print
        resp = req.get_response(self.application)

        print ("*" * 40) + " RESPONSE HEADERS"
        for (key, value) in resp.headers.iteritems():
            print key, "=", value
        print

        resp.app_iter = self.print_generator(resp.app_iter)

        return resp

    @staticmethod
    def print_generator(app_iter):
        """
        Iterator that prints the contents of a wrapper string iterator
        when iterated.
        """
        print ("*" * 40) + " BODY"
        for part in app_iter:
            sys.stdout.write(part)
            sys.stdout.flush()
            yield part
        print


def debug_filter_factory(global_conf):
    """Filter factor to easily insert a debugging middleware into the
    paste.deploy pipeline"""
    def filter(app):
        return Debug(app)
    return filter


class Router(object):
    """
    WSGI middleware that maps incoming requests to WSGI apps.
    """

    def __init__(self, mapper):
        """
        Create a router for the given routes.Mapper.

        Each route in `mapper` must specify a 'controller', which is a
        WSGI app to call.  You'll probably want to specify an 'action' as
        well and have your controller be a wsgi.Controller, who will route
        the request to the action method.

        Examples:
          mapper = routes.Mapper()
          sc = ServerController()

          # Explicit mapping of one route to a controller+action
          mapper.connect(None, "/svrlist", controller=sc, action="list")

          # Actions are all implicitly defined
          mapper.resource("server", "servers", controller=sc)

          # Pointing to an arbitrary WSGI app.  You can specify the
          # {path_info:.*} parameter so the target app can be handed just that
          # section of the URL.
          mapper.connect(None, "/v2.0/{path_info:.*}", controller=TheApp())
        """
        self.map = mapper
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          self.map)

    @webob.dec.wsgify
    def __call__(self, req):
        """
        Route the incoming request to a controller based on self.map.
        If no match, return a 404.
        """
        return self._router

    @staticmethod
    @webob.dec.wsgify
    def _dispatch(req):
        """
        Called by self._router after matching the incoming request to a route
        and putting the information into req.environ.  Returns the routed
        WSGI app's response or an Accept-appropriate 404.
        """
        return req.environ['wsgiorg.routing_args'][1].get('controller') \
            or HTTPNotFound()


class Controller(object):
    """
    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon itself.  All action methods
    must, in addition to their normal parameters, accept a 'req' argument
    which is the incoming webob.Request.  They raise a webob.exc exception,
    or return a dict which will be serialized by requested content type.
    """

    @webob.dec.wsgify
    def __call__(self, req):
        """
        Call the method specified in req.environ by RoutesMiddleware.
        """
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict['action']
        method = getattr(self, action)
        del arg_dict['controller']
        del arg_dict['action']
        arg_dict['req'] = req
        result = method(**arg_dict)
        if type(result) is dict:
            return self._serialize(result, req)
        else:
            return result

    def _serialize(self, data, request):
        """
        Serialize the given dict to the response type requested in request.
        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.
        """
        _metadata = getattr(type(self), "_serialization_metadata", {})
        serializer = Serializer(request.environ, _metadata)
        return serializer.to_content_type(data)


class Serializer(object):
    """
    Serializes a dictionary to a Content Type specified by a WSGI environment.
    """

    def __init__(self, environ, metadata={}):
        """
        Create a serializer based on the given WSGI environment.
        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.
        """
        self.environ = environ
        self.metadata = metadata
        self._methods = {
            'application/json': self._to_json,
            'application/xml': self._to_xml}

    def to_content_type(self, data):
        """
        Serialize a dictionary into a string.  The format of the string
        will be decided based on the Content Type requested in self.environ:
        by Accept: header, or by URL suffix.
        """
        # FIXME(sirp): for now, supporting json only
        #mimetype = 'application/xml'
        mimetype = 'application/json'
        # TODO(gundlach): determine mimetype from request
        return self._methods.get(mimetype, repr)(data)

    def _to_json(self, data):
        def sanitizer(obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return obj

        return json.dumps(data, default=sanitizer)

    def _to_xml(self, data):
        metadata = self.metadata.get('application/xml', {})
        # We expect data to contain a single key which is the XML root.
        root_key = data.keys()[0]
        from xml.dom import minidom
        doc = minidom.Document()
        node = self._to_xml_node(doc, metadata, root_key, data[root_key])
        return node.toprettyxml(indent='    ')

    def _to_xml_node(self, doc, metadata, nodename, data):
        """Recursive method to convert data members to XML nodes."""
        result = doc.createElement(nodename)
        if type(data) is list:
            singular = metadata.get('plurals', {}).get(nodename, None)
            if singular is None:
                if nodename.endswith('s'):
                    singular = nodename[:-1]
                else:
                    singular = 'item'
            for item in data:
                node = self._to_xml_node(doc, metadata, singular, item)
                result.appendChild(node)
        elif type(data) is dict:
            attrs = metadata.get('attributes', {}).get(nodename, {})
            for k, v in data.items():
                if k in attrs:
                    result.setAttribute(k, str(v))
                else:
                    node = self._to_xml_node(doc, metadata, k, v)
                    result.appendChild(node)
        else:  # atom
            node = doc.createTextNode(str(data))
            result.appendChild(node)
        return result


class WSGIHTTPException(Response, webob.exc.HTTPException):
    """Returned when no matching route can be identified"""

    code = None
    label = None
    title = None
    explanation = None

    xml_template = """\
<?xml version="1.0" encoding="UTF-8"?>
<%s xmlns="http://docs.openstack.org/identity/api/v2.0" code="%s">
    <message>%s</message>
    <details>%s</details>
</%s>"""

    def __init__(self, code, label, title, explanation, **kw):
        self.code = code
        self.label = label
        self.title = title
        self.explanation = explanation

        Response.__init__(self, status='%s %s' % (self.code, self.title), **kw)
        webob.exc.HTTPException.__init__(self, self.explanation, self)

    def xml_body(self):
        """Generate a XML body string using the available data"""
        return self.xml_template % (
            self.label, self.code, self.title, self.explanation, self.label)

    def json_body(self):
        """Generate a JSON body string using the available data"""
        json_dict = {self.label: {}}
        json_dict[self.label]['message'] = self.title
        json_dict[self.label]['details'] = self.explanation
        json_dict[self.label]['code'] = self.code

        return json.dumps(json_dict)

    def generate_response(self, environ, start_response):
        """Returns a response to the given environment"""
        if self.content_length is not None:
            del self.content_length

        headerlist = list(self.headerlist)

        accept = environ.get('HTTP_ACCEPT', '')

        # Return JSON by default
        if accept and 'xml' in accept:
            content_type = 'application/xml'
            body = self.xml_body()
        else:
            content_type = 'application/json'
            body = self.json_body()

        extra_kw = {}

        if isinstance(body, unicode):
            extra_kw.update(charset='utf-8')

        resp = Response(body,
            status=self.status,
            headerlist=headerlist,
            content_type=content_type,
            **extra_kw)

        # Why is this repeated?
        resp.content_type = content_type

        return resp(environ, start_response)

    def __call__(self, environ, start_response):
        if environ['REQUEST_METHOD'] == 'HEAD':
            start_response(self.status, self.headerlist)
            return []
        if not self.body:
            return self.generate_response(environ, start_response)
        return webob.Response.__call__(self, environ, start_response)

    def exception(self):
        """Returns self as an exception response"""
        return webob.exc.HTTPException(self.explanation, self)

    exception = property(exception)


class HTTPNotFound(WSGIHTTPException):
    """Represents a 404 Not Found webob response exception"""
    def __init__(self, code=404, label='itemNotFound', title='Item not found.',
            explanation='Error Details...', **kw):
        """Build a 404 WSGI response"""
        super(HTTPNotFound, self).__init__(code, label, title, explanation,
            **kw)
