# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import eventlet
from eventlet import wsgi
from lxml import etree
import os
from paste.deploy import loadapp
import sys
from webob.exc import HTTPUnauthorized


# If ../echo/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'echo', '__init__.py')):
    # also use the local keystone
    KEYSTONE_TOPDIR = os.path.normpath(os.path.join(POSSIBLE_TOPDIR,
                                                    os.pardir,
                                                    os.pardir))
    if os.path.exists(os.path.join(KEYSTONE_TOPDIR,
                                   'keystone',
                                   '__init__.py')):
        sys.path.insert(0, KEYSTONE_TOPDIR)
    sys.path.insert(0, POSSIBLE_TOPDIR)


"""
Echo: a dummy service for OpenStack auth testing. It returns request info.
"""


class EchoApp(object):
    def __init__(self, environ, start_response):
        self.envr = environ
        self.start = start_response
        self.dom = self.toDOM(environ)
        echo_xsl = os.path.join(os.path.abspath(\
            os.path.dirname(__file__)), "xsl/echo.xsl")
        self.transform = etree.XSLT(etree.parse(echo_xsl))

    def __iter__(self):
        # We expect an X_AUTHORIZATION header to be passed in
        # We assume the request is coming from a trusted source. Middleware
        # is used to perform that validation.
        if 'HTTP_X_AUTHORIZATION' not in self.envr:
            self.start('401 Unauthorized', [('Content-Type',
                                             'application/json')])
            return iter(["401 Unauthorized"])

        if 'HTTP_X_IDENTITY_STATUS' not in self.envr:
            identity_status = "Unknown"
        else:
            identity_status = self.envr["HTTP_X_IDENTITY_STATUS"]

        print '  Received:'
        print '  Auth Status:', identity_status
        if 'HTTP_X_AUTHORIZATION' in self.envr:
            print '  Identity   :', self.envr['HTTP_X_AUTHORIZATION']
        if 'HTTP_X_TENANT' in self.envr:
            print '  Tenant     :', self.envr['HTTP_X_TENANT']
        if 'HTTP_X_ROLE' in self.envr:
            print '  Roles      :', self.envr['HTTP_X_ROLE']

        accept = self.envr.get("HTTP_ACCEPT", "application/json")
        if accept == "application/xml":
            return self.toXML()
        else:
            return self.toJSON()

    def toJSON(self):
        self.start('200 OK', [('Content-Type', 'application/json')])
        yield str(self.transform(self.dom))

    def toXML(self):
        self.start('200 OK', [('Content-Type', 'application/xml')])
        yield etree.tostring(self.dom)

    def toDOM(self, environ):
        echo = etree.Element("{http://docs.openstack.org/echo/api/v1.0}echo",
                             method=environ["REQUEST_METHOD"],
                             pathInfo=environ["PATH_INFO"],
                             queryString=environ.get('QUERY_STRING', ""))
        content = etree.Element(
            "{http://docs.openstack.org/echo/api/v1.0}content")
        content.set("type", environ["CONTENT_TYPE"])
        content.text = ""
        inReq = environ["wsgi.input"]
        for line in inReq:
            content.text = content.text + line
        echo.append(content)
        return echo


def app_factory(global_conf, **local_conf):
    return EchoApp

if __name__ == "__main__":
    def usage():
        print "Runs Echo, the canonical OpenStack service, " \
                "with auth middleware"
        print "Options:"
        print "-h, --help  : show this usage information"
        print "-b, --basic : run with basic auth (uses echo_basic.ini)"
        print "-r, --remote: run with remote auth on port 8100" \
                "(uses echo_remote.ini)"
        print "-i, --ini filename: run with specified ini file"
        print "-p, --port: specifies port to listen on (default is 8090)"
        print "by default will run with local, token auth (uses echo.ini)"

    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hbrp:i:",
                                   ["help", "basic", "remote", "port", "ini"])
    except getopt.GetoptError:
        usage()
        sys.exit()

    port = 0
    ini = "echo.ini"
    auth_name = "local Token Auth"

    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            usage()
            sys.exit()
        elif opt in ["-p", "--port"]:
            port = int(arg)
        elif opt in ["-i", "--ini"]:
            auth_name = "with custom ini: %s" % arg
            ini = arg
        elif opt in ["-b", "--basic"]:
            auth_name = "Basic Auth"
            ini = "echo_basic.ini"
        elif opt in ["-r", "--remote"]:
            auth_name = "remote Token Auth"
            ini = "echo_remote.ini"
            if not port:
                port = 8100

    if not port:
        port = 8090
    print "Running with", auth_name
    app = loadapp("config:" + \
        os.path.join(os.path.abspath(os.path.dirname(__file__)),
        ini), global_conf={"log_name": "echo.log"})
    listener = eventlet.listen(('', port))
    pool = eventlet.GreenPool(1000)
    wsgi.server(listener, app, custom_pool=pool)
