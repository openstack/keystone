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

import os
import sys

import eventlet
from eventlet import wsgi
from lxml import etree
from paste.deploy import loadapp

# If ../echo/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'echo', '__init__.py')):
    # also use the local keystone
    KEYSTONE_TOPDIR = os.path.normpath(os.path.join(POSSIBLE_TOPDIR,
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
        if 'HTTP_X_AUTHORIZATION' not in self.envr:
            return HTTPUnauthorized(env, start_response)

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
                             queryString=environ.get('QUERY_STRING', ""),
                             caller_identity=self.envr['HTTP_X_AUTHORIZATION'])
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
    remote_auth = False
    if len(sys.argv) > 1:
        remote_auth = sys.argv[1] == '--remote'

    if remote_auth:
        # running auth remotely
        print "Running for use with remote auth"

        app = loadapp("config:" + \
            os.path.join(os.path.abspath(os.path.dirname(__file__)),
            "echo_remote.ini"), global_conf={"log_name": "echo.log"})

        wsgi.server(eventlet.listen(('', 8100)), app)

    else:
        print "Running all components locally."
        print "Use --remote option to run with remote auth proxy"
        app = loadapp("config:" + \
            os.path.join(os.path.abspath(os.path.dirname(__file__)),
            "echo.ini"), global_conf={"log_name": "echo.log"})

        wsgi.server(eventlet.listen(('', 8090)), app)
