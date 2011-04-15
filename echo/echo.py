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

from eventlet import wsgi
from lxml import etree
import simplejson as json
import eventlet

class EchoApp:
    def __init__(self, environ, start_response):
        self.envr  = environ
        self.start = start_response
        self.dom   = self.toDOM(environ)
        self.transform = etree.XSLT(etree.parse("xsl/echo.xsl"))

    def __iter__(self):
        if self.envr["HTTP_ACCEPT"] == "application/xml":
            return self.toXML()
        else:
            return self.toJSON()

    def toJSON(self):
        self.start('200 OK', [('Content-Type', 'application/json')])
        yield str(self.transform(self.dom))

    def toXML(self):
        self.start('200 OK', [('Content-Type', 'application/xml')])
        yield etree.tostring (self.dom)

    def toDOM(self, environ):
        echo = etree.Element("{http://docs.openstack.org/echo/api/v1.0}echo",
                             method=environ["REQUEST_METHOD"],
                             pathInfo=environ["PATH_INFO"],
                             queryString=environ["QUERY_STRING"])
        content = etree.Element("{http://docs.openstack.org/echo/api/v1.0}content")
        content.set ("type", environ["CONTENT_TYPE"])
        content.text = ""
        inReq = environ["wsgi.input"]
        for line in inReq:
            content.text = content.text + line
        echo.append (content)
        return echo

wsgi.server(eventlet.listen(('', 8090)), EchoApp)
