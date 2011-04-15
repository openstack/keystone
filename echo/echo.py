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
        self.environ = environ
        self.start = start_response
        self.method       = environ["REQUEST_METHOD"]
        self.pathInfo     = environ["PATH_INFO"]
        self.queryString  = environ["QUERY_STRING"]
        self.contentType  = environ["CONTENT_TYPE"]
        self.content      = ""

        inReq = environ["wsgi.input"]
        for line in inReq:
            self.content = self.content + line

    def __iter__(self):
        return self.toXML()

    def toJSON(self):
        self.start('200 OK', [('Content-Type', 'application/json')])
        yield "{'echo' : {}}" 

    def toXML(self):
        echo = etree.Element("{http://docs.openstack.org/echo/api/v1.0}echo",
                             method=self.method,
                             pathInfo=self.pathInfo,
                             queryString=self.queryString)
        content = etree.Element("{http://docs.openstack.org/echo/api/v1.0}content")
        content.set ("type", self.contentType)
        content.text = self.content
        echo.append (content)
        self.start('200 OK', [('Content-Type', 'application/xml')])
        yield etree.tostring (echo, pretty_print=True)

wsgi.server(eventlet.listen(('', 8090)), EchoApp)
