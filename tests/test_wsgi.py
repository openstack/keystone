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

import webob

from keystone.common import wsgi
from keystone.openstack.common import jsonutils
from keystone import test


class FakeApp(wsgi.Application):
    def index(self, context):
        return {'a': 'b'}


class BaseWSGITest(test.TestCase):
    def setUp(self):
        self.app = FakeApp()
        super(BaseWSGITest, self).setUp()

    def _make_request(self, url='/'):
        req = webob.Request.blank(url)
        args = {'action': 'index', 'controller': None}
        req.environ['wsgiorg.routing_args'] = [None, args]
        return req

    def test_mask_password(self):
        message = ("test = 'password': 'aaaaaa', 'param1': 'value1', "
                   "\"new_password\": 'bbbbbb'")
        self.assertEqual(wsgi.mask_password(message, True),
                         u"test = 'password': '***', 'param1': 'value1', "
                         "\"new_password\": '***'")

        message = "test = 'password'  :   'aaaaaa'"
        self.assertEqual(wsgi.mask_password(message, False, '111'),
                         "test = 'password'  :   '111'")

        message = u"test = u'password' : u'aaaaaa'"
        self.assertEqual(wsgi.mask_password(message, True),
                         u"test = u'password' : u'***'")

        message = 'test = "password" : "aaaaaaaaa"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "password" : "***"')

        message = 'test = "original_password" : "aaaaaaaaa"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "original_password" : "***"')

        message = 'test = "original_password" : ""'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "original_password" : "***"')

        message = 'test = "param1" : "value"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "param1" : "value"')


class ApplicationTest(BaseWSGITest):
    def test_response_content_type(self):
        class FakeApp(wsgi.Application):
            def index(self, context):
                return {'a': 'b'}

        app = FakeApp()
        req = self._make_request()
        resp = req.get_response(app)
        self.assertEqual(resp.content_type, 'application/json')

    def test_query_string_available(self):
        class FakeApp(wsgi.Application):
            def index(self, context):
                return context['query_string']

        app = FakeApp()
        req = self._make_request(url='/?1=2')
        resp = req.get_response(app)
        self.assertEqual(jsonutils.loads(resp.body), {'1': '2'})

    def test_render_response(self):
        data = {'attribute': 'value'}
        body = '{"attribute": "value"}'

        resp = wsgi.render_response(body=data)
        self.assertEqual(resp.status, '200 OK')
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body, body)
        self.assertEqual(resp.headers.get('Vary'), 'X-Auth-Token')
        self.assertEqual(resp.headers.get('Content-Length'), str(len(body)))

    def test_render_response_custom_status(self):
        resp = wsgi.render_response(status=(501, 'Not Implemented'))
        self.assertEqual(resp.status, '501 Not Implemented')
        self.assertEqual(resp.status_int, 501)

    def test_render_response_custom_headers(self):
        resp = wsgi.render_response(headers=[('Custom-Header', 'Some-Value')])
        self.assertEqual(resp.headers.get('Custom-Header'), 'Some-Value')
        self.assertEqual(resp.headers.get('Vary'), 'X-Auth-Token')

    def test_render_response_no_body(self):
        resp = wsgi.render_response()
        self.assertEqual(resp.status, '204 No Content')
        self.assertEqual(resp.status_int, 204)
        self.assertEqual(resp.body, '')
        self.assertEqual(resp.headers.get('Content-Length'), '0')
        self.assertEqual(resp.headers.get('Content-Type'), None)
