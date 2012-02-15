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

import json

import webob

from keystone import test
from keystone.common import wsgi


class ApplicationTest(test.TestCase):
    def _make_request(self, url='/'):
        req = webob.Request.blank(url)
        args = {'action': 'index', 'controller': None}
        req.environ['wsgiorg.routing_args'] = [None, args]
        return req

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
        self.assertEqual(json.loads(resp.body), {'1': '2'})
