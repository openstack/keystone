# Copyright 2012 OpenStack Foundation
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

from keystone import middleware
from keystone.tests import unit


class FakeApp(object):
    """Fakes a WSGI app URL normalized."""
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.body = 'SUCCESS'
        return resp(env, start_response)


class UrlMiddlewareTest(unit.TestCase):
    def setUp(self):
        self.middleware = middleware.NormalizingFilter(FakeApp())
        self.response_status = None
        self.response_headers = None
        super(UrlMiddlewareTest, self).setUp()

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    def test_trailing_slash_normalization(self):
        """Tests /v2.0/tokens and /v2.0/tokens/ normalized URLs match."""
        req1 = webob.Request.blank('/v2.0/tokens')
        req2 = webob.Request.blank('/v2.0/tokens/')
        self.middleware(req1.environ, self.start_fake_response)
        self.middleware(req2.environ, self.start_fake_response)
        self.assertEqual(req1.path_url, req2.path_url)
        self.assertEqual('http://localhost/v2.0/tokens', req1.path_url)

    def test_rewrite_empty_path(self):
        """Tests empty path is rewritten to root."""
        req = webob.Request.blank('')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual('http://localhost/', req.path_url)
