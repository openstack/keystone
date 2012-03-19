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

from keystone import middleware
from keystone import test

import test_auth_token_middleware as test_atm


class FakeApp(object):
    """Fakes a WSGI app URL normalized."""
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.body = 'SUCCESS'
        return resp(env, start_response)


class UrlMiddlewareTest(test.TestCase):
    def setUp(self):
        self.middleware = middleware.NormalizingFilter(FakeApp())
        self.middleware.http_client_class = test_atm.FakeHTTPConnection
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
        _ = self.middleware(req1.environ, self.start_fake_response)
        _ = self.middleware(req2.environ, self.start_fake_response)
        self.assertEqual(req1.path_url, req2.path_url)
        self.assertEqual(req1.path_url, 'http://localhost/v2.0/tokens')

    def test_rewrite_empty_path(self):
        """Tests empty path is rewritten to root."""
        req = webob.Request.blank('')
        _ = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(req.path_url, 'http://localhost/')
