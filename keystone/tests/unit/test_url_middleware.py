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

from keystone.server.flask.request_processing.middleware import url_normalize
from keystone.tests import unit


class FakeApp(object):
    """Fakes a WSGI app URL normalized."""

    def __init__(self):
        self.env = {}

    def __call__(self, env, start_response):
        self.env = env
        return


class UrlMiddlewareTest(unit.TestCase):
    def setUp(self):
        super(UrlMiddlewareTest, self).setUp()
        self.fake_app = FakeApp()
        self.middleware = url_normalize.URLNormalizingMiddleware(self.fake_app)

    def test_trailing_slash_normalization(self):
        """Test /v3/auth/tokens & /v3/auth/tokens/ normalized URLs match."""
        expected = '/v3/auth/tokens'
        no_slash = {'PATH_INFO': expected}
        with_slash = {'PATH_INFO': '/v3/auth/tokens/'}
        with_many_slash = {'PATH_INFO': '/v3/auth/tokens////'}

        # Run with a URL that doesn't need stripping and ensure nothing else is
        # added to the environ
        self.middleware(no_slash, None)
        self.assertEqual(expected, self.fake_app.env['PATH_INFO'])
        self.assertEqual(1, len(self.fake_app.env.keys()))

        # Run with a URL that needs a single slash stripped and nothing else is
        # added to the environ
        self.middleware(with_slash, None)
        self.assertEqual(expected, self.fake_app.env['PATH_INFO'])
        self.assertEqual(1, len(self.fake_app.env.keys()))

        # Run with a URL that needs multiple slashes stripped and ensure
        # nothing else is added to the environ
        self.middleware(with_many_slash, None)
        self.assertEqual(expected, self.fake_app.env['PATH_INFO'])
        self.assertEqual(1, len(self.fake_app.env.keys()))

    def test_rewrite_empty_path(self):
        """Test empty path is rewritten to root."""
        environ = {'PATH_INFO': ''}
        self.middleware(environ, None)
        self.assertEqual('/', self.fake_app.env['PATH_INFO'])
        self.assertEqual(1, len(self.fake_app.env.keys()))
