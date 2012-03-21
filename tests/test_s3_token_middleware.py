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

import nose
import webob

from keystone import test

try:
    # NOTE(chmou): We don't want to force to have swift installed for
    # unit test so we skip it we have an ImportError.
    from keystone.middleware import s3_token
    skip = False
except ImportError:
    skip = True


class FakeHTTPResponse(object):
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def read(self):
        return self.body


class FakeHTTPConnection(object):
    def __init__(self, *args):
        pass

    def request(self, method, path, **kwargs):
        ret = {'access': {'token': {'id': 'TOKEN_ID',
                                    'tenant': {'id':  'TENANT_ID'}}}}
        body = json.dumps(ret)
        status = 201
        self.resp = FakeHTTPResponse(status, body)

    def getresponse(self):
        return self.resp

    def close(self):
        pass


class FakeApp(object):
    """This represents a WSGI app protected by the auth_token middleware."""
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.environ = env
        return resp(env, start_response)


class S3TokenMiddlewareTest(test.TestCase):
    def setUp(self, expected_env=None):
        # We probably going to end-up with the same strategy than
        # test_swift_auth when this is decided.
        if skip:
            raise nose.SkipTest('no swift detected')
        self.middleware = s3_token.S3Token(FakeApp(), {})
        self.middleware.http_client_class = FakeHTTPConnection

        self.response_status = None
        self.response_headers = None
        super(S3TokenMiddlewareTest, self).setUp()

    def _start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    # Ignore the request and pass to the next middleware in the
    # pipeline if no path has been specified.
    def test_no_path_request(self):
        req = webob.Request.blank('/')
        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 200)

    # Ignore the request and pass to the next middleware in the
    # pipeline if no Authorization header has been specified
    def test_without_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_without_auth_storage_token(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_with_bogus_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware(req.environ, self._start_fake_response)
        self.assertEqual(self.response_status, 400)

    def test_authorized(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        resp = webob.Request(req.get_response(self.middleware).environ)
        self.assertTrue(resp.path.startswith('/v1/AUTH_TENANT_ID'))
        self.assertEqual(resp.headers['X-Auth-Token'], 'TOKEN_ID')

    def test_authorization_nova_toconnect(self):
        req = webob.Request.blank('/v1/AUTH_swiftint/c/o')
        req.headers['Authorization'] = 'access:FORCED_TENANT_ID:signature'
        req.headers['X-Storage-Token'] = 'token'
        req = req.get_response(self.middleware)
        path = req.environ['PATH_INFO']
        self.assertTrue(path.startswith('/v1/AUTH_FORCED_TENANT_ID'))

if __name__ == '__main__':
    import unittest
    unittest.main()
