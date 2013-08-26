# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import testtools
import webob

from keystone.middleware import s3_token
from keystone.openstack.common import jsonutils


class FakeHTTPResponse(object):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.reason = ""

    def read(self):
        return self.body


class FakeApp(object):
    """This represents a WSGI app protected by the auth_token middleware."""
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.environ = env
        return resp(env, start_response)


class FakeHTTPConnection(object):
    def __init__(self, *args):
        return

    def getresponse(self):
        return self.resp

    def close(self):
        pass

    def request(self, method, path, **kwargs):
        pass


class S3TokenMiddlewareTestBase(testtools.TestCase):
    def setUp(self):
        super(S3TokenMiddlewareTestBase, self).setUp()

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)


def good_request(cls, method, path, **kwargs):
    cls.status = 201
    ret = {'access': {'token':
                      {'id': 'TOKEN_ID',
                       'tenant': {'id': 'TENANT_ID'}}}}
    body = jsonutils.dumps(ret)
    cls.resp = FakeHTTPResponse(cls.status, body)


class S3TokenMiddlewareTestGood(S3TokenMiddlewareTestBase):
    def setup_middleware_fake(self):
        self.middleware.http_client_class = FakeHTTPConnection
        self.middleware.http_client_class.request = good_request

    def setUp(self):
        self.middleware = s3_token.S3Token(FakeApp(), {})
        self.setup_middleware_fake()
        super(S3TokenMiddlewareTestGood, self).setUp()

    # Ignore the request and pass to the next middleware in the
    # pipeline if no path has been specified.
    def test_no_path_request(self):
        req = webob.Request.blank('/')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    # Ignore the request and pass to the next middleware in the
    # pipeline if no Authorization header has been specified
    def test_without_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_without_auth_storage_token(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_authorized(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        req.get_response(self.middleware)
        self.assertTrue(req.path.startswith('/v1/AUTH_TENANT_ID'))
        self.assertEqual(req.headers['X-Auth-Token'], 'TOKEN_ID')

    def test_authorized_http(self):
        self.middleware = (
            s3_token.filter_factory({'auth_protocol': 'http'})(FakeApp()))
        self.setup_middleware_fake()
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        req.get_response(self.middleware)
        self.assertTrue(req.path.startswith('/v1/AUTH_TENANT_ID'))
        self.assertEqual(req.headers['X-Auth-Token'], 'TOKEN_ID')

    def test_authorization_nova_toconnect(self):
        req = webob.Request.blank('/v1/AUTH_swiftint/c/o')
        req.headers['Authorization'] = 'access:FORCED_TENANT_ID:signature'
        req.headers['X-Storage-Token'] = 'token'
        req.get_response(self.middleware)
        path = req.environ['PATH_INFO']
        self.assertTrue(path.startswith('/v1/AUTH_FORCED_TENANT_ID'))


class S3TokenMiddlewareTestBad(S3TokenMiddlewareTestBase):
    def setUp(self):
        self.middleware = s3_token.S3Token(FakeApp(), {})
        self.middleware.http_client_class = FakeHTTPConnection
        super(S3TokenMiddlewareTestBad, self).setUp()

    def test_unauthorized_token(self):
        def request(self, method, path, **kwargs):
            ret = {"error":
                   {"message": "EC2 access key not found.",
                    "code": 401,
                    "title": "Unauthorized"}}
            body = jsonutils.dumps(ret)
            self.status = 403
            self.resp = FakeHTTPResponse(self.status, body)

        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware.http_client_class.request = request
        resp = req.get_response(self.middleware)
        s3_denied_req = self.middleware.deny_request('AccessDenied')
        self.assertEqual(resp.body, s3_denied_req.body)
        self.assertEqual(resp.status_int, s3_denied_req.status_int)

    def test_bogus_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        req.headers['X-Storage-Token'] = 'token'
        resp = req.get_response(self.middleware)
        self.assertEqual(resp.status_int, 400)
        s3_invalid_req = self.middleware.deny_request('InvalidURI')
        self.assertEqual(resp.body, s3_invalid_req.body)
        self.assertEqual(resp.status_int, s3_invalid_req.status_int)

    def test_fail_to_connect_to_keystone(self):
        def request(self, method, path, **kwargs):
            raise s3_token.ServiceError
        self.middleware.http_client_class.request = request

        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware.http_client_class.status = 503
        resp = req.get_response(self.middleware)
        s3_invalid_req = self.middleware.deny_request('InvalidURI')
        self.assertEqual(resp.body, s3_invalid_req.body)
        self.assertEqual(resp.status_int, s3_invalid_req.status_int)

    def test_bad_reply(self):
        def request(self, method, path, **kwargs):
            body = "<badreply>"
            self.status = 201
            self.resp = FakeHTTPResponse(self.status, body)

        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware.http_client_class.request = request
        resp = req.get_response(self.middleware)
        s3_invalid_req = self.middleware.deny_request('InvalidURI')
        self.assertEqual(resp.body, s3_invalid_req.body)
        self.assertEqual(resp.status_int, s3_invalid_req.status_int)


class S3TokenMiddlewareTestUtil(testtools.TestCase):
    def test_split_path_failed(self):
        self.assertRaises(ValueError, s3_token.split_path, '')
        self.assertRaises(ValueError, s3_token.split_path, '/')
        self.assertRaises(ValueError, s3_token.split_path, '//')
        self.assertRaises(ValueError, s3_token.split_path, '//a')
        self.assertRaises(ValueError, s3_token.split_path, '/a/c')
        self.assertRaises(ValueError, s3_token.split_path, '//c')
        self.assertRaises(ValueError, s3_token.split_path, '/a/c/')
        self.assertRaises(ValueError, s3_token.split_path, '/a//')
        self.assertRaises(ValueError, s3_token.split_path, '/a', 2)
        self.assertRaises(ValueError, s3_token.split_path, '/a', 2, 3)
        self.assertRaises(ValueError, s3_token.split_path, '/a', 2, 3, True)
        self.assertRaises(ValueError, s3_token.split_path, '/a/c/o/r', 3, 3)
        self.assertRaises(ValueError, s3_token.split_path, '/a', 5, 4)

    def test_split_path_success(self):
        self.assertEquals(s3_token.split_path('/a'), ['a'])
        self.assertEquals(s3_token.split_path('/a/'), ['a'])
        self.assertEquals(s3_token.split_path('/a/c', 2), ['a', 'c'])
        self.assertEquals(s3_token.split_path('/a/c/o', 3), ['a', 'c', 'o'])
        self.assertEquals(s3_token.split_path('/a/c/o/r', 3, 3, True),
                          ['a', 'c', 'o/r'])
        self.assertEquals(s3_token.split_path('/a/c', 2, 3, True),
                          ['a', 'c', None])
        self.assertEquals(s3_token.split_path('/a/c/', 2), ['a', 'c'])
        self.assertEquals(s3_token.split_path('/a/c/', 2, 3), ['a', 'c', ''])

    def test_split_path_invalid_path(self):
        try:
            s3_token.split_path('o\nn e', 2)
        except ValueError as err:
            self.assertEquals(str(err), 'Invalid path: o%0An%20e')
        try:
            s3_token.split_path('o\nn e', 2, 3, True)
        except ValueError as err:
            self.assertEquals(str(err), 'Invalid path: o%0An%20e')
