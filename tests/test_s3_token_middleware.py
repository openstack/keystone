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
import logging

import stubout
import unittest2 as unittest
import webob

from swift.common import utils as swift_utils

from keystone.middleware import s3_token


def denied_request(code):
    error_table = {
        'AccessDenied':
            (401, 'Access denied'),
        'InvalidURI':
            (400, 'Could not parse the specified URI'),
        }
    xml = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
        '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
        % (code, error_table[code][1])
    return xml


def setUpModule(self):
    self.stubs = stubout.StubOutForTesting()
    # Stub out swift_utils.get_logger.  get_logger tries to configure
    # syslogging to '/dev/log', which will fail on OS X.

    def fake_get_logger(config, log_route=None):
        return logging.getLogger(log_route)
    self.stubs.Set(swift_utils, 'get_logger', fake_get_logger)


def tearDownModule(self):
    self.stubs.UnsetAll()


class FakeHTTPResponse(object):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.reason = ""

    def read(self):
        return self.body


class FakeHTTPConnection(object):
    status = 201

    def __init__(self, *args):
        pass

    def request(self, method, path, **kwargs):
        if self.status == 503:
            raise Exception
        ret = {'access': {'token': {'id': 'TOKEN_ID',
                                    'tenant': {'id':  'TENANT_ID'}}}}
        body = json.dumps(ret)
        status = self.status
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


class S3TokenMiddlewareTest(unittest.TestCase):
    def setUp(self, expected_env=None):
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
        resp = req.get_response(self.middleware)
        self.assertEqual(resp.status_int, 400)
        self.assertEqual(resp.body, denied_request('InvalidURI'))

    def test_bad_token(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware.http_client_class.status = 403
        resp = req.get_response(self.middleware)
        self.assertEqual(resp.status_int, 401)
        self.assertEqual(resp.body, denied_request('AccessDenied'))

    def test_fail_to_connect_to_keystone(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        self.middleware.http_client_class.status = 503
        resp = req.get_response(self.middleware)
        self.assertEqual(resp.status_int, 400)
        self.assertEqual(resp.body, denied_request('InvalidURI'))

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
    unittest.main()
