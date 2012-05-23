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
import datetime
import iso8601

from keystone.middleware import auth_token
from keystone import test


# JSON responses keyed by token ID
TOKEN_RESPONSES = {
    'valid-token': {
        'access': {
            'token': {
                'id': 'valid-token',
                'tenant': {
                    'id': 'tenant_id1',
                    'name': 'tenant_name1',
                },
            },
            'user': {
                'id': 'user_id1',
                'name': 'user_name1',
                'roles': [
                    {'name': 'role1'},
                    {'name': 'role2'},
                ],
            },
        },
    },
    'default-tenant-token': {
        'access': {
            'token': {
                'id': 'default-tenant-token',
            },
            'user': {
                'id': 'user_id1',
                'name': 'user_name1',
                'tenantId': 'tenant_id1',
                'tenantName': 'tenant_name1',
                'roles': [
                    {'name': 'role1'},
                    {'name': 'role2'},
                ],
            },
        },
    },
    'valid-diablo-token': {
        'access': {
            'token': {
                'id': 'valid-diablo-token',
                'tenantId': 'tenant_id1',
            },
            'user': {
                'id': 'user_id1',
                'name': 'user_name1',
                'roles': [
                    {'name': 'role1'},
                    {'name': 'role2'},
                ],
            },
        },
    },
    'unscoped-token': {
        'access': {
            'token': {
                'id': 'unscoped-token',
            },
            'user': {
                'id': 'user_id1',
                'name': 'user_name1',
                'roles': [
                    {'name': 'role1'},
                    {'name': 'role2'},
                ],
            },
        },
    }
}


class FakeMemcache(object):
    def __init__(self):
        self.set_key = None
        self.set_value = None
        self.token_expiration = None

    def get(self, key):
        data = TOKEN_RESPONSES['valid-token'].copy()
        if not data or key != "tokens/%s" % (data['access']['token']['id']):
            return
        if not self.token_expiration:
            dt = datetime.datetime.now() + datetime.timedelta(minutes=5)
            self.token_expiration = dt.strftime("%s")
        dt = datetime.datetime.now() + datetime.timedelta(hours=24)
        ks_expires = dt.isoformat()
        data['access']['token']['expires'] = ks_expires
        return (data, str(self.token_expiration))

    def set(self, key, value, time=None):
        self.set_value = value
        self.set_key = key


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
        """Fakes out several http responses.

        If a POST request is made, we assume the calling code is trying
        to get a new admin token.

        If a GET request is made to validate a token, return success
        if the token is 'token1'. If a different token is provided, return
        a 404, indicating an unknown (therefore unauthorized) token.

        """
        if method == 'POST':
            status = 200
            body = json.dumps({
                'access': {
                    'token': {'id': 'admin_token2'},
                },
            })

        else:
            token_id = path.rsplit('/', 1)[1]
            if token_id in TOKEN_RESPONSES.keys():
                status = 200
                body = json.dumps(TOKEN_RESPONSES[token_id])
            else:
                status = 404
                body = str()

        self.resp = FakeHTTPResponse(status, body)

    def getresponse(self):
        return self.resp

    def close(self):
        pass


class FakeApp(object):
    """This represents a WSGI app protected by the auth_token middleware."""
    def __init__(self, expected_env=None):
        expected_env = expected_env or {}
        self.expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Confirmed',
            'HTTP_X_TENANT_ID': 'tenant_id1',
            'HTTP_X_TENANT_NAME': 'tenant_name1',
            'HTTP_X_USER_ID': 'user_id1',
            'HTTP_X_USER_NAME': 'user_name1',
            'HTTP_X_ROLES': 'role1,role2',
            'HTTP_X_USER': 'user_name1',  # deprecated (diablo-compat)
            'HTTP_X_TENANT': 'tenant_name1',  # deprecated (diablo-compat)
            'HTTP_X_ROLE': 'role1,role2',  # deprecated (diablo-compat)
        }
        self.expected_env.update(expected_env)

    def __call__(self, env, start_response):
        for k, v in self.expected_env.items():
            assert env[k] == v, '%s != %s' % (env[k], v)

        resp = webob.Response()
        resp.body = 'SUCCESS'
        return resp(env, start_response)


class BaseAuthTokenMiddlewareTest(test.TestCase):
    def setUp(self, expected_env=None):
        expected_env = expected_env or {}

        conf = {
            'admin_token': 'admin_token1',
            'auth_host': 'keystone.example.com',
            'auth_port': 1234,
        }

        self.middleware = auth_token.AuthProtocol(FakeApp(expected_env), conf)
        self.middleware.http_client_class = FakeHTTPConnection
        self.middleware._iso8601 = iso8601

        self.response_status = None
        self.response_headers = None
        super(BaseAuthTokenMiddlewareTest, self).setUp()

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)


class DiabloAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest):
    """Auth Token middleware should understand Diablo keystone responses."""
    def setUp(self):
        # pre-diablo only had Tenant ID, which was also the Name
        expected_env = {
            'HTTP_X_TENANT_ID': 'tenant_id1',
            'HTTP_X_TENANT_NAME': 'tenant_id1',
            'HTTP_X_TENANT': 'tenant_id1',  # now deprecated (diablo-compat)
        }
        super(DiabloAuthTokenMiddlewareTest, self).setUp(expected_env)

    def test_diablo_response(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'valid-diablo-token'
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, ['SUCCESS'])


class AuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest):
    def test_valid_request(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'valid-token'
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, ['SUCCESS'])

    def test_default_tenant_token(self):
        """Unscoped requests with a default tenant should "auto-scope."

        The implied scope is the user's tenant ID.

        """
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'default-tenant-token'
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, ['SUCCESS'])

    def test_unscoped_token(self):
        """Unscoped requests with no default tenant ID should be rejected."""
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'unscoped-token'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_request_invalid_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'invalid-token'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_request_no_token(self):
        req = webob.Request.blank('/')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_request_blank_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = ''
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_memcache(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'valid-token'
        self.middleware._cache = FakeMemcache()
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.middleware._cache.set_value, None)

    def test_memcache_set_invalid(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'invalid-token'
        self.middleware._cache = FakeMemcache()
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.middleware._cache.set_value, "invalid")

    def test_memcache_set_expired(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'valid-token'
        self.middleware._cache = FakeMemcache()
        expired = datetime.datetime.now() - datetime.timedelta(minutes=1)
        self.middleware._cache.token_expiration = float(expired.strftime("%s"))
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(len(self.middleware._cache.set_value), 2)

    def test_nomemcache(self):
        self.disable_module('memcache')

        conf = {
            'admin_token': 'admin_token1',
            'auth_host': 'keystone.example.com',
            'auth_port': 1234,
            'memcache_servers': 'localhost:11211',
        }

        auth_token.AuthProtocol(FakeApp(), conf)


if __name__ == '__main__':
    import unittest
    unittest.main()
