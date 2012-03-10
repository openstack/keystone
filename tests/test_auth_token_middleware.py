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

from keystone.middleware import auth_token
from keystone import test


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
        """Fakes out several http responses

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
            if token_id == 'token1':
                status = 200
                body = json.dumps({
                    'access': {
                        'token': {
                            'id': token_id,
                            'tenant': {
                                'id': 'tenant_id1',
                                'name': 'tenant_name1',
                            },
                        },
                        'user': {
                            'id': 'user_id1',
                            'username': 'user_name1',
                            'roles': [
                                {'name': 'role1'},
                                {'name': 'role2'},
                            ],
                        },
                    },
                })
            else:
                status = 404
                body = ''

        self.resp = FakeHTTPResponse(status, body)

    def getresponse(self):
        return self.resp

    def close(self):
        pass


class AuthTokenMiddlewareTest(test.TestCase):
    def setUp(self):
        super(AuthTokenMiddlewareTest, self).setUp()
        conf = {
            'admin_token': 'admin_token1',
            'auth_host': 'keystone.example.com',
            'auth_port': 1234,
        }

        # This object represents a wsgi app that would be wrapped with
        # the auth_token middleware
        def fake_app(env, start_response):
            expected_env = {
                'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                'HTTP_X_TENANT_ID': 'tenant_id1',
                'HTTP_X_TENANT_NAME': 'tenant_name1',
                'HTTP_X_USER_ID': 'user_id1',
                'HTTP_X_USER_NAME': 'user_name1',
                'HTTP_X_ROLES': 'role1,role2',
                'HTTP_X_USER': 'user_name1',
                'HTTP_X_TENANT': 'tenant_name1',
                'HTTP_X_ROLE': 'role1,role2',
            }
            for k, v in expected_env.items():
                self.assertEqual(env[k], v)

            resp = webob.Response()
            resp.body = 'SUCCESS'
            return resp(env, start_response)

        self.middleware = auth_token.AuthProtocol(fake_app, conf)
        self.middleware.http_client_class = FakeHTTPConnection

        self.response_status = None
        self.response_headers = None

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    def test_request(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'token1'
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, ['SUCCESS'])

    def test_request_invalid_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'token2'
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
