# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

import nose
import webob

try:
    # NOTE(chmou): We don't want to force to have swift installed for
    # unit test so we skip it we have an ImportError.
    from keystone.middleware import swift_auth
    skip = False
except ImportError:
    skip = True


class FakeApp(object):
    def __init__(self, status_headers_body_iter=None, acl=None, sync_key=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {}, '')])
        self.acl = acl
        self.sync_key = sync_key

    def __call__(self, env, start_response):
        self.calls += 1
        self.request = webob.Request.blank('', environ=env)
        if self.acl:
            self.request.acl = self.acl
        if self.sync_key:
            self.request.environ['swift_sync_key'] = self.sync_key
        if 'swift.authorize' in env:
            resp = env['swift.authorize'](self.request)
            if resp:
                return resp(env, start_response)
        status, headers, body = self.status_headers_body_iter.next()
        return webob.Response(status=status, headers=headers,
                              body=body)(env, start_response)


class FakeConn(object):
    def __init__(self, status_headers_body_iter=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {}, '')])

    def request(self, method, path, headers):
        self.calls += 1
        self.request_path = path
        self.status, self.headers, self.body = \
            self.status_headers_body_iter.next()
        self.status, self.reason = self.status.split(' ', 1)
        self.status = int(self.status)

    def getresponse(self):
        return self

    def read(self):
        body = self.body
        self.body = ''
        return body


class SwiftAuth(unittest.TestCase):
    def setUp(self):
        if skip:
            raise nose.SkipTest('no swift detected')
        self.auth = swift_auth
        self.test_auth = self.auth.filter_factory({})(FakeApp())

    def _make_request(self, path, **kwargs):
        req = webob.Request.blank(path, **kwargs)
        return req

    def test_identity_status_denied(self):
        env = {'HTTP_X_IDENTITY_STATUS': 'Denied'}
        req = self._make_request('/v1/AUTH_acct')
        req.environ.update(env)
        resp = req.get_response(self.test_auth)
        self.assertEquals(resp.status_int, 401)

    def test_auth_deny_non_reseller_prefix(self):
        req = self._make_request('/v1/BLAH_account',
                                 headers={'X-Auth-Token': 'BLAH_t'})
        resp = req.get_response(self.test_auth)
        self.assertEquals(resp.status_int, 401)
        self.assertEquals(resp.environ['swift.authorize'],
                          self.test_auth.denied_response)

    def test_auth_deny_token_not_for_account(self):
        env = {'HTTP_X_IDENTITY_STATUS': 'Confirmed',
               'HTTP_X_ROLE': 'AUTH_acct',
               'HTTP_X_TENANT_ID': '1',
               'HTTP_X_TENANT_NAME': 'acct',
               'HTTP_X_USER': 'usr'}
        req = self._make_request('/v1/AUTH_1')
        req.environ.update(env)
        resp = req.get_response(self.test_auth)
        self.assertEquals(resp.status_int, 403)

    #NOTE(chmou): This should fail when we are going to add anonymous
    #access back.
    def test_default_forbidden(self):
        env = {'HTTP_X_IDENTITY_STATUS': 'Confirmed',
               'HTTP_X_USER': 'usr',
               'HTTP_X_TENANT_ID': '1',
               'HTTP_X_TENANT_NAME': 'acct',
               'HTTP_X_ROLE': ''}
        req = self._make_request('/v1/AUTH_acct')
        req.environ.update(env)
        resp = req.get_response(self.test_auth)
        self.assertEquals(resp.status_int, 403)

    def test_operator_roles(self):
        env = {'HTTP_X_IDENTITY_STATUS': 'Confirmed',
               'HTTP_X_USER': 'usr',
               'HTTP_X_TENANT_ID': '1',
               'HTTP_X_TENANT_NAME': 'acct',
               'HTTP_X_ROLE': 'owner'}
        filter_factory = self.auth.filter_factory({'operator_roles': 'owner'})
        self.test_auth = filter_factory(FakeApp())
        req = self._make_request('/v1/AUTH_1')
        req.environ.update(env)
        resp = req.get_response(self.test_auth)
        self.assertEquals(resp.status_int, 404)
        self.assertTrue('swift.authorize' in resp.environ)

    def test_authorize_acl_referrer_access(self):
        env = {'keystone.identity': {'roles': ['acct'],
                                     'tenant': ('1', 'acct'),
                                     'user': 'usr'}}

        # 401 without referrer
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        resp = self.test_auth.authorize(req)
        self.assertEquals(resp.status_int, 401)

        # NOTE(chmou) This should be rewritten when we get proper anonymous
        # container access support.
        # Authorize when the ACL allow reading and container listings.
        req = self._make_request('/v1/AUTH_1/c')
        req.acl = '.r:*,.rlistings'
        req.environ.update(env)
        self.assertEquals(self.test_auth.authorize(req), None)

        # 401 when container listing is not allowed.
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        req.acl = '.r:*'
        resp = self.test_auth.authorize(req)
        self.assertEquals(resp.status_int, 401)

        # 401 with a url acl when not coming from there.
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        req.acl = '.r:.example.com,.rlistings'
        resp = self.test_auth.authorize(req)
        self.assertEquals(resp.status_int, 401)

        # Authorize with the right referrer acl and the right url referrer.
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        req.referer = 'http://www.example.com/index.html'
        req.acl = '.r:.example.com,.rlistings'
        self.assertEquals(self.test_auth.authorize(req), None)

    def test_acl_tenant(self):
        env = {'keystone.identity': {'roles': ['allowme'],
                                     'tenant': ('1', 'acct'),
                                     'user': 'usr'}}
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        req.acl = 'allowme'
        self.assertEquals(self.test_auth.authorize(req), None)

    def test_acl_tenant_user(self):
        env = {'keystone.identity': {'roles': [''],
                                     'tenant': ('1', 'acct'),
                                     'user': 'usr'}}
        req = self._make_request('/v1/AUTH_1/c')
        req.environ.update(env)
        req.acl = '1:usr'
        self.assertEquals(self.test_auth.authorize(req), None)


if __name__ == '__main__':
    unittest.main()
