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

import datetime
import iso8601
import os
import string
import tempfile

import webob

from keystone.common import cms
from keystone.common import utils
from keystone.middleware import auth_token
from keystone.openstack.common import jsonutils
from keystone.openstack.common import timeutils
from keystone import test


CERTDIR = test.rootdir("examples/pki/certs")
KEYDIR = test.rootdir("examples/pki/private")
CMSDIR = test.rootdir("examples/pki/cms")
SIGNING_CERT = os.path.join(CERTDIR, 'signing_cert.pem')
SIGNING_KEY = os.path.join(KEYDIR, 'signing_key.pem')
CA = os.path.join(CERTDIR, 'ca.pem')

REVOCATION_LIST = None
REVOKED_TOKEN = None
REVOKED_TOKEN_HASH = None
SIGNED_REVOCATION_LIST = None
SIGNED_TOKEN_SCOPED = None
SIGNED_TOKEN_UNSCOPED = None
SIGNED_TOKEN_SCOPED_KEY = None
SIGNED_TOKEN_UNSCOPED_KEY = None

VALID_SIGNED_REVOCATION_LIST = None

UUID_TOKEN_DEFAULT = "ec6c0710ec2f471498484c1b53ab4f9d"
UUID_TOKEN_NO_SERVICE_CATALOG = '8286720fbe4941e69fa8241723bb02df'
UUID_TOKEN_UNSCOPED = '731f903721c14827be7b2dc912af7776'
VALID_DIABLO_TOKEN = 'b0cf19b55dbb4f20a6ee18e6c6cf1726'

INVALID_SIGNED_TOKEN = string.replace(
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
0000000000000000000000000000000000000000000000000000000000000000
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
5555555555555555555555555555555555555555555555555555555555555555
6666666666666666666666666666666666666666666666666666666666666666
7777777777777777777777777777777777777777777777777777777777777777
8888888888888888888888888888888888888888888888888888888888888888
9999999999999999999999999999999999999999999999999999999999999999
0000000000000000000000000000000000000000000000000000000000000000
xg==""", "\n", "")

# JSON responses keyed by token ID
TOKEN_RESPONSES = {
    UUID_TOKEN_DEFAULT: {
        'access': {
            'token': {
                'id': UUID_TOKEN_DEFAULT,
                'expires': '2999-01-01T00:00:10Z',
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
            'serviceCatalog': {}
        },
    },
    VALID_DIABLO_TOKEN: {
        'access': {
            'token': {
                'id': VALID_DIABLO_TOKEN,
                'expires': '2999-01-01T00:00:10',
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
    UUID_TOKEN_UNSCOPED: {
        'access': {
            'token': {
                'id': UUID_TOKEN_UNSCOPED,
                'expires': '2999-01-01T00:00:10Z',
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
    UUID_TOKEN_NO_SERVICE_CATALOG: {
        'access': {
            'token': {
                'id': 'valid-token',
                'expires': '2999-01-01T00:00:10Z',
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
            }
        },
    },
}

FAKE_RESPONSE_STACK = []


# The data for these tests are signed using openssl and are stored in files
# in the signing subdirectory.  In order to keep the values consistent between
# the tests and the signed documents, we read them in for use in the tests.
def setUpModule(self):
    signing_path = CMSDIR
    with open(os.path.join(signing_path, 'auth_token_scoped.pem')) as f:
        self.SIGNED_TOKEN_SCOPED = cms.cms_to_token(f.read())
    with open(os.path.join(signing_path, 'auth_token_unscoped.pem')) as f:
        self.SIGNED_TOKEN_UNSCOPED = cms.cms_to_token(f.read())
    with open(os.path.join(signing_path, 'auth_token_revoked.pem')) as f:
        self.REVOKED_TOKEN = cms.cms_to_token(f.read())
    self.REVOKED_TOKEN_HASH = utils.hash_signed_token(self.REVOKED_TOKEN)
    with open(os.path.join(signing_path, 'revocation_list.json')) as f:
        self.REVOCATION_LIST = jsonutils.loads(f.read())
    with open(os.path.join(signing_path, 'revocation_list.pem')) as f:
        self.VALID_SIGNED_REVOCATION_LIST = jsonutils.dumps(
            {'signed': f.read()})
    self.SIGNED_TOKEN_SCOPED_KEY =\
        cms.cms_hash_token(self.SIGNED_TOKEN_SCOPED)
    self.SIGNED_TOKEN_UNSCOPED_KEY =\
        cms.cms_hash_token(self.SIGNED_TOKEN_UNSCOPED)

    self.TOKEN_RESPONSES[self.SIGNED_TOKEN_SCOPED_KEY] = {
        'access': {
            'token': {
                'id': self.SIGNED_TOKEN_SCOPED_KEY,
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
    }

    self.TOKEN_RESPONSES[SIGNED_TOKEN_UNSCOPED_KEY] = {
        'access': {
            'token': {
                'id': SIGNED_TOKEN_UNSCOPED_KEY,
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


class FakeMemcache(object):
    def __init__(self):
        self.set_key = None
        self.set_value = None
        self.token_expiration = None

    def get(self, key):
        data = TOKEN_RESPONSES[SIGNED_TOKEN_SCOPED_KEY].copy()
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


class FakeStackHTTPConnection(object):

    def __init__(self, *args, **kwargs):
        pass

    def getresponse(self):
        if len(FAKE_RESPONSE_STACK):
            return FAKE_RESPONSE_STACK.pop()
        return FakeHTTPResponse(500, jsonutils.dumps('UNEXPECTED RESPONSE'))

    def request(self, *_args, **_kwargs):
        pass

    def close(self):
        pass


class FakeHTTPConnection(object):

    last_requested_url = ''

    def __init__(self, *args):
        self.send_valid_revocation_list = True

    def request(self, method, path, **kwargs):
        """Fakes out several http responses.

        If a POST request is made, we assume the calling code is trying
        to get a new admin token.

        If a GET request is made to validate a token, return success
        if the token is 'token1'. If a different token is provided, return
        a 404, indicating an unknown (therefore unauthorized) token.

        """
        FakeHTTPConnection.last_requested_url = path
        if method == 'POST':
            status = 200
            body = jsonutils.dumps({
                'access': {
                    'token': {'id': 'admin_token2'},
                },
            })

        else:
            token_id = path.rsplit('/', 1)[1]
            if token_id in TOKEN_RESPONSES.keys():
                status = 200
                body = jsonutils.dumps(TOKEN_RESPONSES[token_id])
            elif token_id == "revoked":
                status = 200
                body = SIGNED_REVOCATION_LIST
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
            'auth_admin_prefix': '/testadmin',
            'signing_dir': CERTDIR,
        }

        self.middleware = auth_token.AuthProtocol(FakeApp(expected_env), conf)
        self.middleware.http_client_class = FakeHTTPConnection
        self.middleware._iso8601 = iso8601

        self.response_status = None
        self.response_headers = None
        self.middleware.revoked_file_name = tempfile.mkstemp()[1]
        cache_timeout = datetime.timedelta(days=1)
        self.middleware.token_revocation_list_cache_timeout = cache_timeout
        self.middleware.token_revocation_list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})

        signed_list = 'SIGNED_REVOCATION_LIST'
        valid_signed_list = 'VALID_SIGNED_REVOCATION_LIST'
        globals()[signed_list] = globals()[valid_signed_list]

        super(BaseAuthTokenMiddlewareTest, self).setUp()

    def tearDown(self):
        super(BaseAuthTokenMiddlewareTest, self).tearDown()
        try:
            os.remove(self.middleware.revoked_file_name)
        except OSError:
            pass

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)


class StackResponseAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest):
    """Auth Token middleware test setup that allows the tests to define
    a stack of responses to HTTP requests in the test and get those
    responses back in sequence for testing.

    Example::

        resp1 = FakeHTTPResponse(401, jsonutils.dumps(''))
        resp2 = FakeHTTPResponse(200, jsonutils.dumps({
            'access': {
                'token': {'id': 'admin_token2'},
            },
            })
        FAKE_RESPONSE_STACK.append(resp1)
        FAKE_RESPONSE_STACK.append(resp2)

        ... do your testing code here ...

    """

    def setUp(self, expected_env=None):
        super(StackResponseAuthTokenMiddlewareTest, self).setUp(expected_env)
        self.middleware.http_client_class = FakeStackHTTPConnection

    def test_fetch_revocation_list_with_expire(self):
        # first response to revocation list should return 401 Unauthorized
        # to pretend to be an expired token
        resp1 = FakeHTTPResponse(200, jsonutils.dumps({
            'access': {
                'token': {'id': 'admin_token2'},
            },
        }))
        resp2 = FakeHTTPResponse(401, jsonutils.dumps(''))
        resp3 = FakeHTTPResponse(200, jsonutils.dumps({
            'access': {
                'token': {'id': 'admin_token2'},
            },
        }))
        resp4 = FakeHTTPResponse(200, SIGNED_REVOCATION_LIST)

        # first get_admin_token() call
        FAKE_RESPONSE_STACK.append(resp1)
        # request revocation list, get "unauthorized" due to simulated expired
        # token
        FAKE_RESPONSE_STACK.append(resp2)
        # request a new admin_token
        FAKE_RESPONSE_STACK.append(resp3)
        # request revocation list, get the revocation list properly
        FAKE_RESPONSE_STACK.append(resp4)

        fetched_list = jsonutils.loads(self.middleware.fetch_revocation_list())
        self.assertEqual(fetched_list, REVOCATION_LIST)


class DiabloAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest):
    """Auth Token middleware should understand Diablo keystone responses."""
    def setUp(self):
        # pre-diablo only had Tenant ID, which was also the Name
        expected_env = {
            'HTTP_X_TENANT_ID': 'tenant_id1',
            'HTTP_X_TENANT_NAME': 'tenant_id1',
            # now deprecated (diablo-compat)
            'HTTP_X_TENANT': 'tenant_id1',
        }
        super(DiabloAuthTokenMiddlewareTest, self).setUp(expected_env)

    def test_valid_diablo_response(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = VALID_DIABLO_TOKEN
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)


class AuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest):
    def assert_valid_request_200(self, token):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertTrue(req.headers.get('X-Service-Catalog'))
        self.assertEqual(body, ['SUCCESS'])

    def test_valid_uuid_request(self):
        self.assert_valid_request_200(UUID_TOKEN_DEFAULT)
        self.assertEqual("/testadmin/v2.0/tokens/%s" % UUID_TOKEN_DEFAULT,
                         FakeHTTPConnection.last_requested_url)

    def test_valid_signed_request(self):
        FakeHTTPConnection.last_requested_url = ''
        self.assert_valid_request_200(SIGNED_TOKEN_SCOPED)
        self.assertEqual(self.middleware.conf['auth_admin_prefix'],
                         "/testadmin")
        #ensure that signed requests do not generate HTTP traffic
        self.assertEqual('', FakeHTTPConnection.last_requested_url)

    def assert_unscoped_default_tenant_auto_scopes(self, token):
        """Unscoped requests with a default tenant should "auto-scope."

        The implied scope is the user's tenant ID.

        """
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, ['SUCCESS'])

    def test_default_tenant_uuid_token(self):
        self.assert_unscoped_default_tenant_auto_scopes(UUID_TOKEN_DEFAULT)

    def test_default_tenant_signed_token(self):
        self.assert_unscoped_default_tenant_auto_scopes(SIGNED_TOKEN_SCOPED)

    def assert_unscoped_token_receives_401(self, token):
        """Unscoped requests with no default tenant ID should be rejected."""
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_unscoped_uuid_token_receives_401(self):
        self.assert_unscoped_token_receives_401(UUID_TOKEN_UNSCOPED)

    def test_unscoped_pki_token_receives_401(self):
        self.assert_unscoped_token_receives_401(SIGNED_TOKEN_UNSCOPED)

    def test_revoked_token_receives_401(self):
        self.middleware.token_revocation_list = self.get_revocation_list_json()
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = REVOKED_TOKEN
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)

    def get_revocation_list_json(self, token_ids=None):
        if token_ids is None:
            token_ids = [REVOKED_TOKEN_HASH]
        revocation_list = {'revoked': [{'id': x, 'expires': timeutils.utcnow()}
                                       for x in token_ids]}
        return jsonutils.dumps(revocation_list)

    def test_is_signed_token_revoked_returns_false(self):
        #explicitly setting an empty revocation list here to document intent
        self.middleware.token_revocation_list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})
        result = self.middleware.is_signed_token_revoked(REVOKED_TOKEN)
        self.assertFalse(result)

    def test_is_signed_token_revoked_returns_true(self):
        self.middleware.token_revocation_list = self.get_revocation_list_json()
        result = self.middleware.is_signed_token_revoked(REVOKED_TOKEN)
        self.assertTrue(result)

    def test_verify_signed_token_raises_exception_for_revoked_token(self):
        self.middleware.token_revocation_list = self.get_revocation_list_json()
        with self.assertRaises(auth_token.InvalidUserToken):
            self.middleware.verify_signed_token(REVOKED_TOKEN)

    def test_verify_signed_token_succeeds_for_unrevoked_token(self):
        self.middleware.token_revocation_list = self.get_revocation_list_json()
        self.middleware.verify_signed_token(SIGNED_TOKEN_SCOPED)

    def test_get_token_revocation_list_fetched_time_returns_min(self):
        self.middleware.token_revocation_list_fetched_time = None
        self.middleware.revoked_file_name = ''
        self.assertEqual(self.middleware.token_revocation_list_fetched_time,
                         datetime.datetime.min)

    def test_get_token_revocation_list_fetched_time_returns_mtime(self):
        self.middleware.token_revocation_list_fetched_time = None
        mtime = os.path.getmtime(self.middleware.revoked_file_name)
        fetched_time = datetime.datetime.fromtimestamp(mtime)
        self.assertEqual(self.middleware.token_revocation_list_fetched_time,
                         fetched_time)

    def test_get_token_revocation_list_fetched_time_returns_value(self):
        expected = self.middleware._token_revocation_list_fetched_time
        self.assertEqual(self.middleware.token_revocation_list_fetched_time,
                         expected)

    def test_get_revocation_list_returns_fetched_list(self):
        self.middleware.token_revocation_list_fetched_time = None
        os.remove(self.middleware.revoked_file_name)
        self.assertEqual(self.middleware.token_revocation_list,
                         REVOCATION_LIST)

    def test_get_revocation_list_returns_current_list_from_memory(self):
        self.assertEqual(self.middleware.token_revocation_list,
                         self.middleware._token_revocation_list)

    def test_get_revocation_list_returns_current_list_from_disk(self):
        in_memory_list = self.middleware.token_revocation_list
        self.middleware._token_revocation_list = None
        self.assertEqual(self.middleware.token_revocation_list, in_memory_list)

    def test_invalid_revocation_list_raises_service_error(self):
        globals()['SIGNED_REVOCATION_LIST'] = "{}"
        with self.assertRaises(auth_token.ServiceError):
            self.middleware.fetch_revocation_list()

    def test_fetch_revocation_list(self):
        fetched_list = jsonutils.loads(self.middleware.fetch_revocation_list())
        self.assertEqual(fetched_list, REVOCATION_LIST)

    def test_request_invalid_uuid_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'invalid-token'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         'Keystone uri=\'https://keystone.example.com:1234\'')

    def test_request_invalid_signed_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = INVALID_SIGNED_TOKEN
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
        req.headers['X-Auth-Token'] = SIGNED_TOKEN_SCOPED
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
        req.headers['X-Auth-Token'] = SIGNED_TOKEN_SCOPED
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

    def test_request_prevent_service_catalog_injection(self):
        req = webob.Request.blank('/')
        req.headers['X-Service-Catalog'] = '[]'
        req.headers['X-Auth-Token'] = UUID_TOKEN_NO_SERVICE_CATALOG
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertFalse(req.headers.get('X-Service-Catalog'))
        self.assertEqual(body, ['SUCCESS'])

    def test_will_expire_soon(self):
        tenseconds = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=10)
        self.assertTrue(auth_token.will_expire_soon(tenseconds))
        fortyseconds = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=40)
        self.assertFalse(auth_token.will_expire_soon(fortyseconds))
