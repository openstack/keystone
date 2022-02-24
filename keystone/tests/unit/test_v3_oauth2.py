# Copyright 2022 openStack Foundation
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

from base64 import b64encode
from http import client
from oslo_log import log
from oslo_serialization import jsonutils
from unittest import mock
from urllib import parse

from keystone import conf
from keystone import exception
from keystone.tests.unit import test_v3

LOG = log.getLogger(__name__)
CONF = conf.CONF


class FakeUserAppCredListCreateResource(mock.Mock):
    pass


class OAuth2Tests(test_v3.OAuth2RestfulTestCase):
    APP_CRED_CREATE_URL = '/users/%(user_id)s/application_credentials'
    APP_CRED_LIST_URL = '/users/%(user_id)s/application_credentials'
    APP_CRED_DELETE_URL = '/users/%(user_id)s/application_credentials/' \
                          '%(app_cred_id)s'
    APP_CRED_SHOW_URL = '/users/%(user_id)s/application_credentials/' \
                        '%(app_cred_id)s'
    ACCESS_TOKEN_URL = '/OS-OAUTH2/token'

    def setUp(self):
        super(OAuth2Tests, self).setUp()
        log.set_defaults(
            logging_context_format_string='%(asctime)s.%(msecs)03d %('
                                          'color)s%(levelname)s %(name)s [^[['
                                          '01;36m%(request_id)s ^[[00;36m%('
                                          'project_name)s %(user_name)s%('
                                          'color)s] ^[[01;35m%(instance)s%('
                                          'color)s%(message)s^[[00m',
            default_log_levels=log.DEBUG)
        CONF.log_opt_values(LOG, log.DEBUG)
        LOG.debug(f'is_debug_enabled: {log.is_debug_enabled(CONF)}')
        LOG.debug(f'get_default_log_levels: {log.get_default_log_levels()}')

    def _assert_error_resp(self, error_resp, error_msg, error_description):
        resp_keys = (
            'error', 'error_description'
        )
        for key in resp_keys:
            self.assertIsNotNone(error_resp.get(key, None))
        self.assertEqual(error_msg, error_resp.get('error'))
        self.assertEqual(error_description,
                         error_resp.get('error_description'))

    def _create_app_cred(self, user_id, app_cred_name):
        resp = self.post(
            self.APP_CRED_CREATE_URL % {'user_id': user_id},
            body={'application_credential': {'name': app_cred_name}}
        )
        LOG.debug(f'resp: {resp}')
        app_ref = resp.result['application_credential']
        return app_ref

    def _delete_app_cred(self, user_id, app_cred_id):
        resp = self.delete(
            self.APP_CRED_CREATE_URL % {'user_id': user_id,
                                        'app_cred_id': app_cred_id})
        LOG.debug(f'resp: {resp}')

    def _get_access_token(self, app_cred, b64str, headers, data,
                          expected_status):
        if b64str is None:
            client_id = app_cred.get('id')
            client_secret = app_cred.get('secret')
            b64str = b64encode(
                f'{client_id}:{client_secret}'.encode()).decode().strip()
        if headers is None:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {b64str}'
            }
        if data is None:
            data = {
                'grant_type': 'client_credentials'
            }
        data = parse.urlencode(data).encode()
        resp = self.post(
            self.ACCESS_TOKEN_URL,
            headers=headers,
            convert=False,
            body=data,
            expected_status=expected_status)
        return resp


class AccessTokenTests(OAuth2Tests):

    def setUp(self):
        super(AccessTokenTests, self).setUp()

    def _create_access_token(self, client):
        pass

    def _get_access_token_method_not_allowed(self, app_cred,
                                             http_func):
        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        data = {
            'grant_type': 'client_credentials'
        }
        data = parse.urlencode(data).encode()
        resp = http_func(
            self.ACCESS_TOKEN_URL,
            headers=headers,
            convert=False,
            body=data,
            expected_status=client.METHOD_NOT_ALLOWED)
        LOG.debug(f'response: {resp}')
        json_resp = jsonutils.loads(resp.body)
        return json_resp

    def test_get_access_token(self):
        """Test case when an access token can be successfully obtain."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        resp = self._get_access_token(
            app_cred,
            b64str=None,
            headers=None,
            data=None,
            expected_status=client.OK)
        json_resp = jsonutils.loads(resp.body)
        self.assertIn('access_token', json_resp)
        self.assertEqual('Bearer', json_resp['token_type'])
        self.assertEqual(3600, json_resp['expires_in'])

    def test_get_access_token_without_client_auth(self):
        """Test case when there is no client authorization."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        error = 'invalid_client'
        error_description = 'OAuth2.0 client authorization is required.'
        resp = self._get_access_token(app_cred,
                                      b64str=None,
                                      headers=headers,
                                      data=None,
                                      expected_status=client.UNAUTHORIZED)
        self.assertNotEmpty(resp.headers.get("WWW-Authenticate"))
        self.assertEqual('Keystone uri="http://localhost/v3"',
                         resp.headers.get("WWW-Authenticate"))
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_auth_type_is_not_basic(self):
        """Test case when auth_type is not basic."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        client_id = app_cred.get('id')

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (
                   client_id, 'realm', 'nonce', 'path', 'responding')

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Digest {base}'
        }
        error = 'invalid_client'
        error_description = 'OAuth2.0 client authorization type ' \
                            'digest is not supported.'
        resp = self._get_access_token(app_cred,
                                      b64str=None,
                                      headers=headers,
                                      data=None,
                                      expected_status=client.UNAUTHORIZED)
        self.assertNotEmpty(resp.headers.get("WWW-Authenticate"))
        self.assertEqual('Keystone uri="http://localhost/v3"',
                         resp.headers.get("WWW-Authenticate"))
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_without_client_id(self):
        """Test case when there is no client_id."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f':{client_secret}'.encode()).decode().strip()
        error = 'invalid_client'
        error_description = 'OAuth2.0 client authorization is invalid.'
        resp = self._get_access_token(app_cred,
                                      b64str=b64str,
                                      headers=None,
                                      data=None,
                                      expected_status=client.UNAUTHORIZED)
        self.assertNotEmpty(resp.headers.get("WWW-Authenticate"))
        self.assertEqual('Keystone uri="http://localhost/v3"',
                         resp.headers.get("WWW-Authenticate"))
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_without_client_secret(self):
        """Test case when there is no client_secret."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        client_id = app_cred.get('id')
        b64str = b64encode(
            f'{client_id}:'.encode()).decode().strip()
        error = 'invalid_client'
        error_description = 'OAuth2.0 client authorization is invalid.'
        resp = self._get_access_token(app_cred,
                                      b64str=b64str,
                                      headers=None,
                                      data=None,
                                      expected_status=client.UNAUTHORIZED)
        self.assertNotEmpty(resp.headers.get("WWW-Authenticate"))
        self.assertEqual('Keystone uri="http://localhost/v3"',
                         resp.headers.get("WWW-Authenticate"))
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_without_grant_type(self):
        """Test case when there is no grant_type."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        data = {}
        error = 'invalid_request'
        error_description = 'The parameter grant_type is required.'
        resp = self._get_access_token(app_cred,
                                      b64str=None,
                                      headers=None,
                                      data=data,
                                      expected_status=client.BAD_REQUEST)
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_blank_grant_type(self):
        """Test case when grant_type is blank."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        data = {
            'grant_type': ''
        }
        error = 'unsupported_grant_type'
        error_description = 'The parameter grant_type ' \
                            ' is not supported.'
        resp = self._get_access_token(app_cred,
                                      b64str=None,
                                      headers=None,
                                      data=data,
                                      expected_status=client.BAD_REQUEST)
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_grant_type_is_not_client_credentials(self):
        """Test case when grant_type is not client_credentials."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        data = {
            'grant_type': 'not_client_credentials'
        }
        error = 'unsupported_grant_type'
        error_description = 'The parameter grant_type ' \
                            'not_client_credentials is not supported.'
        resp = self._get_access_token(app_cred,
                                      b64str=None,
                                      headers=None,
                                      data=data,
                                      expected_status=client.BAD_REQUEST)
        json_resp = jsonutils.loads(resp.body)
        LOG.debug(f'error: {json_resp.get("error")}')
        LOG.debug(f'error_description: {json_resp.get("error_description")}')
        self.assertEqual(error,
                         json_resp.get('error'))
        self.assertEqual(error_description,
                         json_resp.get('error_description'))

    def test_get_access_token_failed_401(self):
        """Test case when client authentication failed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        error = 'invalid_client'

        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        data = {
            'grant_type': 'client_credentials'
        }
        data = parse.urlencode(data).encode()
        with mock.patch(
                'keystone.api._shared.authentication.'
                'authenticate_for_token') as co_mock:
            co_mock.side_effect = exception.Unauthorized(
                'client is unauthorized')
            resp = self.post(
                self.ACCESS_TOKEN_URL,
                headers=headers,
                convert=False,
                body=data,
                noauth=True,
                expected_status=client.UNAUTHORIZED)
            self.assertNotEmpty(resp.headers.get("WWW-Authenticate"))
            self.assertEqual('Keystone uri="http://localhost/v3"',
                             resp.headers.get("WWW-Authenticate"))
        LOG.debug(f'response: {resp}')
        json_resp = jsonutils.loads(resp.body)
        self.assertEqual(error,
                         json_resp.get('error'))
        LOG.debug(f'error: {json_resp.get("error")}')

    def test_get_access_token_failed_400(self):
        """Test case when the called API is incorrect."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        error = 'invalid_request'
        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        data = {
            'grant_type': 'client_credentials'
        }
        data = parse.urlencode(data).encode()
        with mock.patch(
                'keystone.api._shared.authentication.'
                'authenticate_for_token') as co_mock:
            co_mock.side_effect = exception.ValidationError(
                'Auth method is invalid')
            resp = self.post(
                self.ACCESS_TOKEN_URL,
                headers=headers,
                convert=False,
                body=data,
                noauth=True,
                expected_status=client.BAD_REQUEST)
            LOG.debug(f'response: {resp}')
            json_resp = jsonutils.loads(resp.body)
            self.assertEqual(error,
                             json_resp.get('error'))
            LOG.debug(f'error: {json_resp.get("error")}')

    def test_get_access_token_failed_500_other(self):
        """Test case when unexpected error."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        error = 'other_error'
        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        data = {
            'grant_type': 'client_credentials'
        }
        data = parse.urlencode(data).encode()
        with mock.patch(
                'keystone.api._shared.authentication.'
                'authenticate_for_token') as co_mock:
            co_mock.side_effect = exception.UnexpectedError(
                'unexpected error.')
            resp = self.post(
                self.ACCESS_TOKEN_URL,
                headers=headers,
                convert=False,
                body=data,
                noauth=True,
                expected_status=client.INTERNAL_SERVER_ERROR)

        LOG.debug(f'response: {resp}')
        json_resp = jsonutils.loads(resp.body)
        self.assertEqual(error,
                         json_resp.get('error'))

    def test_get_access_token_failed_500(self):
        """Test case when internal server error."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        error = 'other_error'
        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        data = {
            'grant_type': 'client_credentials'
        }
        data = parse.urlencode(data).encode()
        with mock.patch(
                'keystone.api._shared.authentication.'
                'authenticate_for_token') as co_mock:
            co_mock.side_effect = Exception(
                'Internal server is invalid')
            resp = self.post(
                self.ACCESS_TOKEN_URL,
                headers=headers,
                convert=False,
                body=data,
                noauth=True,
                expected_status=client.INTERNAL_SERVER_ERROR)

        LOG.debug(f'response: {resp}')
        json_resp = jsonutils.loads(resp.body)
        self.assertEqual(error,
                         json_resp.get('error'))

    def test_get_access_token_method_get_not_allowed(self):
        """Test case when the request is get method that is not allowed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        json_resp = self._get_access_token_method_not_allowed(
            app_cred, self.get)
        self.assertEqual('other_error',
                         json_resp.get('error'))
        self.assertEqual('The method is not allowed for the requested URL.',
                         json_resp.get('error_description'))

    def test_get_access_token_method_patch_not_allowed(self):
        """Test case when the request is patch method that is not allowed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        json_resp = self._get_access_token_method_not_allowed(
            app_cred, self.patch)
        self.assertEqual('other_error',
                         json_resp.get('error'))
        self.assertEqual('The method is not allowed for the requested URL.',
                         json_resp.get('error_description'))

    def test_get_access_token_method_put_not_allowed(self):
        """Test case when the request is put method that is not allowed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        json_resp = self._get_access_token_method_not_allowed(
            app_cred, self.put)
        self.assertEqual('other_error',
                         json_resp.get('error'))
        self.assertEqual('The method is not allowed for the requested URL.',
                         json_resp.get('error_description'))

    def test_get_access_token_method_delete_not_allowed(self):
        """Test case when the request is delete method that is not allowed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        json_resp = self._get_access_token_method_not_allowed(
            app_cred, self.delete)
        self.assertEqual('other_error',
                         json_resp.get('error'))
        self.assertEqual('The method is not allowed for the requested URL.',
                         json_resp.get('error_description'))

    def test_get_access_token_method_head_not_allowed(self):
        """Test case when the request is head method that is not allowed."""

        client_name = 'client_name_test'
        app_cred = self._create_app_cred(self.user_id, client_name)
        client_id = app_cred.get('id')
        client_secret = app_cred.get('secret')
        b64str = b64encode(
            f'{client_id}:{client_secret}'.encode()).decode().strip()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {b64str}'
        }
        self.head(
            self.ACCESS_TOKEN_URL,
            headers=headers,
            convert=False,
            expected_status=client.METHOD_NOT_ALLOWED)
