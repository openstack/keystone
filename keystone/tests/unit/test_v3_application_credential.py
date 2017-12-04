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
from testtools import matchers
import uuid

from six.moves import http_client

from keystone.common import provider_api
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs
MEMBER_PATH_FMT = '/users/%(user_id)s/application_credentials/%(app_cred_id)s'


class ApplicationCredentialTestCase(test_v3.RestfulTestCase):
    """Test CRUD operations for application credentials."""

    def config_overrides(self):
        super(ApplicationCredentialTestCase, self).config_overrides()
        self.config_fixture.config(group='auth',
                                   methods='password,application_credential')

    def _app_cred_body(self, roles=None, name=None, expires=None, secret=None):
        name = name or uuid.uuid4().hex
        description = 'Credential for backups'
        app_cred_data = {
            'name': name,
            'description': description
        }
        if roles:
            app_cred_data['roles'] = roles
        if expires:
            app_cred_data['expires_at'] = expires
        if secret:
            app_cred_data['secret'] = secret
        return {'application_credential': app_cred_data}

    def test_create_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)
        # Create operation returns the secret
        self.assertIn('secret', resp.json['application_credential'])
        # But not the stored hash
        self.assertNotIn('secret_hash', resp.json['application_credential'])

    def test_create_application_credential_with_secret(self):
        secret = 'supersecuresecret'
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles, secret=secret)
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)
        self.assertEqual(secret, resp.json['application_credential']['secret'])

    def test_create_application_credential_roles_from_token(self):
        app_cred_body = self._app_cred_body()
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)
        self.assertThat(resp.json['application_credential']['roles'],
                        matchers.HasLength(1))
        self.assertEqual(resp.json['application_credential']['roles'][0]['id'],
                         self.role_id)

    def test_create_application_credential_wrong_user(self):
        wrong_user = unit.create_user(PROVIDERS.identity_api,
                                      test_v3.DEFAULT_DOMAIN_ID)
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        self.post('/users/%s/application_credentials' % wrong_user['id'],
                  body=app_cred_body,
                  expected_status=http_client.FORBIDDEN)

    def test_create_application_credential_bad_role(self):
        roles = [{'id': uuid.uuid4().hex}]
        app_cred_body = self._app_cred_body(roles=roles)
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.BAD_REQUEST)

    def test_create_application_credential_with_expiration(self):
        roles = [{'id': self.role_id}]
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        app_cred_body = self._app_cred_body(roles=roles, expires=expires)
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.CREATED)

    def test_create_application_credential_invalid_expiration_fmt(self):
        roles = [{'id': self.role_id}]
        expires = 'next tuesday'
        app_cred_body = self._app_cred_body(roles=roles, expires=expires)
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.BAD_REQUEST)

    def test_create_application_credential_already_expired(self):
        roles = [{'id': self.role_id}]
        expires = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        app_cred_body = self._app_cred_body(roles=roles, expires=expires)
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.BAD_REQUEST)

    def test_create_application_credential_with_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body_1 = self._app_cred_body(roles=roles)
        app_cred_1 = self.post(
            '/users/%s/application_credentials' % self.user_id,
            body=app_cred_body_1,
            expected_status=http_client.CREATED)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_1.json['application_credential']['id'],
            secret=app_cred_1.json['application_credential']['secret'])
        token_data = self.v3_create_token(auth_data,
                                          expected_status=http_client.CREATED)
        app_cred_body_2 = self._app_cred_body(roles=roles)
        self.post(
            path='/users/%s/application_credentials' % self.user_id,
            body=app_cred_body_2,
            token=token_data.headers['x-subject-token'],
            expected_status=http_client.FORBIDDEN)

    def test_create_application_credential_allow_recursion(self):
        roles = [{'id': self.role_id}]
        app_cred_body_1 = self._app_cred_body(roles=roles)
        app_cred_body_1['application_credential']['unrestricted'] = True
        app_cred_1 = self.post(
            '/users/%s/application_credentials' % self.user_id,
            body=app_cred_body_1,
            expected_status=http_client.CREATED)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred_1.json['application_credential']['id'],
            secret=app_cred_1.json['application_credential']['secret'])
        token_data = self.v3_create_token(auth_data,
                                          expected_status=http_client.CREATED)
        app_cred_body_2 = self._app_cred_body(roles=roles)
        self.post(
            path='/users/%s/application_credentials' % self.user_id,
            body=app_cred_body_2,
            token=token_data.headers['x-subject-token'],
            expected_status=http_client.CREATED)

    def test_list_application_credentials(self):
        resp = self.get('/users/%s/application_credentials' % self.user_id,
                        expected_status=http_client.OK)
        self.assertEqual([], resp.json['application_credentials'])
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.CREATED)
        resp = self.get('/users/%s/application_credentials' % self.user_id,
                        expected_status=http_client.OK)
        self.assertEqual(1, len(resp.json['application_credentials']))
        self.assertNotIn('secret', resp.json['application_credentials'][0])
        self.assertNotIn('secret_hash',
                         resp.json['application_credentials'][0])
        app_cred_body['application_credential']['name'] = 'two'
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.CREATED)
        resp = self.get('/users/%s/application_credentials' % self.user_id,
                        expected_status=http_client.OK)
        self.assertEqual(2, len(resp.json['application_credentials']))
        for ac in resp.json['application_credentials']:
            self.assertNotIn('secret', ac)
            self.assertNotIn('secret_hash', ac)

    def test_list_application_credentials_by_name(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        name = app_cred_body['application_credential']['name']
        search_path = ('/users/%(user_id)s/application_credentials?'
                       'name=%(name)s') % {'user_id': self.user_id,
                                           'name': name}
        resp = self.get(search_path, expected_status=http_client.OK)
        self.assertEqual([], resp.json['application_credentials'])
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.CREATED)
        resp = self.get(search_path, expected_status=http_client.OK)
        self.assertEqual(1, len(resp.json['application_credentials']))
        self.assertNotIn('secret', resp.json['application_credentials'][0])
        self.assertNotIn('secret_hash',
                         resp.json['application_credentials'][0])
        app_cred_body['application_credential']['name'] = 'two'
        self.post('/users/%s/application_credentials' % self.user_id,
                  body=app_cred_body,
                  expected_status=http_client.CREATED)
        resp = self.get(search_path, expected_status=http_client.OK)
        self.assertEqual(1, len(resp.json['application_credentials']))
        self.assertEqual(resp.json['application_credentials'][0]['name'], name)

    def test_get_head_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)

        app_cred_id = resp.json['application_credential']['id']
        self.head(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                     'app_cred_id': app_cred_id},
                  expected_status=http_client.OK)
        expected_response = resp.json
        expected_response['application_credential'].pop('secret')
        resp = self.get(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                           'app_cred_id': app_cred_id},
                        expected_status=http_client.OK)
        self.assertDictEqual(resp.json, expected_response)

    def test_get_head_application_credential_not_found(self):
        self.head(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                     'app_cred_id': uuid.uuid4().hex},
                  expected_status=http_client.NOT_FOUND)
        self.get(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                    'app_cred_id': uuid.uuid4().hex},
                 expected_status=http_client.NOT_FOUND)

    def test_delete_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)
        app_cred_id = resp.json['application_credential']['id']
        self.delete(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                       'app_cred_id': app_cred_id},
                    expected_status=http_client.NO_CONTENT)

    def test_delete_application_credential_not_found(self):
        self.delete(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                       'app_cred_id': uuid.uuid4().hex},
                    expected_status=http_client.NOT_FOUND)

    def test_delete_application_credential_with_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        app_cred = self.post(
            '/users/%s/application_credentials' % self.user_id,
            body=app_cred_body,
            expected_status=http_client.CREATED)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred.json['application_credential']['id'],
            secret=app_cred.json['application_credential']['secret'])
        token_data = self.v3_create_token(auth_data,
                                          expected_status=http_client.CREATED)
        self.delete(
            path=MEMBER_PATH_FMT % {
                'user_id': self.user_id,
                'app_cred_id': app_cred.json['application_credential']['id']},
            token=token_data.headers['x-subject-token'],
            expected_status=http_client.FORBIDDEN)

    def test_delete_application_credential_allow_recursion(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        app_cred_body['application_credential']['unrestricted'] = True
        app_cred = self.post(
            '/users/%s/application_credentials' % self.user_id,
            body=app_cred_body,
            expected_status=http_client.CREATED)
        auth_data = self.build_authentication_request(
            app_cred_id=app_cred.json['application_credential']['id'],
            secret=app_cred.json['application_credential']['secret'])
        token_data = self.v3_create_token(auth_data,
                                          expected_status=http_client.CREATED)
        self.delete(
            path=MEMBER_PATH_FMT % {
                'user_id': self.user_id,
                'app_cred_id': app_cred.json['application_credential']['id']},
            token=token_data.headers['x-subject-token'],
            expected_status=http_client.NO_CONTENT)

    def test_update_application_credential(self):
        roles = [{'id': self.role_id}]
        app_cred_body = self._app_cred_body(roles=roles)
        resp = self.post('/users/%s/application_credentials' % self.user_id,
                         body=app_cred_body,
                         expected_status=http_client.CREATED)
        # Application credentials are immutable
        app_cred_body['application_credential']['description'] = "New Things"
        app_cred_id = resp.json['application_credential']['id']
        self.patch(MEMBER_PATH_FMT % {'user_id': self.user_id,
                                      'app_cred_id': app_cred_id},
                   body=app_cred_body,
                   expected_status=http_client.NOT_FOUND)
