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
import http.client
import uuid

from oslo_utils import timeutils
from testtools import matchers

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
        super().config_overrides()
        self.config_fixture.config(
            group='auth', methods='password,application_credential'
        )

    def _app_cred_body(
        self,
        roles=None,
        name=None,
        expires=None,
        secret=None,
        access_rules=None,
    ):
        name = name or uuid.uuid4().hex
        description = 'Credential for backups'
        app_cred_data = {'name': name, 'description': description}
        if roles:
            app_cred_data['roles'] = roles
        if expires:
            app_cred_data['expires_at'] = expires
        if secret:
            app_cred_data['secret'] = secret
        if access_rules is not None:
            app_cred_data['access_rules'] = access_rules
        return {'application_credential': app_cred_data}

    def test_create_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
        # Create operation returns the secret
        self.assertIn('secret', resp.json['application_credential'])
        # But not the stored hash
        self.assertNotIn('secret_hash', resp.json['application_credential'])

    def test_create_application_credential_implied_role(self):
        """Test creation with implied roles.

        Verify that implied roles are respected when user creates new
        application credential specifying a role that implies some other
        role
        """
        implied_role = unit.new_role_ref(name='implied')
        implied_role_id = implied_role['id']
        PROVIDERS.role_api.create_role(implied_role_id, implied_role)
        PROVIDERS.role_api.create_implied_role(self.role_id, implied_role_id)
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
        # Create operation returns the secret
        self.assertIn('secret', resp.json['application_credential'])
        # But not the stored hash
        self.assertNotIn('secret_hash', resp.json['application_credential'])
        # Ensure implied role is also granted
        self.assertIn(
            implied_role_id,
            [x['id'] for x in resp.json["application_credential"]["roles"]],
        )

    def test_create_application_credential_with_secret(self):
        with self.test_client() as c:
            secret = 'supersecuresecret'
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles, secret=secret)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
        self.assertEqual(secret, resp.json['application_credential']['secret'])

    def test_create_application_credential_roles_from_token(self):
        with self.test_client() as c:
            app_cred_body = self._app_cred_body()
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            self.assertThat(
                resp.json['application_credential']['roles'],
                matchers.HasLength(1),
            )
            self.assertEqual(
                resp.json['application_credential']['roles'][0]['id'],
                self.role_id,
            )

    def test_create_application_credential_wrong_user(self):
        wrong_user = unit.create_user(
            PROVIDERS.identity_api, test_v3.DEFAULT_DOMAIN_ID
        )
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            c.post(
                '/v3/users/{}/application_credentials'.format(
                    wrong_user['id']
                ),
                json=app_cred_body,
                expected_status_code=http.client.FORBIDDEN,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_bad_role(self):
        with self.test_client() as c:
            roles = [{'id': uuid.uuid4().hex}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.BAD_REQUEST,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_with_expiration(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            expires = timeutils.utcnow() + datetime.timedelta(days=365)
            expires = str(expires)
            app_cred_body = self._app_cred_body(roles=roles, expires=expires)
            token = self.get_scoped_token()
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_invalid_expiration_fmt(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            expires = 'next tuesday'
            app_cred_body = self._app_cred_body(roles=roles, expires=expires)
            token = self.get_scoped_token()
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.BAD_REQUEST,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_already_expired(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            expires = timeutils.utcnow() - datetime.timedelta(hours=1)
            app_cred_body = self._app_cred_body(roles=roles, expires=expires)
            token = self.get_scoped_token()
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.BAD_REQUEST,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_with_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body_1 = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            app_cred_1 = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body_1,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            auth_data = self.build_authentication_request(
                app_cred_id=app_cred_1.json['application_credential']['id'],
                secret=app_cred_1.json['application_credential']['secret'],
            )
            token_data = self.v3_create_token(
                auth_data, expected_status=http.client.CREATED
            )
            app_cred_body_2 = self._app_cred_body(roles=roles)
            token = token_data.headers['x-subject-token']
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body_2,
                expected_status_code=http.client.FORBIDDEN,
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_with_trust(self):
        second_role = unit.new_role_ref(name='reader')
        PROVIDERS.role_api.create_role(second_role['id'], second_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, second_role['id']
        )
        with self.test_client() as c:
            pw_token = self.get_scoped_token()
            # create a self-trust - only the roles are important for this test
            trust_ref = unit.new_trust_ref(
                trustor_user_id=self.user_id,
                trustee_user_id=self.user_id,
                project_id=self.project_id,
                role_ids=[second_role['id']],
            )
            resp = c.post(
                '/v3/OS-TRUST/trusts',
                headers={'X-Auth-Token': pw_token},
                json={'trust': trust_ref},
            )
            trust_id = resp.json['trust']['id']
            trust_auth = self.build_authentication_request(
                user_id=self.user_id,
                password=self.user['password'],
                trust_id=trust_id,
            )
            trust_token = self.v3_create_token(trust_auth).headers[
                'X-Subject-Token'
            ]
            app_cred = self._app_cred_body(roles=[{'id': self.role_id}])
            # only the roles from the trust token should be allowed, even if
            # the user has the role assigned on the project
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': trust_token},
                json=app_cred,
                expected_status_code=http.client.BAD_REQUEST,
            )

    def test_create_application_credential_allow_recursion(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body_1 = self._app_cred_body(roles=roles)
            app_cred_body_1['application_credential']['unrestricted'] = True
            token = self.get_scoped_token()
            app_cred_1 = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body_1,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            auth_data = self.build_authentication_request(
                app_cred_id=app_cred_1.json['application_credential']['id'],
                secret=app_cred_1.json['application_credential']['secret'],
            )
            token_data = self.v3_create_token(
                auth_data, expected_status=http.client.CREATED
            )
            app_cred_body_2 = self._app_cred_body(roles=roles)
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body_2,
                expected_status_code=http.client.CREATED,
                headers={
                    'x-Auth-Token': token_data.headers['x-subject-token']
                },
            )

    def test_create_application_credential_with_access_rules(self):
        roles = [{'id': self.role_id}]
        access_rules = [
            {'path': '/v3/projects', 'method': 'POST', 'service': 'identity'}
        ]
        app_cred_body = self._app_cred_body(
            roles=roles, access_rules=access_rules
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': token},
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
            )
            app_cred_id = resp.json['application_credential']['id']
            resp_access_rules = resp.json['application_credential'][
                'access_rules'
            ]
            access_rule_id = resp_access_rules[0].pop('id')
            self.assertEqual(access_rules[0], resp_access_rules[0])
            resp = c.get(
                f'/v3/users/{self.user_id}/access_rules',
                headers={'X-Auth-Token': token},
            )
            resp_access_rule = resp.json['access_rules'][0]
            resp_access_rule.pop('id')
            resp_access_rule.pop('links')
            self.assertEqual(access_rules[0], resp_access_rule)
            resp = c.get(
                f'/v3/users/{self.user_id}/access_rules/{access_rule_id}',
                headers={'X-Auth-Token': token},
            )
            resp_access_rule = resp.json['access_rule']
            resp_access_rule.pop('id')
            resp_access_rule.pop('links')
            self.assertEqual(access_rules[0], resp_access_rule)
            # can't delete an access rule in use
            c.delete(
                f'/v3/users/{self.user_id}/access_rules/{access_rule_id}',
                headers={'X-Auth-Token': token},
                expected_status_code=http.client.FORBIDDEN,
            )
            c.delete(
                f'/v3/users/{self.user_id}/application_credentials/{app_cred_id}',
                headers={'X-Auth-Token': token},
            )
            c.delete(
                f'/v3/users/{self.user_id}/access_rules/{access_rule_id}',
                headers={'X-Auth-Token': token},
            )

    def test_create_application_credential_with_duplicate_access_rule(self):
        roles = [{'id': self.role_id}]
        access_rules = [
            {'path': '/v3/projects', 'method': 'POST', 'service': 'identity'}
        ]
        app_cred_body_1 = self._app_cred_body(
            roles=roles, access_rules=access_rules
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': token},
                json=app_cred_body_1,
                expected_status_code=http.client.CREATED,
            )
        resp_access_rules = resp.json['application_credential']['access_rules']
        self.assertIn('id', resp_access_rules[0])
        access_rule_id = resp_access_rules[0].pop('id')
        self.assertEqual(access_rules[0], resp_access_rules[0])

        app_cred_body_2 = self._app_cred_body(
            roles=roles, access_rules=access_rules
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': token},
                json=app_cred_body_2,
                expected_status_code=http.client.CREATED,
            )
        resp_access_rules = resp.json['application_credential']['access_rules']
        self.assertEqual(access_rule_id, resp_access_rules[0]['id'])

    def test_create_application_credential_with_access_rule_by_id(self):
        roles = [{'id': self.role_id}]
        access_rules = [
            {'path': '/v3/projects', 'method': 'POST', 'service': 'identity'}
        ]
        app_cred_body_1 = self._app_cred_body(
            roles=roles, access_rules=access_rules
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': token},
                json=app_cred_body_1,
                expected_status_code=http.client.CREATED,
            )
        resp_access_rules = resp.json['application_credential']['access_rules']
        access_rule_id = resp_access_rules
        self.assertIn('id', resp_access_rules[0])
        access_rule_id = resp_access_rules[0].pop('id')
        self.assertEqual(access_rules[0], resp_access_rules[0])

        access_rules = [{'id': access_rule_id}]
        app_cred_body_2 = self._app_cred_body(
            roles=roles, access_rules=access_rules
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                headers={'X-Auth-Token': token},
                json=app_cred_body_2,
                expected_status_code=http.client.CREATED,
            )
        resp_access_rules = resp.json['application_credential']['access_rules']
        self.assertEqual(access_rule_id, resp_access_rules[0]['id'])

    def test_list_application_credentials(self):
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual([], resp.json['application_credentials'])
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual(1, len(resp.json['application_credentials']))
            self.assertNotIn('secret', resp.json['application_credentials'][0])
            self.assertNotIn(
                'secret_hash', resp.json['application_credentials'][0]
            )
            app_cred_body['application_credential']['name'] = 'two'
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual(2, len(resp.json['application_credentials']))
            for ac in resp.json['application_credentials']:
                self.assertNotIn('secret', ac)
                self.assertNotIn('secret_hash', ac)

    def test_list_application_credentials_with_deleted_role(self):
        second_role = unit.new_role_ref(name='test_new_role')
        PROVIDERS.role_api.create_role(second_role['id'], second_role)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, self.project_id, second_role['id']
        )
        with self.test_client() as c:
            token = self.get_scoped_token()
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual([], resp.json['application_credentials'])
            roles = [{'id': second_role['id']}]
            app_cred_body = self._app_cred_body(roles=roles)
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            PROVIDERS.role_api.delete_role(second_role['id'])
            resp = c.get(
                f'/v3/users/{self.user_id}/application_credentials',
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )

    def test_list_application_credentials_by_name(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            name = app_cred_body['application_credential']['name']
            search_path = (
                f'/v3/users/{self.user_id}/application_credentials?name={name}'
            )
            resp = c.get(
                search_path,
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual([], resp.json['application_credentials'])
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            resp = c.get(
                search_path,
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual(1, len(resp.json['application_credentials']))
            self.assertNotIn('secret', resp.json['application_credentials'][0])
            self.assertNotIn(
                'secret_hash', resp.json['application_credentials'][0]
            )
            app_cred_body['application_credential']['name'] = 'two'
            c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            resp = c.get(
                search_path,
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertEqual(1, len(resp.json['application_credentials']))
            self.assertEqual(
                resp.json['application_credentials'][0]['name'], name
            )

    def test_get_head_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            app_cred_id = resp.json['application_credential']['id']
            c.head(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': app_cred_id},
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            expected_response = resp.json
            expected_response['application_credential'].pop('secret')
            resp = c.get(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': app_cred_id},
                expected_status_code=http.client.OK,
                headers={'X-Auth-Token': token},
            )
            self.assertDictEqual(resp.json, expected_response)

    def test_get_head_application_credential_not_found(self):
        with self.test_client() as c:
            token = self.get_scoped_token()
            c.head(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': uuid.uuid4().hex},
                expected_status_code=http.client.NOT_FOUND,
                headers={'X-Auth-Token': token},
            )
            c.get(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': uuid.uuid4().hex},
                expected_status_code=http.client.NOT_FOUND,
                headers={'X-Auth-Token': token},
            )

    def test_delete_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            app_cred_id = resp.json['application_credential']['id']
            c.delete(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': app_cred_id},
                expected_status_code=http.client.NO_CONTENT,
                headers={'X-Auth-Token': token},
            )

    def test_delete_application_credential_not_found(self):
        with self.test_client() as c:
            token = self.get_scoped_token()
            c.delete(
                f'/v3{MEMBER_PATH_FMT}'
                % {'user_id': self.user_id, 'app_cred_id': uuid.uuid4().hex},
                expected_status_code=http.client.NOT_FOUND,
                headers={'X-Auth-Token': token},
            )

    def test_delete_application_credential_with_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            app_cred = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            auth_data = self.build_authentication_request(
                app_cred_id=app_cred.json['application_credential']['id'],
                secret=app_cred.json['application_credential']['secret'],
            )
            token_data = self.v3_create_token(
                auth_data, expected_status=http.client.CREATED
            )
            member_path = f'/v3{MEMBER_PATH_FMT}' % {
                'user_id': self.user_id,
                'app_cred_id': app_cred.json['application_credential']['id'],
            }
            token = token_data.headers['x-subject-token']
            c.delete(
                member_path,
                json=app_cred_body,
                expected_status_code=http.client.FORBIDDEN,
                headers={'X-Auth-Token': token},
            )

    def test_delete_application_credential_allow_recursion(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            app_cred_body['application_credential']['unrestricted'] = True
            token = self.get_scoped_token()
            app_cred = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            auth_data = self.build_authentication_request(
                app_cred_id=app_cred.json['application_credential']['id'],
                secret=app_cred.json['application_credential']['secret'],
            )
            token_data = self.v3_create_token(
                auth_data, expected_status=http.client.CREATED
            )
            member_path = f'/v3{MEMBER_PATH_FMT}' % {
                'user_id': self.user_id,
                'app_cred_id': app_cred.json['application_credential']['id'],
            }
            c.delete(
                member_path,
                json=app_cred_body,
                expected_status_code=http.client.NO_CONTENT,
                headers={
                    'x-Auth-Token': token_data.headers['x-subject-token']
                },
            )

    def test_update_application_credential(self):
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(roles=roles)
            token = self.get_scoped_token()
            resp = c.post(
                f'/v3/users/{self.user_id}/application_credentials',
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={'X-Auth-Token': token},
            )
            # Application credentials are immutable
            app_cred_body['application_credential']['description'] = (
                "New Things"
            )
            app_cred_id = resp.json['application_credential']['id']
            # NOTE(morgan): when the whole test case is converted to using
            # flask test_client, this extra v3 prefix will
            # need to be rolled into the base MEMBER_PATH_FMT
            member_path = f'/v3{MEMBER_PATH_FMT}' % {
                'user_id': self.user_id,
                'app_cred_id': app_cred_id,
            }
            c.patch(
                member_path,
                json=app_cred_body,
                expected_status_code=http.client.METHOD_NOT_ALLOWED,
                headers={'X-Auth-Token': token},
            )

    def test_list_access_rules(self):
        access_rules: list[dict[str, str]] = [
            {"service": "foo", "method": "GET", "path": "/bar"}
        ]
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(
                roles=roles, access_rules=access_rules
            )
            token = self.get_scoped_token()
            c.post(
                f"/v3/users/{self.user_id}/application_credentials",
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={"X-Auth-Token": token},
            )
            # Invoke GET access_rules and trigger internal validation
            r = c.get(
                f"/v3/users/{self.user_id}/access_rules",
                expected_status_code=http.client.OK,
                headers={"X-Auth-Token": token},
            )
            ar = r.json["access_rules"]
            self.assertEqual(access_rules[0]["method"], ar[0]["method"])

    def test_list_access_rules_wrong_qp(self):
        with self.test_client() as c:
            token = self.get_scoped_token()
            # Invoke GET access_rules with unsupported query parameters and
            # trigger internal validation
            c.get(
                f"/v3/users/{self.user_id}/access_rules?user_id=foo",
                expected_status_code=http.client.BAD_REQUEST,
                headers={"X-Auth-Token": token},
            )

    def test_show_access_rule(self):
        access_rules: list[dict[str, str]] = [
            {"service": "foo", "method": "GET", "path": "/bar"}
        ]
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(
                roles=roles, access_rules=access_rules
            )
            token = self.get_scoped_token()
            resp = c.post(
                f"/v3/users/{self.user_id}/application_credentials",
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={"X-Auth-Token": token},
            )
            access_rule_id = resp.json["application_credential"][
                "access_rules"
            ][0]["id"]
            # Invoke GET access_rules/{id} and trigger internal validation
            c.get(
                f"/v3/users/{self.user_id}/access_rules/{access_rule_id}",
                expected_status_code=http.client.OK,
                headers={"X-Auth-Token": token},
            )
            c.get(
                f"/v3/users/{self.user_id}/access_rules/{access_rule_id}"
                "?foo=bar",
                expected_status_code=http.client.BAD_REQUEST,
                headers={"X-Auth-Token": token},
            )

    def test_delete_access_rule(self):
        access_rules: list[dict[str, str]] = [
            {"service": "foo", "method": "GET", "path": "/bar"}
        ]
        with self.test_client() as c:
            roles = [{'id': self.role_id}]
            app_cred_body = self._app_cred_body(
                roles=roles, access_rules=access_rules
            )
            token = self.get_scoped_token()
            resp = c.post(
                f"/v3/users/{self.user_id}/application_credentials",
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers={"X-Auth-Token": token},
            )
            app_cred: dict = resp.json["application_credential"]
            access_rule_id = app_cred["access_rules"][0]["id"]
            c.delete(
                f"/v3/users/{self.user_id}/application_credentials"
                f"/{app_cred['id']}",
                json=app_cred_body,
                expected_status_code=http.client.NO_CONTENT,
                headers={"X-Auth-Token": token},
            )
            # Invoke GET access_rules/{id} and trigger internal validation
            c.delete(
                f"/v3/users/{self.user_id}/access_rules/{access_rule_id}",
                expected_status_code=http.client.NO_CONTENT,
                headers={"X-Auth-Token": token},
            )
