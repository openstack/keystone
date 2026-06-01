#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import http.client
import uuid

from oslo_serialization import jsonutils

from keystone.common.policies import base as bp
from keystone.common import provider_api
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _UserCredentialTests:
    """Test cases for anyone that has a valid user token."""

    def test_user_can_create_credentials_for_themselves(self):
        create = {
            'credential': {
                'blob': uuid.uuid4().hex,
                'user_id': self.user_id,
                'type': uuid.uuid4().hex,
            }
        }
        with self.test_client() as c:
            c.post('/v3/credentials', json=create, headers=self.headers)

    def test_user_can_get_their_credentials(self):
        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id,
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            path = f'/v3/credentials/{credential_id}'
            r = c.get(path, headers=self.headers)
            self.assertEqual(self.user_id, r.json['credential']['user_id'])

    def test_user_can_list_their_credentials(self):
        with self.test_client() as c:
            expected = []
            for _ in range(2):
                create = {
                    'credential': {
                        'blob': uuid.uuid4().hex,
                        'type': uuid.uuid4().hex,
                        'user_id': self.user_id,
                    }
                }
                r = c.post(
                    '/v3/credentials', json=create, headers=self.headers
                )
                expected.append(r.json['credential'])

            r = c.get('/v3/credentials', headers=self.headers)
            for credential in expected:
                self.assertIn(credential, r.json['credentials'])

    def test_user_can_filter_their_credentials_by_type_and_user(self):
        with self.test_client() as c:
            credential_type = uuid.uuid4().hex
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': credential_type,
                    'user_id': self.user_id,
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)
            expected_credential_id = r.json['credential']['id']

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id,
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)

            path = f'/v3/credentials?type={credential_type}'
            r = c.get(path, headers=self.headers)
            self.assertEqual(
                expected_credential_id, r.json['credentials'][0]['id']
            )

            path = f'/v3/credentials?user={self.user_id}'
            r = c.get(path, headers=self.headers)
            self.assertEqual(
                expected_credential_id, r.json['credentials'][0]['id']
            )

    def test_user_can_update_their_credential(self):
        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id,
                }
            }

            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            updated_blob = uuid.uuid4().hex
            update = {'credential': {'blob': updated_blob}}
            path = f'/v3/credentials/{credential_id}'
            r = c.patch(path, json=update, headers=self.headers)
            self.assertEqual(updated_blob, r.json['credential']['blob'])

    def test_user_can_delete_their_credentials(self):
        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id,
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            path = f'/v3/credentials/{credential_id}'
            c.delete(path, headers=self.headers)


class _ProjectUsersTests:
    """Users who have project role authorization observe the same behavior."""

    def test_user_cannot_get_credentials_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            c.get(
                path,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_get_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.get(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_list_credentials_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = '/v3/credentials?user_id={}'.format(user['id'])
            r = c.get(path, headers=self.headers)
            self.assertEqual([], r.json['credentials'])

    def test_user_cannot_filter_credentials_by_type_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        credential_type = uuid.uuid4().hex
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': credential_type,
                    'user_id': user['id'],
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = f'/v3/credentials?type={credential_type}'
            r = c.get(path, headers=self.headers)
            self.assertEqual(0, len(r.json['credentials']))

    def test_user_cannot_filter_credentials_by_user_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            expected_cred_ids = []
            for _ in range(2):
                create = {
                    'credential': {
                        'blob': uuid.uuid4().hex,
                        'type': uuid.uuid4().hex,
                        'user_id': user['id'],
                    }
                }
                r = c.post('/v3/credentials', json=create, headers=headers)
                expected_cred_ids.append(r.json['credential']['id'])

        with self.test_client() as c:
            path = '/v3/credentials?user_id={}'.format(user['id'])
            r = c.get(path, headers=self.headers)
            self.assertEqual([], r.json['credentials'])

    def test_user_cannot_update_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = f'/v3/credentials/{credential_id}'
            c.patch(
                path,
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                f'/v3/credentials/{uuid.uuid4().hex}',
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_create_credentials_for_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post(
                '/v3/credentials',
                json=create,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            c.delete(
                path,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )


class _SystemUserCredentialTests:
    """Tests that are common across all system users."""

    def test_user_can_list_credentials_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            r = c.get('/v3/credentials', headers=self.headers)
            self.assertEqual(1, len(r.json['credentials']))
            self.assertEqual(credential_id, r.json['credentials'][0]['id'])
            self.assertEqual(user['id'], r.json['credentials'][0]['user_id'])

    def test_user_cannot_get_non_existant_credential_not_found(self):
        with self.test_client() as c:
            c.get(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND,
            )

    def test_user_can_filter_credentials_by_type_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        credential_type = uuid.uuid4().hex
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': credential_type,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = f'/v3/credentials?type={credential_type}'
            r = c.get(path, headers=self.headers)
            self.assertEqual(1, len(r.json['credentials']))
            self.assertEqual(credential_id, r.json['credentials'][0]['id'])
            self.assertEqual(user['id'], r.json['credentials'][0]['user_id'])

    def test_user_can_filter_credentials_by_user_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            expected_cred_ids = []
            for _ in range(2):
                create = {
                    'credential': {
                        'blob': uuid.uuid4().hex,
                        'type': uuid.uuid4().hex,
                        'user_id': user['id'],
                    }
                }
                r = c.post('/v3/credentials', json=create, headers=headers)
                expected_cred_ids.append(r.json['credential']['id'])

        with self.test_client() as c:
            path = '/v3/credentials?user_id={}'.format(user['id'])
            r = c.get(path, headers=self.headers)
            self.assertEqual(2, len(r.json['credentials']))
            for credential in r.json['credentials']:
                self.assertIn(credential['id'], expected_cred_ids)
                self.assertEqual(user['id'], credential['user_id'])


class SystemReaderTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _SystemUserCredentialTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(system_reader)['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=system_reader['password'],
            system=True,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_cannot_create_credentials_for_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post(
                '/v3/credentials',
                json=create,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = f'/v3/credentials/{credential_id}'
            c.patch(
                path,
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                f'/v3/credentials/{uuid.uuid4().hex}',
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            c.delete(
                path,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )


class SystemMemberTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _SystemUserCredentialTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(system_member)['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=system_member['password'],
            system=True,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_cannot_create_credentials_for_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post(
                '/v3/credentials',
                json=create,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = f'/v3/credentials/{credential_id}'
            c.patch(
                path,
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                f'/v3/credentials/{uuid.uuid4().hex}',
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            c.delete(
                path,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )


class _AdminCredentialTests:
    def test_user_can_create_credentials_for_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            c.post('/v3/credentials', json=create, headers=self.headers)

    def test_user_can_update_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            updated_blob = uuid.uuid4().hex
            update = {'credential': {'blob': updated_blob}}
            r = c.patch(path, json=update, headers=self.headers)
            self.assertEqual(updated_blob, r.json['credential']['blob'])
            self.assertEqual(user['id'], r.json['credential']['user_id'])

    def test_user_cannot_update_non_existant_credential_not_found(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                f'/v3/credentials/{uuid.uuid4().hex}',
                json=update,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND,
            )

    def test_user_can_delete_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=user['id'],
            project_id=project['id'],
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'],
            password=user_password,
            project_id=project['id'],
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id'],
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = f'/v3/credentials/{credential_id}'
            c.delete(path, headers=self.headers)

    def test_user_cannot_delete_non_existant_credential_not_found(self):
        with self.test_client() as c:
            c.delete(
                f'/v3/credentials/{uuid.uuid4().hex}',
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND,
            )


class SystemAdminTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _SystemUserCredentialTests,
    _AdminCredentialTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            system=True,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectReaderTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _ProjectUsersTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(project_reader)['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_reader['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _ProjectUsersTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(project_member)['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_member['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _AdminCredentialTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        self._override_policy()
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            project_id=self.bootstrapper.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.credentials have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_credential': bp.ADMIN_OR_SYSTEM_READER_OR_CRED_OWNER,
                'identity:list_credentials': bp.ADMIN_OR_SYSTEM_READER_OR_CRED_OWNER,
                'identity:create_credential': bp.ADMIN_OR_CRED_OWNER,
                'identity:update_credential': bp.ADMIN_OR_CRED_OWNER,
                'identity:delete_credential': bp.ADMIN_OR_CRED_OWNER,
            }
            f.write(jsonutils.dumps(overridden_policies))


class ProjectReaderTestsEnforceScopeFalse(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _ProjectUsersTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        project_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(project_reader)['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_reader['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTestsEnforceScopeFalse(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _ProjectUsersTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        project_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(project_member)['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_member['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTestsEnforceScopeFalse(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserCredentialTests,
    _SystemUserCredentialTests,
):
    def setUp(self):
        super().setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            project_id=self.bootstrapper.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class TargetInjectionCredentialTests(test_v3.RestfulTestCase):
    """Test that JSON body injection cannot bypass credential RBAC.

    Verifies CVE-2026-42999: the RBAC enforcer must not allow the JSON
    request body to overwrite security-critical keys in the policy dict.
    """

    def setUp(self):
        super().setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS,
            )
        )

    def _make_user_with_project(self, role_id=None):
        user = unit.create_user(
            PROVIDERS.identity_api, domain_id=self.domain_id
        )
        project = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project['id'], project)
        if role_id:
            PROVIDERS.assignment_api.add_role_to_user_and_project(
                user['id'], project['id'], role_id
            )
        return user, project

    def test_list_credentials_cannot_read_other_users_secrets(self):
        """GET /v3/credentials must not return other users' credentials.

        An attacker injects their own user_id into target.credential.user_id
        in the JSON body. Without the fix the per-item policy filter would
        see the attacker's user_id and pass every credential through.
        """
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        victim, victim_project = self._make_user_with_project(role['id'])
        attacker, attacker_project = self._make_user_with_project(role['id'])

        victim_cred = unit.new_credential_ref(
            user_id=victim['id'], project_id=victim_project['id']
        )
        PROVIDERS.credential_api.create_credential(
            victim_cred['id'], victim_cred
        )
        attacker_cred = unit.new_credential_ref(
            user_id=attacker['id'], project_id=attacker_project['id']
        )
        PROVIDERS.credential_api.create_credential(
            attacker_cred['id'], attacker_cred
        )

        attacker_auth = self.build_authentication_request(
            user_id=attacker['id'],
            password=attacker['password'],
            project_id=attacker_project['id'],
        )
        r = self.get(
            '/credentials',
            auth=attacker_auth,
            body={'target': {'credential': {'user_id': attacker['id']}}},
        )

        cred_ids = [c['id'] for c in r.result['credentials']]
        self.assertIn(attacker_cred['id'], cred_ids)
        self.assertNotIn(victim_cred['id'], cred_ids)

    def test_ec2_create_credential_cannot_create_for_other_user(self):
        """EC2 credential creation must not allow impersonating other users.

        POST /v3/users/{user_id}/credentials/OS-EC2: the attacker injects
        target.credential.user_id to bypass the ownership check.
        """
        member_role = unit.new_role_ref(name='member')
        PROVIDERS.role_api.create_role(member_role['id'], member_role)

        victim, victim_project = self._make_user_with_project(
            member_role['id']
        )
        attacker, attacker_project = self._make_user_with_project(
            member_role['id']
        )

        attacker_auth = self.build_authentication_request(
            user_id=attacker['id'],
            password=attacker['password'],
            project_id=attacker_project['id'],
        )
        ec2_uri = f'/users/{victim["id"]}/credentials/OS-EC2'

        self.post(
            ec2_uri,
            auth=attacker_auth,
            body={
                'tenant_id': victim_project['id'],
                'target': {'credential': {'user_id': attacker['id']}},
            },
            expected_status=http.client.FORBIDDEN,
        )
        self.post(
            ec2_uri,
            auth=attacker_auth,
            body={
                'tenant_id': victim_project['id'],
                'target': {
                    'credential': {
                        'user_id': attacker['id'],
                        'project_id': attacker_project['id'],
                    }
                },
            },
            expected_status=http.client.FORBIDDEN,
        )
