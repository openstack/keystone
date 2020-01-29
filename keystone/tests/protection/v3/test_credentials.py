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

import uuid

import http.client
from oslo_serialization import jsonutils

from keystone.common.policies import base as bp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _UserCredentialTests(object):
    """Test cases for anyone that has a valid user token."""

    def test_user_can_create_credentials_for_themselves(self):
        create = {
            'credential': {
                'blob': uuid.uuid4().hex,
                'user_id': self.user_id,
                'type': uuid.uuid4().hex
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
                    'user_id': self.user_id
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            path = '/v3/credentials/%s' % credential_id
            r = c.get(path, headers=self.headers)
            self.assertEqual(
                self.user_id, r.json['credential']['user_id']
            )

    def test_user_can_list_their_credentials(self):
        with self.test_client() as c:
            expected = []
            for _ in range(2):
                create = {
                    'credential': {
                        'blob': uuid.uuid4().hex,
                        'type': uuid.uuid4().hex,
                        'user_id': self.user_id
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
                    'user_id': self.user_id
                }
            }
            r = c.post(
                '/v3/credentials', json=create, headers=self.headers
            )
            expected_credential_id = r.json['credential']['id']

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id
                }
            }
            r = c.post(
                '/v3/credentials', json=create, headers=self.headers
            )

            path = '/v3/credentials?type=%s' % credential_type
            r = c.get(path, headers=self.headers)
            self.assertEqual(
                expected_credential_id, r.json['credentials'][0]['id']
            )

            path = '/v3/credentials?user=%s' % self.user_id
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
                    'user_id': self.user_id
                }
            }

            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            updated_blob = uuid.uuid4().hex
            update = {'credential': {'blob': updated_blob}}
            path = '/v3/credentials/%s' % credential_id
            r = c.patch(path, json=update, headers=self.headers)
            self.assertEqual(updated_blob, r.json['credential']['blob'])

    def test_user_can_delete_their_credentials(self):
        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': self.user_id
                }
            }
            r = c.post('/v3/credentials', json=create, headers=self.headers)
            credential_id = r.json['credential']['id']

            path = '/v3/credentials/%s' % credential_id
            c.delete(path, headers=self.headers)


class _ProjectUsersTests(object):
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            c.get(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.get(
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = '/v3/credentials?user_id=%s' % user['id']
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
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
                    'user_id': user['id']
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = '/v3/credentials?type=%s' % credential_type
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
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
                        'user_id': user['id']
                    }
                }
                r = c.post('/v3/credentials', json=create, headers=headers)
                expected_cred_ids.append(r.json['credential']['id'])

        with self.test_client() as c:
            path = '/v3/credentials?user_id=%s' % user['id']
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = '/v3/credentials/%s' % credential_id
            c.patch(
                path, json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                '/v3/credentials/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
                    'user_id': user['id']
                }
            }
            c.post(
                '/v3/credentials', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _SystemUserCredentialTests(object):
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
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
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
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
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            c.post('/v3/credentials', json=create, headers=headers)

        with self.test_client() as c:
            path = '/v3/credentials?type=%s' % credential_type
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
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
                        'user_id': user['id']
                    }
                }
                r = c.post('/v3/credentials', json=create, headers=headers)
                expected_cred_ids.append(r.json['credential']['id'])

        with self.test_client() as c:
            path = '/v3/credentials?user_id=%s' % user['id']
            r = c.get(path, headers=self.headers)
            self.assertEqual(2, len(r.json['credentials']))
            for credential in r.json['credentials']:
                self.assertIn(credential['id'], expected_cred_ids)
                self.assertEqual(user['id'], credential['user_id'])


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserCredentialTests,
                        _SystemUserCredentialTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_reader['password'],
            system=True
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
                    'user_id': user['id']
                }
            }
            c.post(
                '/v3/credentials', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = '/v3/credentials/%s' % credential_id
            c.patch(
                path, json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                '/v3/credentials/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserCredentialTests,
                        _SystemUserCredentialTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_member
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_member['password'],
            system=True
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
                    'user_id': user['id']
                }
            }
            c.post(
                '/v3/credentials', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}
            path = '/v3/credentials/%s' % credential_id
            c.patch(
                path, json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                '/v3/credentials/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existant_credential_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _UserCredentialTests,
                       _SystemUserCredentialTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_create_credentials_for_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            updated_blob = uuid.uuid4().hex
            update = {'credential': {'blob': updated_blob}}
            r = c.patch(path, json=update, headers=self.headers)
            self.assertEqual(updated_blob, r.json['credential']['blob'])
            self.assertEqual(user['id'], r.json['credential']['user_id'])

    def test_user_cannot_update_non_existant_credential_not_found(self):
        with self.test_client() as c:
            update = {'credential': {'blob': uuid.uuid4().hex}}

            c.patch(
                '/v3/credentials/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
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
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            create = {
                'credential': {
                    'blob': uuid.uuid4().hex,
                    'type': uuid.uuid4().hex,
                    'user_id': user['id']
                }
            }
            r = c.post('/v3/credentials', json=create, headers=headers)
            credential_id = r.json['credential']['id']

        with self.test_client() as c:
            path = '/v3/credentials/%s' % credential_id
            c.delete(path, headers=self.headers)

    def test_user_cannot_delete_non_existant_credential_not_found(self):
        with self.test_client() as c:
            c.delete(
                '/v3/credentials/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _UserCredentialTests,
                         _ProjectUsersTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_reader
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_reader['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _UserCredentialTests,
                         _ProjectUsersTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_member
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_member['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserCredentialTests,
                        _ProjectUsersTests):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
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
            project_id=self.bootstrapper.project_id
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
                'identity:get_credential': bp.SYSTEM_READER_OR_CRED_OWNER,
                'identity:list_credentials': bp.SYSTEM_READER_OR_CRED_OWNER,
                'identity:create_credential': bp.SYSTEM_ADMIN_OR_CRED_OWNER,
                'identity:update_credential': bp.SYSTEM_ADMIN_OR_CRED_OWNER,
                'identity:delete_credential': bp.SYSTEM_ADMIN_OR_CRED_OWNER
            }
            f.write(jsonutils.dumps(overridden_policies))


class ProjectReaderTestsEnforceScopeFalse(base_classes.TestCaseWithBootstrap,
                                          common_auth.AuthTestMixin,
                                          _UserCredentialTests,
                                          _ProjectUsersTests):

    def setUp(self):
        super(ProjectReaderTestsEnforceScopeFalse, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        project_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_reader
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_reader['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTestsEnforceScopeFalse(base_classes.TestCaseWithBootstrap,
                                          common_auth.AuthTestMixin,
                                          _UserCredentialTests,
                                          _ProjectUsersTests):

    def setUp(self):
        super(ProjectMemberTestsEnforceScopeFalse, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        project_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_member
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_member['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTestsEnforceScopeFalse(base_classes.TestCaseWithBootstrap,
                                         common_auth.AuthTestMixin,
                                         _UserCredentialTests,
                                         _SystemUserCredentialTests):

    def setUp(self):
        super(ProjectAdminTestsEnforceScopeFalse, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            project_id=self.bootstrapper.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}
