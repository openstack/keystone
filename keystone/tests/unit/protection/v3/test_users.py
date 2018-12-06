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

from six.moves import http_client

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _CommonUserTests(object):
    """Common default functionality for all users."""

    def test_user_can_get_their_own_user_reference(self):
        with self.test_client() as c:
            r = c.get('/v3/users/%s' % self.user_id, headers=self.headers)
            self.assertEqual(self.user_id, r.json['user']['id'])


class _SystemUserTests(object):
    """Common default functionality for all system users."""

    def test_user_can_get_other_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/users/%s' % user['id'], headers=self.headers)
            self.assertEqual(user['id'], r.json['user']['id'])

    def test_user_cannot_get_non_existent_user_not_found(self):
        with self.test_client() as c:
            c.get(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http_client.NOT_FOUND
            )

    def test_user_can_list_users(self):
        expected_user_ids = []
        for _ in range(3):
            user = PROVIDERS.identity_api.create_user(
                unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
            )
            expected_user_ids.append(user['id'])

        with self.test_client() as c:
            r = c.get('/v3/users', headers=self.headers)
            returned_user_ids = []
            for user in r.json['users']:
                returned_user_ids.append(user['id'])

            for user_id in expected_user_ids:
                self.assertIn(user_id, returned_user_ids)


class _SystemMemberAndReaderUserTests(object):
    """Common functionality for system readers and system members."""

    def test_user_cannot_create_users(self):
        create = {
            'user': {
                'name': uuid.uuid4().hex,
                'domain': CONF.identity.default_domain_id
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            update = {'user': {'email': uuid.uuid4().hex}}

            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_user_forbidden(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_delete_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _CommonUserTests,
                        _SystemUserTests,
                        _SystemMemberAndReaderUserTests):

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


class SystemMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _CommonUserTests,
                        _SystemUserTests,
                        _SystemMemberAndReaderUserTests):

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


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _CommonUserTests,
                       _SystemUserTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

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

    def test_user_can_create_users(self):
        create = {
            'user': {
                'name': uuid.uuid4().hex,
                'domain': CONF.identity.default_domain_id
            }
        }

        with self.test_client() as c:
            c.post('/v3/users', json=create, headers=self.headers)

    def test_user_can_update_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers
            )

    def test_user_cannot_update_non_existent_user_not_found(self):
        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http_client.NOT_FOUND
            )

    def test_user_can_delete_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete('/v3/users/%s' % user['id'], headers=self.headers)

    def test_user_cannot_delete_non_existent_user_not_found(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http_client.NOT_FOUND
            )
