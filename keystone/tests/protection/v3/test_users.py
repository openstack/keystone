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

from keystone.common.policies import user as up
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

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
                expected_status_code=http.client.NOT_FOUND
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
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            update = {'user': {'email': uuid.uuid4().hex}}

            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_user_forbidden(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_users(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainUserTests(object):
    """Commont default functionality for all domain users."""

    def test_user_can_get_user_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/users/%s' % user['id'], headers=self.headers)
            self.assertEqual(user['id'], r.json['user']['id'])

    def test_user_cannot_get_user_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.get(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_list_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/users', headers=self.headers)
            self.assertEqual(2, len(r.json['users']))
            user_ids = []
            for user in r.json['users']:
                user_ids.append(user['id'])
            self.assertIn(self.user_id, user_ids)
            self.assertIn(user['id'], user_ids)

    def test_user_cannot_list_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            r = c.get('/v3/users', headers=self.headers)
            user_ids = []
            for u in r.json['users']:
                user_ids.append(u['id'])
            self.assertNotIn(user['id'], user_ids)


class _DomainMemberAndReaderUserTests(object):
    """Functionality for all domain members and domain readers."""

    def test_user_cannot_create_users_within_domain(self):
        create = {
            'user': {
                'domain_id': self.domain_id,
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'user': {
                'domain_id': domain['id'],
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_user_forbidden(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _ProjectUserTests(object):
    """Common tests cases for all project users."""

    def test_user_cannot_get_users_within_their_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.get(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_users_in_other_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.get(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.get(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_users_within_domain(self):
        with self.test_client() as c:
            c.get(
                '/v3/users?domain_id=%s' % self.domain_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_users_in_other_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.get(
                '/v3/users?domain_id=%s' % domain['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_users_within_domain(self):
        create = {
            'user': {
                'domain_id': self.domain_id,
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_users_in_other_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'user': {
                'domain_id': domain['id'],
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_user_forbidden(self):
        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_users_in_other_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
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
                expected_status_code=http.client.NOT_FOUND
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
                expected_status_code=http.client.NOT_FOUND
            )


class DomainReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _CommonUserTests,
                        _DomainUserTests,
                        _DomainMemberAndReaderUserTests):

    def setUp(self):
        super(DomainReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_reader = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_reader)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_reader['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _CommonUserTests,
                        _DomainUserTests,
                        _DomainMemberAndReaderUserTests):

    def setUp(self):
        super(DomainMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _CommonUserTests,
                       _DomainUserTests):

    def setUp(self):
        super(DomainAdminTests, self).setUp()
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

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.users have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will apply a logical OR to deprecated policies with
        # new policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users. This
        # will cause these specific tests to fail since we're trying to correct
        # this broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_user': up.SYSTEM_READER_OR_DOMAIN_READER_OR_USER,
                'identity:list_users': up.SYSTEM_READER_OR_DOMAIN_READER,
                'identity:create_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:update_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:delete_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))

    def test_user_can_create_users_within_domain(self):
        create = {
            'user': {
                'domain_id': self.domain_id,
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post('/v3/users', json=create, headers=self.headers)

    def test_user_cannot_create_users_within_domain_hyphened_domain_id(self):
        # Finally, show that we can create a new user without any surprises.
        # But if we specify a 'domain-id' instead of a 'domain_id', we get a
        # Forbidden response because we fail a policy check before
        # normalization occurs.
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'user': {
                'domain-id': domain['id'],
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'user': {
                'domain_id': domain['id'],
                'name': uuid.uuid4().hex
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/users', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_update_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers
            )

    def test_user_can_update_users_within_domain_hyphened_domain_id(self):
        # If we try updating the user's 'domain_id' by specifying a
        # 'domain-id', then it'll be stored into extras rather than normalized,
        # and the user's actual 'domain_id' is not affected.
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        update = {'user': {'domain-id': domain['id']}}
        with self.test_client() as c:
            r = c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers
            )
            self.assertEqual(domain['id'], r.json['user']['domain-id'])
            self.assertEqual(self.domain_id, r.json['user']['domain_id'])

    def test_user_cannot_update_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % user['id'], json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_user_forbidden(self):
        update = {'user': {'email': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/users/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_delete_users_within_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers
            )

    def test_user_cannot_delete_users_in_other_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_user_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _CommonUserTests,
                         _ProjectUserTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project = unit.new_project_ref(domain_id=self.domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        self.project_id = project['id']

        project_reader = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_reader)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_reader['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _CommonUserTests,
                         _ProjectUserTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project = unit.new_project_ref(domain_id=self.domain_id)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        self.project_id = project['id']

        project_member = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_member)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_member['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _CommonUserTests,
                        _ProjectUserTests):

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

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

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
        # keystone.common.policies.users have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_user': up.SYSTEM_READER_OR_DOMAIN_READER_OR_USER,
                'identity:list_users': up.SYSTEM_READER_OR_DOMAIN_READER,
                'identity:create_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:update_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:delete_user': up.SYSTEM_ADMIN_OR_DOMAIN_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))
