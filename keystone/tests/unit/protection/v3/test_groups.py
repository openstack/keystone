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


class _SystemUserGroupTests(object):
    """Common default functionality for all system users."""

    def test_user_can_list_groups(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            r = c.get('/v3/groups', headers=self.headers)
            self.assertEqual(1, len(r.json['groups']))
            self.assertEqual(group['id'], r.json['groups'][0]['id'])

    def test_user_can_get_a_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            r = c.get('/v3/groups/%s' % group['id'], headers=self.headers)
            self.assertEqual(group['id'], r.json['group']['id'])

    def test_user_can_list_group_members(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/groups/%s/users' % group['id'], headers=self.headers
            )
            self.assertEqual(1, len(r.json['users']))
            self.assertEqual(user['id'], r.json['users'][0]['id'])

    def test_user_can_list_groups_for_other_users(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/groups' % user['id'], headers=self.headers
            )
            self.assertEqual(1, len(r.json['groups']))
            self.assertEqual(group['id'], r.json['groups'][0]['id'])

    def test_user_can_check_if_user_in_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.get(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers,
                expected_status_code=http_client.NO_CONTENT
            )

    def test_user_cannot_get_non_existent_group_not_found(self):
        with self.test_client() as c:
            c.get(
                '/v3/groups/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http_client.NOT_FOUND
            )


class _SystemMemberAndReaderGroupTests(object):
    """Common default functionality for system readers and system members."""

    def test_user_cannot_create_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'group': {
                'name': uuid.uuid4().hex,
                'domain_id': domain['id']
            }
        }

        with self.test_client() as c:
            c.post(
                '/v3/groups', json=create, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        update = {'group': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/groups/%s' % group['id'], json=update,
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_delete_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.delete(
                '/v3/groups/%s' % group['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_add_users_to_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.put(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_remove_users_from_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.delete(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserGroupTests,
                        _SystemMemberAndReaderGroupTests):

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
                        _SystemUserGroupTests,
                        _SystemMemberAndReaderGroupTests):

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
                       _SystemUserGroupTests):

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

    def test_user_can_create_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        create = {
            'group': {
                'name': uuid.uuid4().hex,
                'domain_id': domain['id']
            }
        }

        with self.test_client() as c:
            c.post('/v3/groups', json=create, headers=self.headers)

    def test_user_can_update_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        update = {'group': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/groups/%s' % group['id'], json=update,
                headers=self.headers
            )

    def test_user_can_delete_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.delete(
                '/v3/groups/%s' % group['id'], headers=self.headers
            )

    def test_user_can_add_users_to_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.put(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers
            )

    def test_user_can_remove_users_from_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.delete(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers
            )


class ProjectUserTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin):

    def setUp(self):
        super(ProjectUserTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(user)['id']

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=project['id']
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=user['password'],
            project_id=project['id']
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_get_list_their_own_groups(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=self.domain_id)
        )

        PROVIDERS.identity_api.add_user_to_group(self.user_id, group['id'])

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/groups' % self.user_id, headers=self.headers
            )
            self.assertEqual(1, len(r.json['groups']))
            self.assertEqual(group['id'], r.json['groups'][0]['id'])

    def test_user_cannot_list_groups_for_other_users(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.get(
                '/v3/users/%s/groups' % user['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_list_groups(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.get(
                '/v3/groups', headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_get_a_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )

        with self.test_client() as c:
            c.get(
                '/v3/groups/%s' % group['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_list_group_members(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.get(
                '/v3/groups/%s/users' % group['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_check_if_user_in_group(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(domain_id=domain['id'])
        )
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=domain['id'])
        )

        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])

        with self.test_client() as c:
            c.get(
                '/v3/groups/%s/users/%s' % (group['id'], user['id']),
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_get_non_existent_group_forbidden(self):
        with self.test_client() as c:
            c.get(
                '/v3/groups/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )
