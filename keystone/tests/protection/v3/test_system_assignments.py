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

from keystone.common.policies import base
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserSystemAssignmentTests(object):

    def test_user_can_list_user_system_role_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/system/users/%s/roles' % user['id'], headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))
            self.assertEqual(
                self.bootstrapper.member_role_id, r.json['roles'][0]['id']
            )

    def test_user_can_check_user_system_role_assignment(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_list_group_system_role_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/system/groups/%s/roles' % group['id'],
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['roles']))
            self.assertEqual(
                self.bootstrapper.member_role_id, r.json['roles'][0]['id']
            )

    def test_user_can_check_group_system_role_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )


class _SystemMemberAndReaderSystemAssignmentTests(object):

    def test_user_cannot_grant_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_grant_group_system_assignment(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_group_system_assignment(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainAndProjectUserSystemAssignmentTests(object):

    def test_user_cannot_list_system_role_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/users/%s/roles' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_check_user_system_role_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_grant_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_group_system_role_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/groups/%s/roles' % group['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_check_group_system_role_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.get(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_grant_group_system_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_group_system_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserSystemAssignmentTests,
                        _SystemMemberAndReaderSystemAssignmentTests):

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
                        _SystemUserSystemAssignmentTests,
                        _SystemMemberAndReaderSystemAssignmentTests):

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
        self.expected = [
            # assignment of the user running the test case
            {
                'user_id': self.user_id,
                'system': 'all',
                'role_id': self.bootstrapper.member_role_id
            }
        ]

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
                       _SystemUserSystemAssignmentTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.user_id = self.bootstrapper.admin_user_id
        self.expected = []

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_grant_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
            )

    def test_user_can_revoke_system_assignments(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/users/%s/roles/%s' % (
                    user['id'], self.bootstrapper.member_role_id
                ), headers=self.headers
            )

    def test_user_can_grant_group_system_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.put(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers,
            )

    def test_user_can_revoke_group_system_assignments(self):
        group = PROVIDERS.identity_api.create_group(
            unit.new_group_ref(CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_system_grant_for_group(
            group['id'], self.bootstrapper.member_role_id
        )

        with self.test_client() as c:
            c.delete(
                '/v3/system/groups/%s/roles/%s' % (
                    group['id'], self.bootstrapper.member_role_id
                ), headers=self.headers
            )


class DomainUserTests(base_classes.TestCaseWithBootstrap,
                      common_auth.AuthTestMixin,
                      _DomainAndProjectUserSystemAssignmentTests):

    def setUp(self):
        super(DomainUserTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.domain_user_id = PROVIDERS.identity_api.create_user(
            domain_user
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.domain_user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.domain_user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _DomainAndProjectUserSystemAssignmentTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project_reader = unit.new_user_ref(domain_id=self.domain_id)
        project_reader_id = PROVIDERS.identity_api.create_user(
            project_reader
        )['id']
        project = unit.new_project_ref(domain_id=self.domain_id)
        project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=project_reader_id,
            project_id=project_id
        )

        auth = self.build_authentication_request(
            user_id=project_reader_id,
            password=project_reader['password'],
            project_id=project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _DomainAndProjectUserSystemAssignmentTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        project_member = unit.new_user_ref(domain_id=self.domain_id)
        project_member_id = PROVIDERS.identity_api.create_user(
            project_member
        )['id']
        project = unit.new_project_ref(domain_id=self.domain_id)
        project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=project_member_id,
            project_id=project_id
        )

        auth = self.build_authentication_request(
            user_id=project_member_id,
            password=project_member['password'],
            project_id=project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _DomainAndProjectUserSystemAssignmentTests):

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

        project_admin = unit.new_user_ref(domain_id=self.domain_id)
        project_admin_id = PROVIDERS.identity_api.create_user(
            project_admin
        )['id']
        project = unit.new_project_ref(domain_id=self.domain_id)
        project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=project_admin_id,
            project_id=project_id
        )

        auth = self.build_authentication_request(
            user_id=project_admin_id,
            password=project_admin['password'],
            project_id=project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.grants have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:check_system_grant_for_user': base.SYSTEM_READER,
                'identity:list_system_grants_for_user': base.SYSTEM_READER,
                'identity:create_system_grant_for_user': base.SYSTEM_ADMIN,
                'identity:revoke_system_grant_for_user': base.SYSTEM_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))
