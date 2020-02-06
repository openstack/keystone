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

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserTokenTests(object):

    def test_user_can_validate_system_scoped_token(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.reader_role_id
        )

        system_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            system=True
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=system_auth)
            system_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = system_token
            c.get('/v3/auth/tokens', headers=self.headers)

    def test_user_can_validate_domain_scoped_token(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = unit.new_user_ref(domain_id=domain['id'])
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        domain_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=domain_auth)
            domain_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = domain_token
            c.get('/v3/auth/tokens', headers=self.headers)

    def test_user_can_validate_project_scoped_token(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        project_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=project_auth)
            project_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = project_token
            c.get('/v3/auth/tokens', headers=self.headers)


class _SystemMemberAndReaderTokenTests(object):

    def test_user_cannot_revoke_a_system_scoped_token(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.reader_role_id
        )

        system_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            system=True
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=system_auth)
            system_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = system_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_a_domain_scoped_token(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = unit.new_user_ref(domain_id=domain['id'])
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        domain_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=domain_auth)
            domain_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = domain_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_a_project_scoped_token(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        project_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=project_auth)
            project_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = project_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserTokenTests,
                        _SystemMemberAndReaderTokenTests):

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
                        _SystemUserTokenTests,
                        _SystemMemberAndReaderTokenTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
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


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _SystemUserTokenTests):

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

    def test_user_can_revoke_a_system_scoped_token(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.reader_role_id
        )

        system_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            system=True
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=system_auth)
            system_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = system_token
            c.delete('/v3/auth/tokens', headers=self.headers)

    def test_user_can_revoke_a_domain_scoped_token(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = unit.new_user_ref(domain_id=domain['id'])
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        domain_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=domain_auth)
            domain_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = domain_token
            c.delete('/v3/auth/tokens', headers=self.headers)

    def test_user_can_revoke_a_project_scoped_token(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        project_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=project_auth)
            project_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = project_token
            c.delete('/v3/auth/tokens', headers=self.headers)


class _DomainAndProjectUserTests(object):

    def test_user_can_validate_their_own_tokens(self):
        with self.test_client() as c:
            self.headers['X-Subject-Token'] = self.token_id
            c.get('/v3/auth/tokens', headers=self.headers)

    def test_user_can_revoke_their_own_tokens(self):
        with self.test_client() as c:
            self.headers['X-Subject-Token'] = self.token_id
            c.delete('/v3/auth/tokens', headers=self.headers)

    def test_user_cannot_validate_system_scoped_token(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.reader_role_id
        )

        system_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            system=True
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=system_auth)
            system_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = system_token
            c.get(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_system_scoped_token(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_system_grant_for_user(
            user['id'], self.bootstrapper.reader_role_id
        )

        system_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            system=True
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=system_auth)
            system_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = system_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_validate_domain_scoped_token(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = unit.new_user_ref(domain_id=domain['id'])
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        domain_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=domain_auth)
            domain_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = domain_token
            c.get(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_domain_scoped_token(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        user = unit.new_user_ref(domain_id=domain['id'])
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            domain_id=domain['id']
        )

        domain_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            domain_id=domain['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=domain_auth)
            domain_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = domain_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_validate_project_scoped_token(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        project_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=project_auth)
            project_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = project_token
            c.get(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_revoke_project_scoped_token(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user['id'] = PROVIDERS.identity_api.create_user(user)['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        project_auth = self.build_authentication_request(
            user_id=user['id'], password=user['password'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=project_auth)
            project_token = r.headers['X-Subject-Token']

        with self.test_client() as c:
            self.headers['X-Subject-Token'] = project_token
            c.delete(
                '/v3/auth/tokens', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class DomainUserTests(base_classes.TestCaseWithBootstrap,
                      common_auth.AuthTestMixin,
                      _DomainAndProjectUserTests):

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


class ProjectUserTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _DomainAndProjectUserTests):

    def setUp(self):
        super(ProjectUserTests, self).setUp()
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
