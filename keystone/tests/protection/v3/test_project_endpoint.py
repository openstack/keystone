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


class _SystemUserProjectEndpointTests(object):
    """Common default functionality for all system users."""

    def test_user_can_list_projects_for_endpoint(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            r = c.get('/v3/OS-EP-FILTER/endpoints/%s/projects'
                      % endpoint['id'],
                      headers=self.headers)
            for project_itr in r.json['projects']:
                self.assertIn(project['id'], project_itr['id'])

    def test_user_can_check_endpoint_in_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            c.get('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                  % (project['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.NO_CONTENT)

    def test_user_can_list_endpoints_for_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            r = c.get('/v3/OS-EP-FILTER/projects/%s/endpoints' % project['id'],
                      headers=self.headers)
            for endpoint_itr in r.json['endpoints']:
                self.assertIn(endpoint['id'], endpoint_itr['id'])


class _SystemReaderAndMemberProjectEndpointTests(object):

    def test_user_cannot_add_endpoint_to_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        with self.test_client() as c:
            c.put('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                  % (project['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_remove_endpoint_from_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        with self.test_client() as c:
            c.delete('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                     % (project['id'], endpoint['id']),
                     headers=self.headers,
                     expected_status_code=http.client.FORBIDDEN)


class _DomainAndProjectUserProjectEndpointTests(object):

    def test_user_cannot_list_projects_for_endpoint(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            c.get('/v3/OS-EP-FILTER/endpoints/%s/projects' % endpoint['id'],
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_check_endpoint_in_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            c.get('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                  % (project['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_list_endpoints_for_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            c.get('/v3/OS-EP-FILTER/projects/%s/endpoints' % project['id'],
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserProjectEndpointTests,
                        _SystemReaderAndMemberProjectEndpointTests):

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
                        _SystemUserProjectEndpointTests,
                        _SystemReaderAndMemberProjectEndpointTests):

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
                       _SystemUserProjectEndpointTests):

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

    def test_user_can_add_endpoint_to_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        with self.test_client() as c:
            c.put('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                  % (project['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.NO_CONTENT)

    def test_user_can_remove_endpoint_from_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint['id'], project['id'])
        with self.test_client() as c:
            c.delete('/v3/OS-EP-FILTER/projects/%s/endpoints/%s'
                     % (project['id'], endpoint['id']),
                     headers=self.headers,
                     expected_status_code=http.client.NO_CONTENT)


class DomainUserTests(base_classes.TestCaseWithBootstrap,
                      common_auth.AuthTestMixin,
                      _DomainAndProjectUserProjectEndpointTests,
                      _SystemReaderAndMemberProjectEndpointTests):

    def setUp(self):
        super(DomainUserTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
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
            user_id=self.user_id,
            password=domain_admin['password'],
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
                       _DomainAndProjectUserProjectEndpointTests,
                       _SystemReaderAndMemberProjectEndpointTests):

    def setUp(self):
        super(ProjectUserTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

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


class ProjectUserTestsWithoutEnforceScope(
        base_classes.TestCaseWithBootstrap,
        common_auth.AuthTestMixin,
        _DomainAndProjectUserProjectEndpointTests,
        _SystemReaderAndMemberProjectEndpointTests):

    def _override_policy(self):
        # TODO(cmurphy): Remove this once the deprecated policies in
        # keystone.common.policies.project_endpoint have been removed. This is
        # only here to make sure we test the new policies instead of the
        # deprecated ones. Oslo.policy will OR deprecated policies with new
        # policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users. This
        # will cause these specific tests to fail since we're trying to correct
        # this broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_projects_for_endpoint': bp.SYSTEM_READER,
                'identity:add_endpoint_to_project': bp.SYSTEM_ADMIN,
                'identity:check_endpoint_in_project': bp.SYSTEM_READER,
                'identity:list_endpoints_for_project': bp.SYSTEM_READER,
                'identity:remove_endpoint_from_project': bp.SYSTEM_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))

    def setUp(self):
        super(ProjectUserTestsWithoutEnforceScope, self).setUp()
        self.loadapp()
        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        self._override_policy()
        # Explicity set enforce_scope to False to make sure we maintain
        # backwards compatibility with project users.
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        user = unit.new_user_ref(domain_id=domain['id'])
        self.user_id = PROVIDERS.identity_api.create_user(user)['id']

        self.project_id = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=domain['id'])
        )['id']

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=user['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}
