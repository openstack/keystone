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


class _SystemUserPoliciesAssociationTests(object):
    """Common default functionality for all system users."""

    def test_user_can_check_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id'])

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                  % (policy['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.NO_CONTENT)

    def test_user_can_check_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], service_id=service['id'])

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                  % (policy['id'], service['id']),
                  headers=self.headers,
                  expected_status_code=http.client.NO_CONTENT)

    def test_user_can_check_policy_association_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], service_id=service['id'], region_id=region['id']
        )

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                  % (policy['id'], service['id'], region['id']),
                  headers=self.headers,
                  expected_status_code=http.client.NO_CONTENT)

    def test_user_can_get_policy_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id']
        )
        with self.test_client() as c:
            c.get('/v3/endpoints/%s/OS-ENDPOINT-POLICY/policy'
                  % (endpoint['id']),
                  headers=self.headers)

    def test_user_list_endpoints_for_policy(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id']
        )
        with self.test_client() as c:
            r = c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints'
                      % (policy['id']),
                      headers=self.headers)
            for endpoint_itr in r.json['endpoints']:
                self.assertIn(endpoint['id'], endpoint_itr['id'])


class _SystemReaderAndMemberPoliciesAssociationTests(object):

    def test_user_cannot_create_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_policy_assoc_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_assoc_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainAndProjectUserPolicyAssociationsTests(object):

    def test_user_cannot_check_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id'])

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                  % (policy['id'], endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_check_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], service_id=service['id'])

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                  % (policy['id'], service['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_check_policy_association_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)

        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], service_id=service['id'], region_id=region['id']
        )

        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                  % (policy['id'], service['id'], region['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_policy_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id']
        )
        with self.test_client() as c:
            c.get('/v3/endpoints/%s/OS-ENDPOINT-POLICY/policy'
                  % (endpoint['id']),
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_list_endpoints_for_policy(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy['id'], endpoint['id']
        )
        with self.test_client() as c:
            c.get('/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints'
                  % (policy['id']), headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN
                  )

    def test_user_cannot_create_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_policy_assoc_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_policy_assoc_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserPoliciesAssociationTests,
                        _SystemReaderAndMemberPoliciesAssociationTests):

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
                        _SystemUserPoliciesAssociationTests,
                        _SystemReaderAndMemberPoliciesAssociationTests):

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
                       _SystemUserPoliciesAssociationTests):

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

    def test_user_can_create_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_delete_policy_association_for_endpoint(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        endpoint = unit.new_endpoint_ref(service['id'], region_id=None)
        endpoint = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/endpoints/%s'
                % (policy['id'], endpoint['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_create_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_delete_policy_association_for_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s'
                % (policy['id'], service['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_create_policy_association_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.put(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_delete_policy_association_for_region_and_service(self):
        policy = unit.new_policy_ref()
        policy = PROVIDERS.policy_api.create_policy(policy['id'], policy)
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/policies/%s/OS-ENDPOINT-POLICY/services/%s/regions/%s'
                % (policy['id'], service['id'], region['id']),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )


class DomainUserTests(base_classes.TestCaseWithBootstrap,
                      common_auth.AuthTestMixin,
                      _DomainAndProjectUserPolicyAssociationsTests):

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
                       _DomainAndProjectUserPolicyAssociationsTests):

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
        _DomainAndProjectUserPolicyAssociationsTests):

    def setUp(self):
        super(ProjectUserTestsWithoutEnforceScope, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))

        # Explicityly set enforce_scope to False to make sure we maintain
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
            self.bootstrapper.member_role_id, user_id=self.user_id,
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
