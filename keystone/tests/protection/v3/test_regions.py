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

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _UserRegionTests:
    """Common default functionality for all users."""

    def test_user_can_get_a_region(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.get('/v3/regions/{}'.format(region['id']), headers=self.headers)

    def test_user_can_list_regions(self):
        expected_regions = []
        for _ in range(2):
            region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())
            expected_regions.append(region['id'])

        with self.test_client() as c:
            r = c.get('/v3/regions', headers=self.headers)
            for region in r.json['regions']:
                self.assertIn(region['id'], expected_regions)


class _SystemReaderAndMemberUserRegionTests:
    """Common default functionality for system readers and system members."""

    def test_user_cannot_create_regions(self):
        create = {'region': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/regions',
                json=create,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            update = {'region': {'description': uuid.uuid4().hex}}
            c.patch(
                '/v3/regions/{}'.format(region['id']),
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/regions/{}'.format(region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )


class _DomainAndProjectUserRegionTests:
    """Common default functionality for all domain and project users."""

    def test_user_cannot_create_regions(self):
        create = {'region': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/regions',
                json=create,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_update_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            update = {'region': {'description': uuid.uuid4().hex}}
            c.patch(
                '/v3/regions/{}'.format(region['id']),
                json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )

    def test_user_cannot_delete_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/regions/{}'.format(region['id']),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN,
            )


class SystemReaderTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserRegionTests,
    _SystemReaderAndMemberUserRegionTests,
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


class SystemMemberTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserRegionTests,
    _SystemReaderAndMemberUserRegionTests,
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


class SystemAdminTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserRegionTests,
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

    def test_user_can_create_regions(self):
        create = {'region': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post('/v3/regions', json=create, headers=self.headers)

    def test_user_can_update_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            update = {'region': {'description': uuid.uuid4().hex}}
            c.patch(
                '/v3/regions/{}'.format(region['id']),
                json=update,
                headers=self.headers,
            )

    def test_user_can_delete_regions(self):
        region = PROVIDERS.catalog_api.create_region(unit.new_region_ref())

        with self.test_client() as c:
            c.delete(
                '/v3/regions/{}'.format(region['id']), headers=self.headers
            )


class DomainUserTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserRegionTests,
    _DomainAndProjectUserRegionTests,
):
    def setUp(self):
        super().setUp()
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
            self.bootstrapper.admin_role_id,
            user_id=self.user_id,
            domain_id=self.domain_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectUserTests(
    base_classes.TestCaseWithBootstrap,
    common_auth.AuthTestMixin,
    _UserRegionTests,
    _DomainAndProjectUserRegionTests,
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
            project_id=self.bootstrapper.project_id,
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
    _UserRegionTests,
    _DomainAndProjectUserRegionTests,
):
    def setUp(self):
        super().setUp()
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
            self.bootstrapper.member_role_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=user['password'],
            project_id=self.project_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}
