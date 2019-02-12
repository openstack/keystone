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


def _create_limit_and_dependencies():
    """Create a limit and its dependencies to test with."""
    service = PROVIDERS.catalog_api.create_service(
        uuid.uuid4().hex, unit.new_service_ref()
    )

    registered_limit = unit.new_registered_limit_ref(
        service_id=service['id'], id=uuid.uuid4().hex
    )
    registered_limits = (
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit]
        )
    )
    registered_limit = registered_limits[0]

    project = PROVIDERS.resource_api.create_project(
        uuid.uuid4().hex,
        unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
    )

    limit = unit.new_limit_ref(
        project_id=project['id'], service_id=service['id'],
        resource_name=registered_limit['resource_name'],
        resource_limit=5, id=uuid.uuid4().hex
    )
    limits = PROVIDERS.unified_limit_api.create_limits([limit])
    return limits


class _UserLimitTests(object):
    """Common default functionality for all users except system admins."""

    def test_user_can_get_limit_model(self):
        with self.test_client() as c:
            c.get('/v3/limits/model', headers=self.headers)

    def test_user_can_get_a_limit(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            r = c.get('/v3/limits/%s' % limit['id'], headers=self.headers)
            self.assertEqual(limit['id'], r.json['limit']['id'])

    def test_user_can_list_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            r = c.get('/v3/limits', headers=self.headers)
            self.assertTrue(len(r.json['limits']) == 1)
            self.assertEqual(limit['id'], r.json['limits'][0]['id'])

    def test_user_cannot_create_limits(self):
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        registered_limit = unit.new_registered_limit_ref(
            service_id=service['id'], id=uuid.uuid4().hex
        )
        registered_limits = (
            PROVIDERS.unified_limit_api.create_registered_limits(
                [registered_limit]
            )
        )
        registered_limit = registered_limits[0]

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        create = {
            'limits': [
                unit.new_limit_ref(
                    project_id=project['id'], service_id=service['id'],
                    resource_name=registered_limit['resource_name'],
                    resource_limit=5
                )
            ]
        }

        with self.test_client() as c:
            c.post(
                '/v3/limits', json=create, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        update = {'limits': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/limits/%s' % limit['id'], json=update,
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_delete_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            c.delete(
                '/v3/limits/%s' % limit['id'],
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserLimitTests):
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
                        _UserLimitTests):

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
                       common_auth.AuthTestMixin):

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

    def test_user_can_get_a_limit(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            r = c.get('/v3/limits/%s' % limit['id'], headers=self.headers)
            self.assertEqual(limit['id'], r.json['limit']['id'])

    def test_user_can_list_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            r = c.get('/v3/limits', headers=self.headers)
            self.assertTrue(len(r.json['limits']) == 1)
            self.assertEqual(limit['id'], r.json['limits'][0]['id'])

    def test_user_can_create_limits(self):
        service = PROVIDERS.catalog_api.create_service(
            uuid.uuid4().hex, unit.new_service_ref()
        )

        registered_limit = unit.new_registered_limit_ref(
            service_id=service['id'], id=uuid.uuid4().hex
        )
        registered_limits = (
            PROVIDERS.unified_limit_api.create_registered_limits(
                [registered_limit]
            )
        )
        registered_limit = registered_limits[0]

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        create = {
            'limits': [
                unit.new_limit_ref(
                    project_id=project['id'], service_id=service['id'],
                    resource_name=registered_limit['resource_name'],
                    resource_limit=5
                )
            ]
        }

        with self.test_client() as c:
            c.post('/v3/limits', json=create, headers=self.headers)

    def test_user_can_update_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        update = {'limits': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/limits/%s' % limit['id'], json=update,
                headers=self.headers
            )

    def test_user_can_delete_limits(self):
        limits = _create_limit_and_dependencies()
        limit = limits[0]

        with self.test_client() as c:
            c.delete('/v3/limits/%s' % limit['id'], headers=self.headers)
