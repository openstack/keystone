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

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _ImpliedRolesSetupMixin(object):
    def _create_test_roles(self):
        ref = unit.new_role_ref()
        role = PROVIDERS.role_api.create_role(ref['id'], ref)
        self.prior_role_id = role['id']
        ref = unit.new_role_ref()
        role = PROVIDERS.role_api.create_role(ref['id'], ref)
        self.implied_role_id = role['id']


class _SystemUserImpliedRoleTests(object):
    """Common default functionality for all system users."""

    def test_user_can_list_implied_roles(self):
        PROVIDERS.role_api.create_implied_role(self.prior_role_id,
                                               self.implied_role_id)

        with self.test_client() as c:
            r = c.get('/v3/roles/%s/implies' % self.prior_role_id,
                      headers=self.headers)
            self.assertEqual(1, len(r.json['role_inference']['implies']))

    def test_user_can_get_an_implied_role(self):
        PROVIDERS.role_api.create_implied_role(self.prior_role_id,
                                               self.implied_role_id)

        with self.test_client() as c:
            c.get(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers)
            c.head(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT)

    def test_user_can_list_role_inference_rules(self):
        PROVIDERS.role_api.create_implied_role(self.prior_role_id,
                                               self.implied_role_id)

        with self.test_client() as c:
            r = c.get('/v3/role_inferences',
                      headers=self.headers)
            # There should be three role inferences: two from the defaults and
            # one from the test setup
            self.assertEqual(3, len(r.json['role_inferences']))


class _SystemReaderAndMemberImpliedRoleTests(object):
    """Common default functionality for system readers and system members."""

    def test_user_cannot_create_implied_roles(self):
        with self.test_client() as c:
            c.put(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_implied_roles(self):
        PROVIDERS.role_api.create_implied_role(self.prior_role_id,
                                               self.implied_role_id)

        with self.test_client() as c:
            c.delete(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _ImpliedRolesSetupMixin,
                        _SystemUserImpliedRoleTests,
                        _SystemReaderAndMemberImpliedRoleTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self._create_test_roles()

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
                        _ImpliedRolesSetupMixin,
                        _SystemUserImpliedRoleTests,
                        _SystemReaderAndMemberImpliedRoleTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self._create_test_roles()

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
                       _ImpliedRolesSetupMixin,
                       _SystemUserImpliedRoleTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self._create_test_roles()

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

    def test_user_can_create_implied_roles(self):
        with self.test_client() as c:
            c.put(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers,
                expected_status_code=http.client.CREATED
            )

    def test_user_can_delete_implied_roles(self):
        PROVIDERS.role_api.create_implied_role(self.prior_role_id,
                                               self.implied_role_id)

        with self.test_client() as c:
            c.delete(
                '/v3/roles/%s/implies/%s' % (
                    self.prior_role_id, self.implied_role_id),
                headers=self.headers
            )
