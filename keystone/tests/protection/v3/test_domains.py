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

from keystone.common.policies import domain as dp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserDomainTests(object):

    def test_user_can_list_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get('/v3/domains', headers=self.headers)
            domain_ids = []
            for domain in r.json['domains']:
                domain_ids.append(domain['id'])
            self.assertIn(domain['id'], domain_ids)

    def test_user_can_filter_domains_by_name(self):
        domain_name = uuid.uuid4().hex
        domain = unit.new_domain_ref(name=domain_name)
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)

        PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains?name=%s' % domain_name,
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['domains']))
            self.assertEqual(domain['id'], r.json['domains'][0]['id'])

    def test_user_can_filter_domains_by_enabled(self):
        enabled_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        disabled_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref(enabled=False)
        )

        with self.test_client() as c:
            r = c.get('/v3/domains?enabled=true', headers=self.headers)
            enabled_domain_ids = []
            for domain in r.json['domains']:
                enabled_domain_ids.append(domain['id'])
            self.assertIn(enabled_domain['id'], enabled_domain_ids)
            self.assertNotIn(disabled_domain['id'], enabled_domain_ids)

            r = c.get('/v3/domains?enabled=false', headers=self.headers)
            disabled_domain_ids = []
            for domain in r.json['domains']:
                disabled_domain_ids.append(domain['id'])
            self.assertIn(disabled_domain['id'], disabled_domain_ids)
            self.assertNotIn(enabled_domain['id'], disabled_domain_ids)

    def test_user_can_get_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get('/v3/domains/%s' % domain['id'], headers=self.headers)
            self.assertEqual(domain['id'], r.json['domain']['id'])


class _SystemMemberAndReaderDomainTests(object):

    def test_user_cannot_create_a_domain(self):
        create = {'domain': {'name': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/domains', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        update = {'domain': {'description': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/domains/%s' % domain['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s' % domain['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainAndProjectUserDomainTests(object):

    def test_user_can_get_a_domain(self):
        with self.test_client() as c:
            r = c.get('/v3/domains/%s' % self.domain_id, headers=self.headers)
            self.assertEqual(self.domain_id, r.json['domain']['id'])

    def test_user_cannot_get_a_domain_they_are_not_authorized_to_access(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s' % domain['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_domains(self):
        with self.test_client() as c:
            c.get(
                '/v3/domains', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_domains_by_name(self):
        domain_name = uuid.uuid4().hex
        domain = unit.new_domain_ref(name=domain_name)
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)

        PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.get(
                '/v3/domains?name=%s' % domain_name,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_filter_domains_by_enabled(self):
        with self.test_client() as c:
            c.get(
                '/v3/domains?enabled=true', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
            c.get(
                '/v3/domains?enabled=false', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        update = {'domain': {'description': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/domains/%s' % domain['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_a_domain(self):
        create = {'domain': {'name': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/domains', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            update = {'domain': {'enabled': False}}
            path = '/v3/domains/%s' % domain['id']
            c.patch(
                path, json=update, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_non_existant_domain_forbidden(self):

        with self.test_client() as c:
            c.get(
                '/v3/domains/%s' % uuid.uuid4().hex,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserDomainTests,
                        _SystemMemberAndReaderDomainTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.system_reader_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.system_reader_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.system_reader_id, password=system_reader['password'],
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
                        _SystemUserDomainTests,
                        _SystemMemberAndReaderDomainTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.system_member_id = PROVIDERS.identity_api.create_user(
            system_member
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.system_member_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.system_member_id, password=system_member['password'],
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
                       _SystemUserDomainTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.system_admin_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.system_admin_id,
            password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_update_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        update = {'domain': {'description': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/domains/%s' % domain['id'], json=update,
                headers=self.headers
            )

    def test_user_can_create_a_domain(self):
        create = {'domain': {'name': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/domains', json=create, headers=self.headers
            )

    def test_user_can_delete_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            update = {'domain': {'enabled': False}}
            path = '/v3/domains/%s' % domain['id']
            c.patch(path, json=update, headers=self.headers)
            c.delete(path, headers=self.headers)


class DomainUserTests(base_classes.TestCaseWithBootstrap,
                      common_auth.AuthTestMixin,
                      _DomainAndProjectUserDomainTests):

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
                         _DomainAndProjectUserDomainTests):

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
                         _DomainAndProjectUserDomainTests):

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
                        _DomainAndProjectUserDomainTests):

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
        # keystone.common.policies.domains have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_domain': (
                    dp.SYSTEM_USER_OR_DOMAIN_USER_OR_PROJECT_USER
                )
            }
            f.write(jsonutils.dumps(overridden_policies))
