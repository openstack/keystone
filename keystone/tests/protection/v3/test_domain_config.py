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


class _SystemDomainAndProjectUserDomainConfigTests(object):

    def test_user_can_get_security_compliance_domain_config(self):
        # Set the security compliance configuration options
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex=password_regex
        )
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  % CONF.identity.default_domain_id, headers=self.headers)

    def test_user_can_get_security_compliance_domain_config_option(self):
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  '/password_regex_description'
                  % CONF.identity.default_domain_id, headers=self.headers)

    def test_can_get_security_compliance_config_with_user_from_other_domain(self):  # noqa: E501
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        # Create a user in the new domain
        user = unit.create_user(PROVIDERS.identity_api, domain['id'])

        # Create a project in the new domain
        project = unit.new_project_ref(domain_id=domain['id'])
        PROVIDERS.resource_api.create_project(project['id'], project)

        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        # Give the new user a non-admin role on the project
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'],
            project['id'],
            role['id']
        )
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        group = 'security_compliance'
        self.config_fixture.config(
            group=group,
            password_regex=password_regex
        )
        self.config_fixture.config(
            group=group,
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  % CONF.identity.default_domain_id, headers=self.headers)


class _SystemUserDomainConfigTests(object):

    def test_user_can_get_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config'
                  % domain['id'], headers=self.headers)

    def test_user_can_get_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap'
                  % domain['id'], headers=self.headers)

    def test_user_can_get_config_by_group_invalid_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        invalid_domain_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap'
                  % invalid_domain_id, headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_get_non_existent_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config' % domain['id'], headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_get_non_existent_config_group_invalid_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap'
                  % invalid_domain_id, headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_get_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap/url'
                  % domain['id'], headers=self.headers)

    def test_user_can_get_non_existent_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(domain['id'], config)
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap/user_tree_dn'
                  % domain['id'], headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_get_non_existent_config_option_invalid_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        config = {'ldap': {'url': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(domain['id'], config)
        invalid_domain_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap/user_tree_dn'
                  % invalid_domain_id, headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_get_security_compliance_domain_config(self):
        # Set the security compliance configuration options
        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex=password_regex
        )
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  % CONF.identity.default_domain_id, headers=self.headers)

    def test_user_can_get_security_compliance_domain_config_option(self):
        password_regex_description = uuid.uuid4().hex
        self.config_fixture.config(
            group='security_compliance',
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  '/password_regex_description'
                  % CONF.identity.default_domain_id, headers=self.headers)

    def test_can_get_security_compliance_config_with_user_from_other_domain(self):  # noqa: E501
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        password_regex = uuid.uuid4().hex
        password_regex_description = uuid.uuid4().hex
        group = 'security_compliance'
        self.config_fixture.config(
            group=group,
            password_regex=password_regex
        )
        self.config_fixture.config(
            group=group,
            password_regex_description=password_regex_description
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/security_compliance'
                  % CONF.identity.default_domain_id, headers=self.headers)

    def test_user_can_get_domain_config_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/default', headers=self.headers)

    def test_user_can_get_domain_group_config_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/ldap/default', headers=self.headers)

    def test_user_can_get_domain_config_option_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/ldap/url/default', headers=self.headers)


class _SystemReaderMemberDomainAndProjectUserDomainConfigTests(object):

    def test_user_cannot_create_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        with self.test_client() as c:
            c.put('/v3/domains/%s/config'
                  % domain['id'],
                  json={'config': unit.new_domain_config_ref()},
                  headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_update_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config'
                    % domain['id'], json={'config': new_config},
                    headers=self.headers,
                    expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_update_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config/ldap'
                    % domain['id'], json={'config': new_config},
                    headers=self.headers,
                    expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_update_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        new_config = {'url': uuid.uuid4().hex}
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config/ldap/url'
                    % domain['id'],
                    json={'config': new_config},
                    headers=self.headers,
                    expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_delete_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config' % domain['id'],
                     headers=self.headers,
                     expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_delete_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config/ldap'
                     % domain['id'], headers=self.headers,
                     expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_delete_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config/ldap/url'
                     % domain['id'], headers=self.headers,
                     expected_status_code=http.client.FORBIDDEN)


class _DomainAndProjectUserDomainConfigTests(object):

    def test_user_cannot_get_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config'
                  % domain['id'], headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap'
                  % domain['id'], headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_non_existant_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        with self.test_client() as c:
            c.get('/v3/domains/%s/config' % domain['id'], headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.get('/v3/domains/%s/config/ldap/url'
                  % domain['id'], headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_domain_config_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/default', headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_domain_group_config_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/ldap/default', headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_get_domain_config_option_default(self):
        with self.test_client() as c:
            c.get('/v3/domains/config/ldap/url/default', headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)


class SystemReaderTests(
        base_classes.TestCaseWithBootstrap,
        common_auth.AuthTestMixin,
        _SystemUserDomainConfigTests,
        _SystemReaderMemberDomainAndProjectUserDomainConfigTests,
        _SystemDomainAndProjectUserDomainConfigTests):

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


class SystemMemberTests(
        base_classes.TestCaseWithBootstrap,
        common_auth.AuthTestMixin,
        _SystemUserDomainConfigTests,
        _SystemReaderMemberDomainAndProjectUserDomainConfigTests,
        _SystemDomainAndProjectUserDomainConfigTests):

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
                       _SystemUserDomainConfigTests,
                       _SystemDomainAndProjectUserDomainConfigTests):

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

    def test_user_can_create_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        with self.test_client() as c:
            c.put('/v3/domains/%s/config'
                  % domain['id'],
                  json={'config': unit.new_domain_config_ref()},
                  headers=self.headers,
                  expected_status_code=http.client.CREATED)

    def test_user_cannot_create_invalid_domain_config(self):
        invalid_domain_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.put('/v3/domains/%s/config'
                  % invalid_domain_id,
                  json={'config': unit.new_domain_config_ref()},
                  headers=self.headers,
                  expected_status_code=http.client.NOT_FOUND)

    def test_user_can_update_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config'
                    % domain['id'], json={'config': new_config},
                    headers=self.headers)

    def test_user_can_update_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config/ldap'
                    % domain['id'], json={'config': new_config},
                    headers=self.headers)

    def test_user_can_update_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        new_config = {'url': uuid.uuid4().hex}
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.patch('/v3/domains/%s/config/ldap/url'
                    % domain['id'], json={'config': new_config},
                    headers=self.headers)

    def test_user_can_delete_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config' % domain['id'],
                     headers=self.headers)

    def test_user_can_delete_domain_group_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config/ldap'
                     % domain['id'], headers=self.headers)

    def test_user_can_delete_domain_config_option(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config/ldap/url'
                     % domain['id'], headers=self.headers)

    def test_user_cannot_delete_invalid_domain_config(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        PROVIDERS.domain_config_api.create_config(
            domain['id'], unit.new_domain_config_ref())
        invalid_domain_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.delete('/v3/domains/%s/config' % invalid_domain_id,
                     headers=self.headers,
                     expected_status_code=http.client.NOT_FOUND)


class DomainUserTests(
        base_classes.TestCaseWithBootstrap,
        common_auth.AuthTestMixin,
        _SystemDomainAndProjectUserDomainConfigTests,
        _DomainAndProjectUserDomainConfigTests,
        _SystemReaderMemberDomainAndProjectUserDomainConfigTests):

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


class ProjectUserTests(
        base_classes.TestCaseWithBootstrap,
        common_auth.AuthTestMixin,
        _SystemDomainAndProjectUserDomainConfigTests,
        _DomainAndProjectUserDomainConfigTests,
        _SystemReaderMemberDomainAndProjectUserDomainConfigTests):

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
        _SystemDomainAndProjectUserDomainConfigTests,
        _DomainAndProjectUserDomainConfigTests,
        _SystemReaderMemberDomainAndProjectUserDomainConfigTests):

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
