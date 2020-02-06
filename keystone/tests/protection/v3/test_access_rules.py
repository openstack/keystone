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
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _UserAccessRuleTests(object):
    """Test cases for anyone that has a valid user token."""

    def test_user_can_get_their_access_rules(self):
        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                self.user_id, app_cred['access_rules'][0]['id'])
            c.get(path, headers=self.headers)

    def test_user_can_list_their_access_rules(self):
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': uuid.uuid4().hex,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        with self.test_client() as c:
            r = c.get('/v3/users/%s/access_rules' % self.user_id,
                      headers=self.headers)
            self.assertEqual(len(r.json['access_rules']), 1)

    def test_user_can_delete_their_access_rules(self):
        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        PROVIDERS.application_credential_api.delete_application_credential(
            app_cred['id'])
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                self.user_id, access_rule_id)
            c.delete(path, headers=self.headers)


class _ProjectUsersTests(object):
    """Users who have project role authorization observe the same behavior."""

    def test_user_cannot_get_access_rules_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )

        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.get(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_own_non_existent_access_rule_not_found(self):
        with self.test_client() as c:
            c.get(
                '/v3/users/%s/access_rules/%s' % (
                    self.user_id, uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_cannot_get_non_existent_access_rule_other_user_forbidden(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.get(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_access_rules_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': uuid.uuid4().hex,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)

        with self.test_client() as c:
            path = '/v3/users/%s/access_rules' % user['id']
            c.get(path, headers=self.headers,
                  expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_delete_access_rules_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        PROVIDERS.application_credential_api.delete_application_credential(
            app_cred['id'])
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_cannot_delete_non_existent_access_rule_other_user_forbidden(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _SystemUserAccessRuleTests(object):
    """Tests that are common across all system users."""

    def test_user_can_list_access_rules_for_other_users(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )

        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': uuid.uuid4().hex,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)

        with self.test_client() as c:
            r = c.get('/v3/users/%s/access_rules' % user['id'],
                      headers=self.headers)
            self.assertEqual(1, len(r.json['access_rules']))

    def test_user_cannot_get_non_existent_access_rule_not_found(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.get(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserAccessRuleTests):

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

    def test_user_cannot_delete_access_rules_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )

        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        PROVIDERS.application_credential_api.delete_application_credential(
            app_cred['id'])
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_access_rule_forbidden(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserAccessRuleTests):

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

    def test_user_cannot_delete_access_rules_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )

        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        PROVIDERS.application_credential_api.delete_application_credential(
            app_cred['id'])
        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.delete(
                path, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_access_rule_forbidden(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _SystemUserAccessRuleTests):

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

    def test_user_can_delete_access_rules_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=user['id'],
            project_id=project['id']
        )
        access_rule_id = uuid.uuid4().hex
        app_cred = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'user_id': user['id'],
            'project_id': project['id'],
            'secret': uuid.uuid4().hex,
            'access_rules': [{
                'id': access_rule_id,
                'service': uuid.uuid4().hex,
                'path': uuid.uuid4().hex,
                'method': uuid.uuid4().hex[16:]
            }]
        }
        PROVIDERS.application_credential_api.create_application_credential(
            app_cred)
        PROVIDERS.application_credential_api.delete_application_credential(
            app_cred['id'])

        with self.test_client() as c:
            path = '/v3/users/%s/access_rules/%s' % (
                user['id'], access_rule_id)
            c.delete(path, headers=self.headers)

    def test_user_cannot_delete_non_existent_access_rule_not_found(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/access_rules/%s' % (
                    user['id'], uuid.uuid4().hex),
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _UserAccessRuleTests,
                         _ProjectUsersTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_reader
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_reader['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _UserAccessRuleTests,
                         _ProjectUsersTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            project_member
        )['id']
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.project_id = PROVIDERS.resource_api.create_project(
            project['id'], project
        )['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=project_member['password'],
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserAccessRuleTests,
                        _ProjectUsersTests):

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
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        self.project_id = self.bootstrapper.project_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}
