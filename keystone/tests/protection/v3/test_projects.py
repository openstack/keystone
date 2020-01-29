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

from keystone.common.policies import project as pp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserTests(object):
    """Common default functionality for all system users."""

    def test_user_can_list_projects(self):
        PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/projects', headers=self.headers)
            self.assertEqual(2, len(r.json['projects']))

    def test_user_can_list_projects_for_other_users(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(
                CONF.identity.default_domain_id,
                id=uuid.uuid4().hex
            )
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/projects' % user['id'], headers=self.headers,
            )
            self.assertEqual(1, len(r.json['projects']))
            self.assertEqual(project['id'], r.json['projects'][0]['id'])

    def test_user_can_get_a_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/projects/%s' % project['id'], headers=self.headers)
            self.assertEqual(project['id'], r.json['project']['id'])

    def test_user_cannot_get_non_existent_project_not_found(self):
        with self.test_client() as c:
            c.get(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )


class _SystemMemberAndReaderProjectTests(object):
    """Common default functionality for system members and system readers."""

    def test_user_cannot_create_projects(self):
        create = {
            'project': unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        with self.test_client() as c:
            c.post(
                '/v3/projects', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_project_forbidden(self):
        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_project_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainUsersTests(object):
    """Common default functionality for all domain users."""

    def test_user_can_list_projects_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/projects', headers=self.headers)
            self.assertEqual(1, len(r.json['projects']))
            self.assertEqual(project['id'], r.json['projects'][0]['id'])

    def test_user_cannot_list_projects_in_other_domain(self):
        PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/projects', headers=self.headers)
            self.assertEqual(0, len(r.json['projects']))

    def test_user_can_get_a_project_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            r = c.get('/v3/projects/%s' % project['id'], headers=self.headers)
            self.assertEqual(project['id'], r.json['project']['id'])

    def test_user_cannot_get_a_project_in_other_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_list_projects_for_user_in_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(
                self.domain_id,
                id=uuid.uuid4().hex
            )
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/projects' % user['id'], headers=self.headers
            )
            self.assertEqual(1, len(r.json['projects']))
            self.assertEqual(project['id'], r.json['projects'][0]['id'])

    def test_user_cannot_list_projects_for_user_in_other_domain(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(
                CONF.identity.default_domain_id,
                id=uuid.uuid4().hex
            )
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/users/%s/projects' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainMemberAndReaderProjectTests(object):
    """Common default functionality for domain member and domain readers."""

    def test_user_cannot_create_projects_within_domain(self):
        create = {'project': unit.new_project_ref(domain_id=self.domain_id)}

        with self.test_client() as c:
            c.post(
                '/v3/projects', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_projects_in_other_domains(self):
        create = {
            'project': unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        with self.test_client() as c:
            c.post(
                '/v3/projects', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_projects_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_projects_in_other_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_project_forbidden(self):
        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_projects_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_projects_in_other_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_projects_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserTests,
                        _SystemMemberAndReaderProjectTests):

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
                        _SystemUserTests,
                        _SystemMemberAndReaderProjectTests):

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
                       _SystemUserTests):

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

    def test_user_can_create_projects(self):
        create = {
            'project': unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        with self.test_client() as c:
            c.post('/v3/projects', json=create, headers=self.headers)

    def test_user_can_update_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers
            )

    def test_user_can_update_non_existent_project_not_found(self):
        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_user_can_delete_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete('/v3/projects/%s' % project['id'], headers=self.headers)

    def test_user_can_delete_non_existent_project_not_found(self):
        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_user_can_list_their_projects(self):
        other_project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        user_project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=user_project['id']
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/projects' % self.user_id, headers=self.headers,
            )
            self.assertEqual(2, len(r.json['projects']))
            project_ids = []
            for project in r.json['projects']:
                project_ids.append(project['id'])

            self.assertIn(user_project['id'], project_ids)
            self.assertIn(self.bootstrapper.project_id, project_ids)
            self.assertNotIn(other_project['id'], project_ids)


class DomainReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _DomainUsersTests,
                        _DomainMemberAndReaderProjectTests):

    def setUp(self):
        super(DomainReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _DomainUsersTests,
                        _DomainMemberAndReaderProjectTests):

    def setUp(self):
        super(DomainMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_user = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_user['password'],
            domain_id=self.domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _DomainUsersTests):

    def setUp(self):
        super(DomainAdminTests, self).setUp()
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
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.project have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_project': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER_OR_PROJECT_USER),
                'identity:list_user_projects': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER_OR_OWNER),
                'identity:list_projects': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER),
                'identity:create_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:update_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:delete_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))

    def test_user_can_create_projects_within_domain(self):
        create = {'project': unit.new_project_ref(domain_id=self.domain_id)}

        with self.test_client() as c:
            c.post('/v3/projects', json=create, headers=self.headers)

    def test_user_cannot_create_projects_in_other_domains(self):
        create = {
            'project': unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        with self.test_client() as c:
            c.post(
                '/v3/projects', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_update_projects_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers
            )

    def test_user_cannot_update_projects_in_other_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_project_forbidden(self):
        # Because domain users operate outside of system scope, we can't
        # confidently return a Not Found here because they aren't system users.
        # The best we can do is return a Forbidden because we need the
        # project's domain in order to resolve the policy check, and the
        # project doesn't exist. This errors on the side of opacity and returns
        # a 403 instead of a 404.
        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_delete_projects_within_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=self.domain_id)
        )

        with self.test_client() as c:
            c.delete('/v3/projects/%s' % project['id'], headers=self.headers)

    def test_user_cannot_delete_projects_in_other_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_projects_forbidden(self):
        # Because domain users operate outside of system scope, we can't
        # confidently return a Not Found here because they aren't system users.
        # The best we can do is return a Forbidden because we need the
        # project's domain in order to resolve the policy check, and the
        # project doesn't exist. This errors on the side of opacity and returns
        # a 403 instead of a 404.
        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class ProjectUserTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin):

    def setUp(self):
        super(ProjectUserTests, self).setUp()
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

        self.user_id = self.bootstrapper.admin_user_id
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.bootstrapper.project_id
        )
        self.project_id = self.bootstrapper.project_id

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            project_id=self.bootstrapper.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def _override_policy(self):
        # TODO(lbragstad): Remove this once the deprecated policies in
        # keystone.common.policies.project have been removed. This is only
        # here to make sure we test the new policies instead of the deprecated
        # ones. Oslo.policy will OR deprecated policies with new policies to
        # maintain compatibility and give operators a chance to update
        # permissions or update policies without breaking users. This will
        # cause these specific tests to fail since we're trying to correct this
        # broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_project': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER_OR_PROJECT_USER),
                'identity:list_user_projects': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER_OR_OWNER),
                'identity:list_projects': (
                    pp.SYSTEM_READER_OR_DOMAIN_READER),
                'identity:create_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:update_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
                'identity:delete_project': pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN
            }
            f.write(jsonutils.dumps(overridden_policies))

    def test_user_cannot_list_projects(self):
        # This test is assuming the user calling the API has a role assignment
        # on the project created by ``keystone-manage bootstrap``.
        with self.test_client() as c:
            c.get(
                '/v3/projects', headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_projects_for_others(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(
                CONF.identity.default_domain_id,
                id=uuid.uuid4().hex
            )
        )

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.get(
                '/v3/users/%s/projects' % user['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_list_their_projects(self):
        # Users can get this information from the GET /v3/auth/projects API or
        # the GET /v3/users/{user_id}/projects API. The GET /v3/projects API is
        # administrative, reserved for system and domain users.
        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/projects' % self.user_id, headers=self.headers,
            )
            self.assertEqual(1, len(r.json['projects']))
            self.assertEqual(self.project_id, r.json['projects'][0]['id'])

    def test_user_can_get_their_project(self):
        with self.test_client() as c:
            c.get('/v3/projects/%s' % self.project_id, headers=self.headers)

    def test_user_cannot_get_other_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_create_projects(self):
        create = {
            'project': unit.new_project_ref(
                domain_id=CONF.identity.default_domain_id
            )
        }

        with self.test_client() as c:
            c.post(
                '/v3/projects', json=create, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % project['id'], json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_non_existent_project_forbidden(self):
        update = {'project': {'description': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.patch(
                '/v3/projects/%s' % uuid.uuid4().hex, json=update,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_projects(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % project['id'], headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_non_existent_project_forbidden(self):
        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s' % uuid.uuid4().hex, headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
