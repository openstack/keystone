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


class _UserEC2CredentialTests(object):

    def test_user_can_get_their_ec2_credentials(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/users/%s/credentials/OS-EC2' % self.user_id,
                       json={'tenant_id': project['id']}, headers=self.headers)

            credential_id = r.json['credential']['access']

            path = '/v3/users/%s/credentials/OS-EC2/%s' % (
                self.user_id, credential_id)
            r = c.get(path, headers=self.headers)
            self.assertEqual(
                self.user_id, r.json['credential']['user_id']
            )

    def test_user_can_list_their_ec2_credentials(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=project['id']
        )

        with self.test_client() as c:
            c.post('/v3/users/%s/credentials/OS-EC2' % self.user_id,
                   json={'tenant_id': project['id']}, headers=self.headers)

            path = '/v3/users/%s/credentials/OS-EC2' % self.user_id
            r = c.get(path, headers=self.headers)
            for credential in r.json['credentials']:
                self.assertEqual(
                    self.user_id, credential['user_id']
                )

    def test_user_create_their_ec2_credentials(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=project['id']
        )

        with self.test_client() as c:
            c.post('/v3/users/%s/credentials/OS-EC2' % self.user_id,
                   json={'tenant_id': project['id']}, headers=self.headers,
                   expected_status_code=http.client.CREATED)

    def test_user_delete_their_ec2_credentials(self):
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=project['id']
        )

        with self.test_client() as c:
            r = c.post('/v3/users/%s/credentials/OS-EC2' % self.user_id,
                       json={'tenant_id': project['id']}, headers=self.headers)
            credential_id = r.json['credential']['access']

            c.delete('/v3/users/%s/credentials/OS-EC2/%s' % (
                     self.user_id, credential_id),
                     headers=self.headers)

    def test_user_cannot_create_ec2_credentials_for_others(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                   json={'tenant_id': project['id']}, headers=self.headers,
                   expected_status_code=http.client.FORBIDDEN)

    def test_user_cannot_delete_ec2_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            r = c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                       json={'tenant_id': project['id']}, headers=headers)
            credential_id = r.json['credential']['access']

            c.delete('/v3/users/%s/credentials/OS-EC2/%s' % (
                     self.user_id, credential_id),
                     headers=self.headers,
                     expected_status_code=http.client.FORBIDDEN)


class _SystemUserTests(object):

    def test_user_can_get_ec2_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            r = c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                       json={'tenant_id': project['id']}, headers=headers)
            credential_id = r.json['credential']['access']

            path = '/v3/users/%s/credentials/OS-EC2/%s' % (
                self.user_id, credential_id)
            c.get(path, headers=self.headers,
                  expected_status_code=http.client.OK)


class _SystemReaderAndMemberTests(object):

    def test_user_cannot_list_ec2_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                   json={'tenant_id': project['id']}, headers=headers)

            path = '/v3/users/%s/credentials/OS-EC2' % self.user_id
            r = c.get(path, headers=self.headers)
            self.assertEqual([], r.json['credentials'])


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserTests,
                        _SystemReaderAndMemberTests):

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
                        _SystemReaderAndMemberTests):

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

    def test_user_can_list_ec2_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                   json={'tenant_id': project['id']}, headers=headers)

            path = '/v3/users/%s/credentials/OS-EC2' % self.user_id
            r = c.get(path, headers=self.headers)
            self.assertEqual([], r.json['credentials'])

    def test_user_can_create_ec2_credentials_for_others(self):
        user = PROVIDERS.identity_api.create_user(
            unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        )
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )

        with self.test_client() as c:
            c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                   json={'tenant_id': project['id']}, headers=self.headers)

    def test_user_can_delete_ec2_credentials_for_others(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user_password = user['password']
        user = PROVIDERS.identity_api.create_user(user)
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id
        )
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=user['id'],
            project_id=project['id']
        )
        user_auth = self.build_authentication_request(
            user_id=user['id'], password=user_password,
            project_id=project['id']
        )
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=user_auth)
            token_id = r.headers['X-Subject-Token']
            headers = {'X-Auth-Token': token_id}

            r = c.post('/v3/users/%s/credentials/OS-EC2' % user['id'],
                       json={'tenant_id': project['id']}, headers=headers)
            credential_id = r.json['credential']['access']

            c.delete('/v3/users/%s/credentials/OS-EC2/%s' % (
                     self.user_id, credential_id),
                     headers=self.headers)


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _UserEC2CredentialTests,
                        _SystemReaderAndMemberTests):

    def _override_policy(self):
        # TODO(cmurphy): Remove this once the deprecated policies in
        # keystone.common.policies.ec2_credential have been removed. This is
        # only here to make sure we test the new policies instead of the
        # deprecated ones. Oslo.policy will OR deprecated policies with new
        # policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users. This
        # will cause these specific tests to fail since we're trying to correct
        # this broken behavior with better scope checking.
        reader_or_cred_owner = bp.SYSTEM_READER_OR_CRED_OWNER
        reader_or_owner = bp.RULE_SYSTEM_READER_OR_OWNER
        admin_or_cred_owner = bp.SYSTEM_ADMIN_OR_CRED_OWNER
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:ec2_get_credential': reader_or_cred_owner,
                'identity:ec2_list_credentials': reader_or_owner,
                'identity:ec2_create_credential': admin_or_cred_owner,
                'identity:ec2_update_credential': admin_or_cred_owner,
                'identity:ec2_delete_credential': admin_or_cred_owner
            }
            f.write(jsonutils.dumps(overridden_policies))

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

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
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
