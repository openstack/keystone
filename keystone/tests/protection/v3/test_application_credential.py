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

import datetime
import uuid

import http.client
from oslo_serialization import jsonutils

from keystone.common.policies import base as base_policy
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _TestAppCredBase(base_classes.TestCaseWithBootstrap):
    """Base class for application credential tests."""

    def _new_app_cred_data(self, user_id=None, project_id=None, name=None,
                           expires=None, system=None):
        if not user_id:
            user_id = self.app_cred_user_id
        if not name:
            name = uuid.uuid4().hex
        if not expires:
            expires = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        if not system:
            system = uuid.uuid4().hex
        if not project_id:
            project_id = self.app_cred_project_id
        app_cred_data = {
            'id': uuid.uuid4().hex,
            'name': name,
            'description': uuid.uuid4().hex,
            'user_id': user_id,
            'project_id': project_id,
            'system': system,
            'expires_at': expires,
            'roles': [
                {'id': self.bootstrapper.member_role_id},
            ],
            'secret': uuid.uuid4().hex,
            'unrestricted': False
        }
        return app_cred_data

    def setUp(self):
        super(_TestAppCredBase, self).setUp()

        # create a user and project for app cred testing
        new_user_ref = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        app_cred_user_ref = PROVIDERS.identity_api.create_user(
            new_user_ref
        )
        self.app_cred_user_id = app_cred_user_ref['id']
        self.app_cred_user_password = new_user_ref['password']
        app_cred_project_ref = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )
        self.app_cred_project_id = app_cred_project_ref['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=self.app_cred_user_id,
            project_id=self.app_cred_project_id
        )

    def _create_application_credential(self):
        app_cred = self._new_app_cred_data()
        return \
            PROVIDERS.application_credential_api.create_application_credential(
                app_cred)

    def _override_policy(self):
        # TODO(gyee): Remove this once the deprecated policies in
        # keystone.common.policies.application_credential have been removed.
        # This is only here to make sure we test the new policies instead of
        # the deprecated ones. Oslo.policy will OR deprecated policies with
        # new policies to maintain compatibility and give operators a chance to
        # update permissions or update policies without breaking users.
        # This will cause these specific tests to fail since we're trying to
        # correct this broken behavior with better scope checking.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:get_application_credential': (
                    base_policy.RULE_SYSTEM_READER_OR_OWNER),
                'identity:list_application_credentials': (
                    base_policy.RULE_SYSTEM_READER_OR_OWNER),
                'identity:create_application_credential': (
                    base_policy.RULE_OWNER),
                'identity:delete_application_credential': (
                    base_policy.RULE_SYSTEM_ADMIN_OR_OWNER),
            }
            f.write(jsonutils.dumps(overridden_policies))


class _DomainAndProjectUserTests(object):
    """Domain and project user tests.

    Domain and project users should not be able to manage application
    credentials other then their own.
    """

    def test_user_cannot_list_application_credentials(self):
        # create a couple of application credentials
        self._create_application_credential()
        self._create_application_credential()

        with self.test_client() as c:
            c.get('/v3/users/%s/application_credentials' % (
                  self.app_cred_user_id),
                  expected_status_code=http.client.FORBIDDEN,
                  headers=self.headers)

    def test_user_cannot_get_application_credential(self):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            c.get('/v3/users/%s/application_credentials/%s' % (
                  self.app_cred_user_id,
                  app_cred['id']),
                  expected_status_code=http.client.FORBIDDEN,
                  headers=self.headers)

    def test_user_cannot_lookup_application_credential(self):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            c.get('/v3/users/%s/application_credentials?name=%s' % (
                  self.app_cred_user_id,
                  app_cred['name']),
                  expected_status_code=http.client.FORBIDDEN,
                  headers=self.headers)

    def test_user_cannot_delete_application_credential(self):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/application_credentials/%s' % (
                    self.app_cred_user_id,
                    app_cred['id']),
                expected_status_code=http.client.FORBIDDEN,
                headers=self.headers)

    def test_user_cannot_lookup_non_existent_application_credential(self):
        with self.test_client() as c:
            c.get('/v3/users/%s/application_credentials?name=%s' % (
                  self.app_cred_user_id,
                  uuid.uuid4().hex),
                  expected_status_code=http.client.FORBIDDEN,
                  headers=self.headers)

    def test_user_cannot_create_app_credential_for_another_user(self):
        # create another user
        another_user = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        another_user_id = PROVIDERS.identity_api.create_user(
            another_user
        )['id']

        app_cred_body = {
            'application_credential': unit.new_application_credential_ref(
                roles=[{'id': self.bootstrapper.member_role_id}])
        }

        with self.test_client() as c:
            c.post(
                '/v3/users/%s/application_credentials' % another_user_id,
                json=app_cred_body,
                expected_status_code=http.client.FORBIDDEN,
                headers=self.headers)


class _SystemUserAndOwnerTests(object):
    """Common default functionality for all system users and owner."""

    def test_user_can_list_application_credentials(self):
        # create a couple of application credentials
        self._create_application_credential()
        self._create_application_credential()

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/application_credentials' % (
                    self.app_cred_user_id),
                headers=self.headers)
            self.assertEqual(2, len(r.json['application_credentials']))

    def test_user_can_get_application_credential(self):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/application_credentials/%s' % (
                    self.app_cred_user_id,
                    app_cred['id']),
                headers=self.headers)
            actual_app_cred = r.json['application_credential']
            self.assertEqual(app_cred['id'], actual_app_cred['id'])

    def test_user_can_lookup_application_credential(self):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            r = c.get(
                '/v3/users/%s/application_credentials?name=%s' % (
                    self.app_cred_user_id,
                    app_cred['name']),
                headers=self.headers)
            self.assertEqual(1, len(r.json['application_credentials']))
            actual_app_cred = r.json['application_credentials'][0]
            self.assertEqual(app_cred['id'], actual_app_cred['id'])

    def _test_delete_application_credential(
            self,
            expected_status_code=http.client.NO_CONTENT):
        app_cred = self._create_application_credential()

        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/application_credentials/%s' % (
                    self.app_cred_user_id,
                    app_cred['id']),
                expected_status_code=expected_status_code,
                headers=self.headers)

    def test_user_cannot_create_app_credential_for_another_user(self):
        # create another user
        another_user = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        another_user_id = PROVIDERS.identity_api.create_user(
            another_user
        )['id']

        app_cred_body = {
            'application_credential': unit.new_application_credential_ref(
                roles=[{'id': self.bootstrapper.member_role_id}])
        }

        with self.test_client() as c:
            c.post(
                '/v3/users/%s/application_credentials' % another_user_id,
                json=app_cred_body,
                expected_status_code=http.client.FORBIDDEN,
                headers=self.headers)


class SystemReaderTests(_TestAppCredBase,
                        common_auth.AuthTestMixin,
                        _SystemUserAndOwnerTests):

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

    def test_system_reader_cannot_delete_application_credential_for_user(self):
        self._test_delete_application_credential(
            expected_status_code=http.client.FORBIDDEN)


class SystemMemberTests(_TestAppCredBase,
                        common_auth.AuthTestMixin,
                        _SystemUserAndOwnerTests):

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

    def test_system_reader_cannot_delete_application_credential_for_user(self):
        self._test_delete_application_credential(
            expected_status_code=http.client.FORBIDDEN)


class SystemAdminTests(_TestAppCredBase,
                       common_auth.AuthTestMixin,
                       _SystemUserAndOwnerTests):

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

    def test_system_admin_can_delete_application_credential_for_user(self):
        self._test_delete_application_credential()


class OwnerTests(_TestAppCredBase,
                 common_auth.AuthTestMixin,
                 _SystemUserAndOwnerTests):

    def setUp(self):
        super(OwnerTests, self).setUp()
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

        # in this case app_cred_user_id and user_id are the same since we
        # are testing the owner
        self.user_id = self.app_cred_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.app_cred_user_password,
            project_id=self.app_cred_project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_create_application_credential_by_owner(self):
        app_cred_body = {
            'application_credential': unit.new_application_credential_ref()
        }

        with self.test_client() as c:
            c.post(
                '/v3/users/%s/application_credentials' % self.user_id,
                json=app_cred_body,
                expected_status_code=http.client.CREATED,
                headers=self.headers)

    def test_owner_can_delete_application_credential(self):
        self._test_delete_application_credential()

    def test_user_cannot_lookup_application_credential_for_another_user(self):
        # create another user
        another_user = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        another_user_id = PROVIDERS.identity_api.create_user(
            another_user
        )['id']

        auth = self.build_authentication_request(
            user_id=another_user_id,
            password=another_user['password']
        )

        # authenticate for a token as a completely different user with
        # completely different authorization
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            another_user_token = r.headers['X-Subject-Token']

        # create an application credential as the self.user_id user on a
        # project that the user above doesn't have any authorization on
        app_cred = self._create_application_credential()

        # attempt to lookup the application credential as another user
        with self.test_client() as c:
            c.get(
                '/v3/users/%s/application_credentials/%s' % (
                    another_user_id,
                    app_cred['id']),
                expected_status_code=http.client.FORBIDDEN,
                headers={'X-Auth-Token': another_user_token})

    def test_user_cannot_delete_application_credential_for_another_user(self):
        # create another user
        another_user = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        another_user_id = PROVIDERS.identity_api.create_user(
            another_user
        )['id']

        auth = self.build_authentication_request(
            user_id=another_user_id,
            password=another_user['password']
        )

        # authenticate for a token as a completely different user with
        # completely different authorization
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            another_user_token = r.headers['X-Subject-Token']

        # create an application credential as the self.user_id user on a
        # project that the user above doesn't have any authorization on
        app_cred = self._create_application_credential()

        # attempt to delete the application credential as another user
        with self.test_client() as c:
            c.delete(
                '/v3/users/%s/application_credentials/%s' % (
                    another_user_id,
                    app_cred['id']),
                expected_status_code=http.client.FORBIDDEN,
                headers={'X-Auth-Token': another_user_token})


class DomainAdminTests(_TestAppCredBase,
                       common_auth.AuthTestMixin,
                       _DomainAndProjectUserTests):

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

        domain_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=CONF.identity.default_domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=CONF.identity.default_domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainReaderTests(_TestAppCredBase,
                        common_auth.AuthTestMixin,
                        _DomainAndProjectUserTests):

    def setUp(self):
        super(DomainReaderTests, self).setUp()
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

        domain_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=CONF.identity.default_domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=CONF.identity.default_domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainMemberTests(_TestAppCredBase,
                        common_auth.AuthTestMixin,
                        _DomainAndProjectUserTests):

    def setUp(self):
        super(DomainMemberTests, self).setUp()
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

        domain_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            domain_id=CONF.identity.default_domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=CONF.identity.default_domain_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectAdminTests(_TestAppCredBase,
                        common_auth.AuthTestMixin,
                        _DomainAndProjectUserTests):

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

        project_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_admin)['id']
        # even project admin of project where the app credential
        # is intended for cannot perform app credential operations
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id,
            user_id=self.user_id,
            project_id=self.app_cred_project_id
        )
        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_admin['password'],
            project_id=self.app_cred_project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectReaderTests(_TestAppCredBase,
                         common_auth.AuthTestMixin,
                         _DomainAndProjectUserTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
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

        project_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_admin)['id']
        # even project admin of project where the app credential
        # is intended for cannot perform app credential operations
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id,
            user_id=self.user_id,
            project_id=self.app_cred_project_id
        )
        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_admin['password'],
            project_id=self.app_cred_project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectMemberTests(_TestAppCredBase,
                         common_auth.AuthTestMixin,
                         _DomainAndProjectUserTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
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

        project_admin = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(project_admin)['id']
        # even project admin of project where the app credential
        # is intended for cannot perform app credential operations
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id,
            user_id=self.user_id,
            project_id=self.app_cred_project_id
        )
        auth = self.build_authentication_request(
            user_id=self.user_id, password=project_admin['password'],
            project_id=self.app_cred_project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}
