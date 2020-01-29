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

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TrustTests(base_classes.TestCaseWithBootstrap,
                 common_auth.AuthTestMixin):
    """Common functionality for all trust tests.

    Sets up trustor and trustee users and trust.
    """

    def setUp(self):
        super(TrustTests, self).setUp()
        self.loadapp()
        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']

        trustor_user = unit.new_user_ref(domain_id=self.domain_id)
        self.trustor_user_id = PROVIDERS.identity_api.create_user(
            trustor_user)['id']
        trustee_user = unit.new_user_ref(domain_id=self.domain_id)
        self.trustee_user_id = PROVIDERS.identity_api.create_user(
            trustee_user)['id']
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )
        self.project_id = project['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.trustor_user_id,
            project_id=self.project_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.trustee_user_id,
            project_id=project['id']
        )
        self.trust_id = uuid.uuid4().hex
        self.trust_data = {
            'trust': {'trustor_user_id': self.trustor_user_id,
                      'trustee_user_id': self.trustee_user_id,
                      'project_id': self.project_id,
                      'impersonation': False},
            'roles': [{"id": self.bootstrapper.member_role_id}]
        }
        auth = self.build_authentication_request(
            user_id=self.trustor_user_id,
            password=trustor_user['password'],
            project_id=project['id']
        )
        # Grab a token using the trustor persona we're testing and prepare
        # headers for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.trustor_headers = {'X-Auth-Token': self.token_id}

        auth = self.build_authentication_request(
            user_id=self.trustee_user_id,
            password=trustee_user['password'],
            project_id=project['id']
        )
        # Grab a token using the trustee persona we're testing and prepare
        # headers for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.trustee_headers = {'X-Auth-Token': self.token_id}

    def _override_policy_old_defaults(self):
        # TODO(cmurphy): This is to simulate what would happen if the operator
        # had generated a sample policy config, or had never removed their old
        # policy files since we adopted policy in code, and had explicitly
        # retained the old "" policy check strings. Remove this once the
        # hardcoded enforcement is removed from the trusts API.
        with open(self.policy_file_name, 'w') as f:
            overridden_policies = {
                'identity:list_trusts': '',
                'identity:delete_trust': '',
                'identity:get_trust': '',
                'identity:list_roles_for_trust': '',
                'identity:get_role_for_trust': '',
            }
            f.write(jsonutils.dumps(overridden_policies))


class _AdminTestsMixin(object):
    """Tests for all admin users.

    This exercises both the is_admin user and users granted the admin role on
    the system scope.
    """

    def test_admin_cannot_create_trust_for_other_user(self):
        json = {'trust': self.trust_data['trust']}
        json['trust']['roles'] = self.trust_data['roles']

        with self.test_client() as c:
            c.post(
                '/v3/OS-TRUST/trusts',
                json=json,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_list_all_trusts(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts',
                headers=self.headers
            )
        self.assertEqual(1, len(r.json['trusts']))


class AdminTokenTests(TrustTests, _AdminTestsMixin):
    """Tests for the is_admin user.

    The Trusts API has hardcoded is_admin checks that we need to ensure are
    preserved through the system-scope transition.
    """

    def setUp(self):
        super(AdminTokenTests, self).setUp()
        self.config_fixture.config(admin_token='ADMIN')
        self.headers = {'X-Auth-Token': 'ADMIN'}

    def test_admin_can_delete_trust_for_other_user(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_admin_can_get_non_existent_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % trust_id,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_admin_cannot_get_trust_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % self.trust_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_cannot_list_trust_roles_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_cannot_get_trust_role_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _SystemUserTests(object):
    """Tests for system admin, member, and reader."""

    def test_user_can_get_non_existent_trust(self):
        trust_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % trust_id,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_user_can_get_trust_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s' % self.trust_id,
                headers=self.headers
            )
        self.assertEqual(r.json['trust']['id'], self.trust_id)

    def test_user_can_list_trusts_for_trustee(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.headers
            )

    def test_user_can_list_trusts_for_trustor(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.headers
            )

    def test_user_can_list_trust_roles_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.headers
            )
        self.assertEqual(r.json['roles'][0]['id'],
                         self.bootstrapper.member_role_id)

    def test_user_can_get_trust_role_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.headers
            )


class _SystemReaderMemberTests(_SystemUserTests):
    """Tests for system readers and members."""

    def test_user_cannot_create_trust(self):
        json = {'trust': self.trust_data['trust']}
        json['trust']['roles'] = self.trust_data['roles']

        with self.test_client() as c:
            c.post(
                '/v3/OS-TRUST/trusts',
                json=json,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(TrustTests, _SystemReaderMemberTests):
    """Tests for system reader users."""

    def setUp(self):
        super(SystemReaderTests, self).setUp()
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
            user_id=self.user_id,
            password=system_reader['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemMemberTests(TrustTests, _SystemReaderMemberTests):
    """Tests for system member users."""

    def setUp(self):
        super(SystemMemberTests, self).setUp()
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
            user_id=self.user_id,
            password=system_member['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemAdminTests(TrustTests, _AdminTestsMixin, _SystemUserTests):
    """Tests for system admin users."""

    def setUp(self):
        super(SystemAdminTests, self).setUp()
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

    def test_admin_can_delete_trust_for_other_user(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers
            )

    def test_admin_cannot_delete_trust_for_user_overridden_defaults(self):
        # only the is_admin admin can do this
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_cannot_get_trust_for_other_user_overridden_defaults(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % self.trust_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_cannot_list_roles_for_other_user_overridden_defaults(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_admin_cannot_get_trust_role_for_other_user_overridden(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_list_all_trusts_overridden_defaults(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts',
                headers=self.headers
            )
        self.assertEqual(1, len(r.json['trusts']))


class ProjectUserTests(TrustTests):
    """Tests for all project users."""

    def setUp(self):
        super(ProjectUserTests, self).setUp()
        other_user = unit.new_user_ref(domain_id=self.domain_id)
        self.other_user_id = PROVIDERS.identity_api.create_user(
            other_user)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.other_user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.other_user_id,
            password=other_user['password'],
            project_id=self.project_id
        )
        # Grab a token using another persona who has no trusts associated with
        # them
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.other_headers = {'X-Auth-Token': self.token_id}

    def test_user_can_list_trusts_of_whom_they_are_the_trustor(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.trustor_headers
            )
        self.assertEqual(1, len(r.json['trusts']))
        self.assertEqual(self.trust_id, r.json['trusts'][0]['id'])

    def test_user_can_list_trusts_delegated_to_them(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.trustee_headers
            )
        self.assertEqual(1, len(r.json['trusts']))
        self.assertEqual(self.trust_id, r.json['trusts'][0]['id'])

    def test_trustor_cannot_list_trusts_for_trustee(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.trustor_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustee_cannot_list_trusts_for_trustor(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_trusts_for_other_trustor(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_trusts_for_other_trustee(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_all_trusts(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts',
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_another_users_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_get_non_existent_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % trust_id,
                headers=self.other_headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_user_can_get_trust_of_whom_they_are_the_trustor(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustor_headers
            )

    def test_user_can_get_trust_delegated_to_them(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustee_headers
            )
        self.assertEqual(r.json['trust']['id'], self.trust_id)

    def test_trustor_can_create_trust(self):
        json = {'trust': self.trust_data['trust']}
        json['trust']['roles'] = self.trust_data['roles']

        with self.test_client() as c:
            c.post(
                '/v3/OS-TRUST/trusts',
                json=json,
                headers=self.trustor_headers
            )

    def test_trustee_cannot_create_trust(self):
        json = {'trust': self.trust_data['trust']}
        json['trust']['roles'] = self.trust_data['roles']

        with self.test_client() as c:
            c.post(
                '/v3/OS-TRUST/trusts',
                json=json,
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_can_delete_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustor_headers
            )

    def test_trustee_cannot_delete_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_trust_for_other_user(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_can_list_trust_roles(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.trustor_headers
            )
        self.assertEqual(r.json['roles'][0]['id'],
                         self.bootstrapper.member_role_id)

    def test_trustee_can_list_trust_roles(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.trustee_headers
            )
        self.assertEqual(r.json['roles'][0]['id'],
                         self.bootstrapper.member_role_id)

    def test_user_cannot_list_trust_roles_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_can_get_trust_role(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.trustor_headers
            )

    def test_trustee_can_get_trust_role(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.trustee_headers
            )

    def test_user_cannot_get_trust_role_for_other_user(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_cannot_list_trusts_for_trustee_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.trustor_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustee_cannot_list_trusts_for_trustor_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_trusts_for_other_trustor_overridden(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_trusts_for_trustee_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_all_trusts_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts',
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_can_delete_trust_overridden_default(self):
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustor_headers
            )

    def test_trustee_cannot_delete_trust_overridden_default(self):
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustee_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_trust_for_other_user_overridden_default(self):
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_get_trust_of_whom_they_are_the_trustor_overridden(self):
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustor_headers
            )

    def test_user_can_get_trust_delegated_to_them_overridden_default(self):
        self._override_policy_old_defaults()
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.trustee_headers
            )
        self.assertEqual(r.json['trust']['id'], self.trust_id)

    def test_trustor_can_list_trust_roles_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.trustor_headers
            )
        self.assertEqual(r.json['roles'][0]['id'],
                         self.bootstrapper.member_role_id)

    def test_trustee_can_list_trust_roles_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            r = c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.trustee_headers
            )
        self.assertEqual(r.json['roles'][0]['id'],
                         self.bootstrapper.member_role_id)

    def test_user_cannot_list_trust_roles_other_user_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustor_can_get_trust_role_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.trustor_headers
            )

    def test_trustee_can_get_trust_role_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.trustee_headers
            )

    def test_user_cannot_get_trust_role_other_user_overridden_default(self):
        self._override_policy_old_defaults()
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.other_headers,
                expected_status_code=http.client.FORBIDDEN
            )


class DomainUserTests(TrustTests):
    """Tests for all domain users.

    Domain users should not be able to interact with trusts at all.
    """

    def setUp(self):
        super(DomainUserTests, self).setUp()
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(
            domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=domain_admin['password'],
            domain_id=self.domain_id
        )
        # Grab a token using another persona who has no trusts associated with
        # them
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_trustor_cannot_list_trusts_for_trustee(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustee_user_id=%s' %
                 self.trustee_user_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_trustee_cannot_list_trusts_for_trustor(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                ('/v3/OS-TRUST/trusts?trustor_user_id=%s' %
                 self.trustor_user_id),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_all_trusts(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts',
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_can_get_non_existent_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s' % trust_id,
                headers=self.headers,
                expected_status_code=http.client.NOT_FOUND
            )

    def test_user_cannot_create_trust(self):
        trust_data = self.trust_data['trust']
        trust_data['trustor_user_id'] = self.user_id
        json = {'trust': trust_data}
        json['trust']['roles'] = self.trust_data['roles']

        with self.test_client() as c:
            c.post(
                '/v3/OS-TRUST/trusts',
                json=json,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_trust(self):
        ref = PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.delete(
                '/v3/OS-TRUST/trusts/%s' % ref['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_trust_roles(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.get(
                '/v3/OS-TRUST/trusts/%s/roles' % self.trust_id,
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_trust_role(self):
        PROVIDERS.trust_api.create_trust(
            self.trust_id, **self.trust_data)

        with self.test_client() as c:
            c.head(
                ('/v3/OS-TRUST/trusts/%s/roles/%s' %
                 (self.trust_id, self.bootstrapper.member_role_id)),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )
