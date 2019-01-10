# Copyright 2012 OpenStack Foundation
# Copyright 2013 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

from oslo_serialization import jsonutils
from six.moves import http_client

from keystone.common import provider_api
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3
from keystone.tests.unit import utils


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class IdentityTestProtectedCase(test_v3.RestfulTestCase):
    """Test policy enforcement on the v3 Identity API."""

    def _policy_fixture(self):
        return ksfixtures.Policy(self.tmpfilename, self.config_fixture)

    def setUp(self):
        """Setup for Identity Protection Test Cases.

        As well as the usual housekeeping, create a set of domains,
        users, roles and projects for the subsequent tests:

        - Three domains: A,B & C.  C is disabled.
        - DomainA has user1, DomainB has user2 and user3
        - DomainA has group1 and group2, DomainB has group3
        - User1 has two roles on DomainA
        - User2 has one role on DomainA

        Remember that there will also be a fourth domain in existence,
        the default domain.

        """
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        super(IdentityTestProtectedCase, self).setUp()

        # A default auth request we can use - un-scoped user token
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'])

    def load_sample_data(self, enable_sqlite_foreign_key=False):
        self._populate_default_domain()

        # Start by creating a couple of domains
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.domainC = unit.new_domain_ref(enabled=False)
        PROVIDERS.resource_api.create_domain(self.domainC['id'], self.domainC)

        # Some projects in the domains
        self.projectA = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(
            self.projectA['id'], self.projectA
        )
        self.projectB = unit.new_project_ref(domain_id=self.domainB['id'])
        PROVIDERS.resource_api.create_project(
            self.projectB['id'], self.projectB
        )

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainA['id'])
        self.user2 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])
        self.user3 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])

        self.group1 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group1 = PROVIDERS.identity_api.create_group(self.group1)

        self.group2 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group2 = PROVIDERS.identity_api.create_group(self.group2)

        self.group3 = unit.new_group_ref(domain_id=self.domainB['id'])
        self.group3 = PROVIDERS.identity_api.create_group(self.group3)

        self.role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role['id'], self.role)
        self.role1 = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role1['id'], self.role1)

        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user1['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user2['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role1['id'], user_id=self.user1['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user1['id'],
            project_id=self.projectA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user2['id'],
            project_id=self.projectB['id']
        )

    def _get_id_list_from_ref_list(self, ref_list):
        result_list = []
        for x in ref_list:
            result_list.append(x['id'])
        return result_list

    def _set_policy(self, new_policy):
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))

    def test_list_users_unprotected(self):
        """GET /users (unprotected).

        Test Plan:

        - Update policy so api is unprotected
        - Use an un-scoped token to make sure we can get back all
          the users independent of domain

        """
        self._set_policy({"identity:list_users": []})
        r = self.get('/users', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertIn(self.user1['id'], id_list)
        self.assertIn(self.user2['id'], id_list)
        self.assertIn(self.user3['id'], id_list)

    def test_list_users_admin_project(self):
        self.config_fixture.config(
            admin_project_name=self.projectA['name'],
            admin_project_domain_name=self.domainA['name'],
            group='resource')

        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            project_id=self.projectA['id'])

        rule = 'role:%s and is_admin_project:True' % self.role['name']
        self._set_policy({"identity:list_users": rule})

        r = self.get('/users', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertIn(self.user1['id'], id_list)
        self.assertIn(self.user2['id'], id_list)
        self.assertIn(self.user3['id'], id_list)

    def test_list_users_not_in_admin_project(self):
        self.config_fixture.config(
            admin_project_name=self.projectA['name'],
            admin_project_domain_name=self.domainA['name'],
            group='resource')

        self.auth = self.build_authentication_request(
            user_id=self.user2['id'],
            password=self.user2['password'],
            project_id=self.projectB['id'])

        rule = 'role:%s and is_admin_project:True' % self.role['name']
        self._set_policy({"identity:list_users": rule})

        self.get('/users',
                 auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)

    def test_list_users_filtered_by_domain(self):
        """GET /users?domain_id=mydomain (filtered).

        Test Plan:

        - Update policy so api is unprotected
        - Use an un-scoped token to make sure we can filter the
          users by domainB, getting back the 2 users in that domain

        """
        self._set_policy({"identity:list_users": []})
        url_by_name = '/users?domain_id=%s' % self.domainB['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should  get back two users, those in DomainB
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertIn(self.user2['id'], id_list)
        self.assertIn(self.user3['id'], id_list)

    def test_get_user_protected_match_id(self):
        """GET /users/{id} (match payload).

        Test Plan:

        - Update policy to protect api by user_id
        - List users with user_id of user1 as filter, to check that
          this will correctly match user_id in the flattened
          payload

        """
        # TODO(henry-nash, ayoung): It would be good to expand this
        # test for further test flattening, e.g. protect on, say, an
        # attribute of an object being created
        new_policy = {"identity:get_user": [["user_id:%(user_id)s"]]}
        self._set_policy(new_policy)
        url_by_name = '/users/%s' % self.user1['id']
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(self.user1['id'], r.result['user']['id'])

    def test_get_user_protected_match_target(self):
        """GET /users/{id} (match target).

        Test Plan:

        - Update policy to protect api by domain_id
        - Try and read a user who is in DomainB with a token scoped
          to Domain A - this should fail
        - Retry this for a user who is in Domain A, which should succeed.
        - Finally, try getting a user that does not exist, which should
          still return UserNotFound

        """
        new_policy = {'identity:get_user':
                      [["domain_id:%(target.user.domain_id)s"]]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            domain_id=self.domainA['id'])
        url_by_name = '/users/%s' % self.user2['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

        url_by_name = '/users/%s' % self.user1['id']
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(self.user1['id'], r.result['user']['id'])

        url_by_name = '/users/%s' % uuid.uuid4().hex
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.UserNotFound.code)

    def test_revoke_grant_protected_match_target(self):
        """DELETE /domains/{id}/users/{id}/roles/{id} (match target).

        Test Plan:

        - Update policy to protect api by domain_id of entities in
          the grant
        - Try and delete the existing grant that has a user who is
          from a different domain - this should fail.
        - Retry this for a user who is in Domain A, which should succeed.

        """
        new_policy = {'identity:revoke_grant':
                      [["domain_id:%(target.user.domain_id)s"]]}
        self._set_policy(new_policy)
        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domainA['id'],
                'user_id': self.user2['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role['id']}

        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            domain_id=self.domainA['id'])
        self.delete(member_url, auth=self.auth,
                    expected_status=exception.ForbiddenAction.code)

        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domainA['id'],
                'user_id': self.user1['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role1['id']}
        self.delete(member_url, auth=self.auth)

    def test_list_users_protected_by_domain(self):
        """GET /users?domain_id=mydomain (protected).

        Test Plan:

        - Update policy to protect api by domain_id
        - List groups using a token scoped to domainA with a filter
          specifying domainA - we should only get back the one user
          that is in domainA.
        - Try and read the users from domainB - this should fail since
          we don't have a token scoped for domainB

        """
        new_policy = {"identity:list_users": ["domain_id:%(domain_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            domain_id=self.domainA['id'])
        url_by_name = '/users?domain_id=%s' % self.domainA['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back one user, the one in DomainA
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.user1['id'], id_list)

        # Now try for domainB, which should fail
        url_by_name = '/users?domain_id=%s' % self.domainB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_domain(self):
        """GET /groups?domain_id=mydomain (protected).

        Test Plan:

        - Update policy to protect api by domain_id
        - List groups using a token scoped to domainA and make sure
          we only get back the two groups that are in domainA
        - Try and read the groups from domainB - this should fail since
          we don't have a token scoped for domainB

        """
        new_policy = {"identity:list_groups": ["domain_id:%(domain_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            domain_id=self.domainA['id'])
        url_by_name = '/groups?domain_id=%s' % self.domainA['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back two groups, the ones in DomainA
        id_list = self._get_id_list_from_ref_list(r.result.get('groups'))
        self.assertEqual(2, len(id_list))
        self.assertIn(self.group1['id'], id_list)
        self.assertIn(self.group2['id'], id_list)

        # Now try for domainB, which should fail
        url_by_name = '/groups?domain_id=%s' % self.domainB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_domain_and_filtered(self):
        """GET /groups?domain_id=mydomain&name=myname (protected).

        Test Plan:

        - Update policy to protect api by domain_id
        - List groups using a token scoped to domainA with a filter
          specifying both domainA and the name of group.
        - We should only get back the group in domainA that matches
          the name

        """
        new_policy = {"identity:list_groups": ["domain_id:%(domain_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            domain_id=self.domainA['id'])
        url_by_name = '/groups?domain_id=%s&name=%s' % (
            self.domainA['id'], self.group2['name'])
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back one user, the one in DomainA that matches
        # the name supplied
        id_list = self._get_id_list_from_ref_list(r.result.get('groups'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.group2['id'], id_list)


class IdentityTestPolicySample(test_v3.RestfulTestCase):
    """Test policy enforcement of the policy.json file."""

    def load_sample_data(self, enable_sqlite_foreign_key=False):
        self._populate_default_domain()

        self.just_a_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=CONF.identity.default_domain_id)
        self.another_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=CONF.identity.default_domain_id)
        self.admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=CONF.identity.default_domain_id)

        self.role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role['id'], self.role)
        self.admin_role = unit.new_role_ref(name='admin')
        PROVIDERS.role_api.create_role(self.admin_role['id'], self.admin_role)

        # Create and assign roles to the project
        self.project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(self.project['id'], self.project)
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.just_a_user['id'],
            project_id=self.project['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.another_user['id'],
            project_id=self.project['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.admin_user['id'],
            project_id=self.project['id']
        )

    def test_user_validate_same_token(self):
        # Given a non-admin user token, the token can be used to validate
        # itself.
        # This is GET /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.get('/auth/tokens', token=token,
                 headers={'X-Subject-Token': token})

    def test_user_validate_user_token(self):
        # A user can validate one of their own tokens.
        # This is GET /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.get('/auth/tokens', token=token1,
                 headers={'X-Subject-Token': token2})

    def test_user_validate_other_user_token_rejected(self):
        # A user cannot validate another user's token.
        # This is GET /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.get('/auth/tokens', token=user1_token,
                 headers={'X-Subject-Token': user2_token},
                 expected_status=http_client.FORBIDDEN)

    def test_admin_validate_user_token(self):
        # An admin can validate a user's token.
        # This is GET /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/auth/tokens', token=admin_token,
                 headers={'X-Subject-Token': user_token})

    def test_user_check_same_token(self):
        # Given a non-admin user token, the token can be used to check
        # itself.
        # This is HEAD /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token,
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.OK)

    def test_user_check_user_token(self):
        # A user can check one of their own tokens.
        # This is HEAD /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token1,
                  headers={'X-Subject-Token': token2},
                  expected_status=http_client.OK)

    def test_user_check_other_user_token_rejected(self):
        # A user cannot check another user's token.
        # This is HEAD /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.head('/auth/tokens', token=user1_token,
                  headers={'X-Subject-Token': user2_token},
                  expected_status=http_client.FORBIDDEN)

    def test_admin_check_user_token(self):
        # An admin can check a user's token.
        # This is HEAD /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.head('/auth/tokens', token=admin_token,
                  headers={'X-Subject-Token': user_token},
                  expected_status=http_client.OK)

    def test_user_revoke_same_token(self):
        # Given a non-admin user token, the token can be used to revoke
        # itself.
        # This is DELETE /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token,
                    headers={'X-Subject-Token': token})

    def test_user_revoke_user_token(self):
        # A user can revoke one of their own tokens.
        # This is DELETE /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token1,
                    headers={'X-Subject-Token': token2})

    def test_user_revoke_other_user_token_rejected(self):
        # A user cannot revoke another user's token.
        # This is DELETE /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.delete('/auth/tokens', token=user1_token,
                    headers={'X-Subject-Token': user2_token},
                    expected_status=http_client.FORBIDDEN)

    def test_admin_revoke_user_token(self):
        # An admin can revoke a user's token.
        # This is DELETE /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.delete('/auth/tokens', token=admin_token,
                    headers={'X-Subject-Token': user_token})

    def test_list_revoke_events_is_protected(self):
        # An admin can list revoke events, a regular user cannot
        # This is GET /v3/OS-REVOKE/events

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/OS-REVOKE/events', token=admin_token)
        self.get('/OS-REVOKE/events', token=user_token, expected_status=403)


class IdentityTestv3CloudPolicySample(test_v3.RestfulTestCase,
                                      test_v3.AssignmentTestMixin):
    """Test policy enforcement of the sample v3 cloud policy file."""

    def _policy_fixture(self):
        return ksfixtures.Policy(unit.dirs.etc('policy.v3cloudsample.json'),
                                 self.config_fixture)

    def setUp(self):
        """Setup for v3 Cloud Policy Sample Test Cases.

        The following data is created:

        - Three domains: domainA, domainB and admin_domain
        - One project, which name is 'project'
        - domainA has three users: domain_admin_user, project_admin_user and
          just_a_user:

          - domain_admin_user has role 'admin' on domainA,
          - project_admin_user has role 'admin' on the project,
          - just_a_user has a non-admin role on both domainA and the project.
        - admin_domain has admin_project, and user cloud_admin_user, with an
          'admin' role on admin_project.
        - domainA has two groups (group1, group2), domainB has one group
          (group3)

        We test various api protection rules from the cloud sample policy
        file to make sure the sample is valid and that we correctly enforce it.

        """
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestv3CloudPolicySample, self).setUp()

        self.config_fixture.config(
            group='resource',
            admin_project_name=self.admin_project['name'])
        self.config_fixture.config(
            group='resource',
            admin_project_domain_name=self.admin_domain['name'])
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def load_sample_data(self, enable_sqlite_foreign_key=False):
        # Start by creating a couple of domains
        self._populate_default_domain()
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.admin_domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(
            self.admin_domain['id'], self.admin_domain
        )

        self.admin_project = unit.new_project_ref(
            domain_id=self.admin_domain['id'])
        PROVIDERS.resource_api.create_project(
            self.admin_project['id'], self.admin_project
        )

        # And our users
        self.cloud_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.admin_domain['id'])
        self.just_a_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainA['id'])
        self.domain_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainA['id'])
        self.domainB_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainB['id'])
        self.project_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainA['id'])
        self.project_adminB_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainB['id'])

        # The admin role, a domain specific role and another plain role
        self.admin_role = unit.new_role_ref(name='admin')
        PROVIDERS.role_api.create_role(self.admin_role['id'], self.admin_role)
        self.roleA = unit.new_role_ref(domain_id=self.domainA['id'])
        PROVIDERS.role_api.create_role(self.roleA['id'], self.roleA)
        self.role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role['id'], self.role)

        # The cloud admin just gets the admin role on the special admin project
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.cloud_admin_user['id'],
            project_id=self.admin_project['id']
        )

        # Assign roles to the domain
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.domain_admin_user['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.just_a_user['id'],
            domain_id=self.domainA['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.domainB_admin_user['id'],
            domain_id=self.domainB['id']
        )

        # Create and assign roles to the project
        self.project = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(self.project['id'], self.project)
        self.projectB = unit.new_project_ref(domain_id=self.domainB['id'])
        PROVIDERS.resource_api.create_project(
            self.projectB['id'], self.projectB
        )
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.project_admin_user['id'],
            project_id=self.project['id']
        )
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=self.project_adminB_user['id'],
            project_id=self.projectB['id'])
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.just_a_user['id'],
            project_id=self.project['id']
        )

        self.group1 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group1 = PROVIDERS.identity_api.create_group(self.group1)

        self.group2 = unit.new_group_ref(domain_id=self.domainA['id'])
        self.group2 = PROVIDERS.identity_api.create_group(self.group2)

        self.group3 = unit.new_group_ref(domain_id=self.domainB['id'])
        self.group3 = PROVIDERS.identity_api.create_group(self.group3)

    def _stati(self, expected_status):
        # Return the expected return codes for APIs with and without data
        # with any specified status overriding the normal values
        if expected_status is None:
            return (http_client.OK, http_client.CREATED,
                    http_client.NO_CONTENT)
        else:
            return (expected_status, expected_status, expected_status)

    def _test_user_management(self, user_id, domain_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/users/%s' % user_id
        list_url = '/users?domain_id=%s' % domain_id

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        user = {'description': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'user': user},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        user_ref = unit.new_user_ref(domain_id=domain_id)
        self.post('/users', auth=self.auth, body={'user': user_ref},
                  expected_status=status_created)

    def _test_group_management(self, group, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/groups/%s' % group['id']
        list_url = '/groups?domain_id=%s' % group['domain_id']
        users_url = '/groups/%s/users' % group['id']
        group_member_url = '/groups/%s/users/%s' % (group['id'],
                                                    self.just_a_user['id'])

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        self.put(group_member_url, auth=self.auth,
                 expected_status=status_no_data)
        self.get(users_url, auth=self.auth,
                 expected_status=status_OK)
        group_ref = unit.new_group_ref(domain_id=group['domain_id'])
        self.post('/groups', auth=self.auth, body={'group': group_ref},
                  expected_status=status_created)
        self.delete(group_member_url, auth=self.auth,
                    expected_status=status_no_data)
        group = {'description': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'group': group},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

    def _test_project_management(self, domain_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/projects/%s' % self.project['id']
        list_url = '/projects?domain_id=%s' % domain_id

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        project = {'description': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'project': project},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        proj_ref = unit.new_project_ref(domain_id=domain_id)
        self.post('/projects', auth=self.auth, body={'project': proj_ref},
                  expected_status=status_created)

    def _test_domain_management(self, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/domains/%s' % self.domainB['id']
        list_url = '/domains'

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        domain = {'description': 'Updated', 'enabled': False}
        self.patch(entity_url, auth=self.auth, body={'domain': domain},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        domain_ref = unit.new_domain_ref()
        self.post('/domains', auth=self.auth, body={'domain': domain_ref},
                  expected_status=status_created)

    def _test_grants(self, target, entity_id, role_domain_id=None,
                     list_status_OK=False, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        a_role = unit.new_role_ref(domain_id=role_domain_id)
        PROVIDERS.role_api.create_role(a_role['id'], a_role)

        collection_url = (
            '/%(target)s/%(target_id)s/users/%(user_id)s/roles' % {
                'target': target,
                'target_id': entity_id,
                'user_id': self.just_a_user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': a_role['id']}

        self.put(member_url, auth=self.auth,
                 expected_status=status_no_data)
        self.head(member_url, auth=self.auth,
                  expected_status=status_no_data)
        if list_status_OK:
            self.get(collection_url, auth=self.auth)
        else:
            self.get(collection_url, auth=self.auth,
                     expected_status=status_OK)
        self.delete(member_url, auth=self.auth,
                    expected_status=status_no_data)

    def _role_management_cases(self, read_status_OK=False, expected=None):
        # Set the different status values for different types of call depending
        # on whether we expect the calls to fail or not.
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/roles/%s' % self.role['id']
        list_url = '/roles'

        if read_status_OK:
            self.get(entity_url, auth=self.auth)
            self.get(list_url, auth=self.auth)
        else:
            self.get(entity_url, auth=self.auth,
                     expected_status=status_OK)
            self.get(list_url, auth=self.auth,
                     expected_status=status_OK)

        role = {'name': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'role': role},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        role_ref = unit.new_role_ref()
        self.post('/roles', auth=self.auth, body={'role': role_ref},
                  expected_status=status_created)

    def _domain_role_management_cases(self, domain_id, read_status_OK=False,
                                      expected=None):
        # Set the different status values for different types of call depending
        # on whether we expect the calls to fail or not.
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/roles/%s' % self.roleA['id']
        list_url = '/roles?domain_id=%s' % domain_id

        if read_status_OK:
            self.get(entity_url, auth=self.auth)
            self.get(list_url, auth=self.auth)
        else:
            self.get(entity_url, auth=self.auth,
                     expected_status=status_OK)
            self.get(list_url, auth=self.auth,
                     expected_status=status_OK)

        role = {'name': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'role': role},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        role_ref = unit.new_role_ref(domain_id=domain_id)
        self.post('/roles', auth=self.auth, body={'role': role_ref},
                  expected_status=status_created)

    def test_user_management(self):
        # First, authenticate with a user that does not have the domain
        # admin role - shouldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_user_management(
            self.domain_admin_user['id'], self.domainA['id'],
            expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_user_management(self.just_a_user['id'], self.domainA['id'])

    def test_user_management_normalized_keys(self):
        """Illustrate the inconsistent handling of hyphens in keys.

        To quote Morgan in bug 1526244:

            the reason this is converted from "domain-id" to "domain_id" is
            because of how we process/normalize data. The way we have to handle
            specific data types for known columns requires avoiding "-" in the
            actual python code since "-" is not valid for attributes in python
            w/o significant use of "getattr" etc.

            In short, historically we handle some things in conversions. The
            use of "extras" has long been a poor design choice that leads to
            odd/strange inconsistent behaviors because of other choices made in
            handling data from within the body. (In many cases we convert from
            "-" to "_" throughout openstack)

        Source: https://bugs.launchpad.net/keystone/+bug/1526244/comments/9

        """
        # Authenticate with a user that has the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        # Show that we can read a normal user without any surprises.
        r = self.get(
            '/users/%s' % self.just_a_user['id'],
            auth=self.auth,
            expected_status=http_client.OK)
        self.assertValidUserResponse(r)

        # We don't normalize query string keys, so both of these result in a
        # 403, because we didn't specify a domain_id query string in either
        # case, and we explicitly require one (it doesn't matter what
        # 'domain-id' value you use).
        self.get(
            '/users?domain-id=%s' % self.domainA['id'],
            auth=self.auth,
            expected_status=exception.ForbiddenAction.code)
        self.get(
            '/users?domain-id=%s' % self.domainB['id'],
            auth=self.auth,
            expected_status=exception.ForbiddenAction.code)

        # If we try updating the user's 'domain_id' by specifying a
        # 'domain-id', then it'll be stored into extras rather than normalized,
        # and the user's actual 'domain_id' is not affected.
        r = self.patch(
            '/users/%s' % self.just_a_user['id'],
            auth=self.auth,
            body={'user': {'domain-id': self.domainB['id']}},
            expected_status=http_client.OK)
        self.assertEqual(self.domainB['id'], r.json['user']['domain-id'])
        self.assertEqual(self.domainA['id'], r.json['user']['domain_id'])
        self.assertNotEqual(self.domainB['id'], self.just_a_user['domain_id'])
        self.assertValidUserResponse(r, self.just_a_user)

        # Finally, show that we can create a new user without any surprises.
        # But if we specify a 'domain-id' instead of a 'domain_id', we get a
        # Forbidden response because we fail a policy check before
        # normalization occurs.
        user_ref = unit.new_user_ref(domain_id=self.domainA['id'])
        r = self.post(
            '/users',
            auth=self.auth,
            body={'user': user_ref},
            expected_status=http_client.CREATED)
        self.assertValidUserResponse(r, ref=user_ref)
        user_ref['domain-id'] = user_ref.pop('domain_id')
        self.post(
            '/users',
            auth=self.auth,
            body={'user': user_ref},
            expected_status=exception.ForbiddenAction.code)

    def test_user_management_by_cloud_admin(self):
        # Test users management with a cloud admin. This user should
        # be able to manage users in any domain.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_user_management(self.just_a_user['id'], self.domainA['id'])

    def test_group_management(self):
        # First, authenticate with a user that does not have the domain
        # admin role - shouldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_group_management(
            self.group1, expected=exception.ForbiddenAction.code)

        # ...but should be able to list groups of which they are a member
        url = '/users/%s/groups' % self.just_a_user['id']
        self.get(url, auth=self.auth)

        # Now, authenticate with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_group_management(self.group1)
        self._test_group_management(self.group3,
                                    expected=exception.ForbiddenAction.code)

    def test_group_management_by_cloud_admin(self):
        # Test groups management with a cloud admin. This user should
        # be able to manage groups in any domain.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_group_management(self.group1)
        self._test_group_management(self.group3)

    def test_project_management(self):
        # First, authenticate with a user that does not have the project
        # admin role - shouldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_project_management(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

        # ...but should still be able to list projects of which they are
        # a member
        url = '/users/%s/projects' % self.just_a_user['id']
        self.get(url, auth=self.auth)

        # Now, authenticate with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_project_management(self.domainA['id'])

    def test_project_management_by_cloud_admin(self):
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        # Check whether cloud admin can operate a domain
        # other than its own domain or not
        self._test_project_management(self.domainA['id'])

    def test_domain_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'])

        # Check that with such a token we cannot modify grants on a
        # different domain
        self._test_grants('domains', self.domainB['id'],
                          expected=exception.ForbiddenAction.code)

    def test_domain_grants_by_cloud_admin(self):
        # Test domain grants with a cloud admin. This user should be
        # able to manage roles on any domain.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_grants('domains', self.domainA['id'])

    def test_domain_grants_by_cloud_admin_for_domain_specific_role(self):
        # Test domain grants with a cloud admin. This user should be
        # able to manage domain roles on any domain.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_grants('domains', self.domainA['id'],
                          role_domain_id=self.domainB['id'])

    def test_domain_grants_by_non_admin_for_domain_specific_role(self):
        # A non-admin shouldn't be able to do anything
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'],
                          role_domain_id=self.domainA['id'],
                          expected=exception.ForbiddenAction.code)
        self._test_grants('domains', self.domainA['id'],
                          role_domain_id=self.domainB['id'],
                          expected=exception.ForbiddenAction.code)

    def test_domain_grants_by_domain_admin_for_domain_specific_role(self):
        # Authenticate with a user that does have the domain admin role,
        # should not be able to assign a domain_specific role from another
        # domain
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'],
                          role_domain_id=self.domainB['id'],
                          # List status will always be OK, since we are not
                          # granting/checking/deleting assignments
                          list_status_OK=True,
                          expected=exception.ForbiddenAction.code)

        # They should be able to assign a domain specific role from the same
        # domain
        self._test_grants('domains', self.domainA['id'],
                          role_domain_id=self.domainA['id'])

    def test_project_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the project
        # admin role
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'])

    def test_project_grants_by_domain_admin(self):
        # Test project grants with a domain admin. This user should be
        # able to manage roles on any project in its own domain.
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('projects', self.project['id'])

    def test_project_grants_by_non_admin_for_domain_specific_role(self):
        # A non-admin shouldn't be able to do anything
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainA['id'],
                          expected=exception.ForbiddenAction.code)
        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainB['id'],
                          expected=exception.ForbiddenAction.code)

    def test_project_grants_by_project_admin_for_domain_specific_role(self):
        # Authenticate with a user that does have the project admin role,
        # should not be able to assign a domain_specific role from another
        # domain
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainB['id'],
                          # List status will always be OK, since we are not
                          # granting/checking/deleting assignments
                          list_status_OK=True,
                          expected=exception.ForbiddenAction.code)

        # They should be able to assign a domain specific role from the same
        # domain
        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainA['id'])

    def test_project_grants_by_domain_admin_for_domain_specific_role(self):
        # Authenticate with a user that does have the domain admin role,
        # should not be able to assign a domain_specific role from another
        # domain
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainB['id'],
                          # List status will always be OK, since we are not
                          # granting/checking/deleting assignments
                          list_status_OK=True,
                          expected=exception.ForbiddenAction.code)

        # They should be able to assign a domain specific role from the same
        # domain
        self._test_grants('projects', self.project['id'],
                          role_domain_id=self.domainA['id'])

    def test_cloud_admin_list_assignments_of_domain(self):
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        collection_url = self.build_role_assignment_query_url(
            domain_id=self.domainA['id'])
        r = self.get(collection_url, auth=self.auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=2, resource_url=collection_url)

        domainA_admin_entity = self.build_role_assignment_entity(
            domain_id=self.domainA['id'],
            user_id=self.domain_admin_user['id'],
            role_id=self.admin_role['id'],
            inherited_to_projects=False)
        domainA_user_entity = self.build_role_assignment_entity(
            domain_id=self.domainA['id'],
            user_id=self.just_a_user['id'],
            role_id=self.role['id'],
            inherited_to_projects=False)

        self.assertRoleAssignmentInListResponse(r, domainA_admin_entity)
        self.assertRoleAssignmentInListResponse(r, domainA_user_entity)

    def test_domain_admin_list_assignments_of_domain(self):
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        collection_url = self.build_role_assignment_query_url(
            domain_id=self.domainA['id'])
        r = self.get(collection_url, auth=self.auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=2, resource_url=collection_url)

        domainA_admin_entity = self.build_role_assignment_entity(
            domain_id=self.domainA['id'],
            user_id=self.domain_admin_user['id'],
            role_id=self.admin_role['id'],
            inherited_to_projects=False)
        domainA_user_entity = self.build_role_assignment_entity(
            domain_id=self.domainA['id'],
            user_id=self.just_a_user['id'],
            role_id=self.role['id'],
            inherited_to_projects=False)

        self.assertRoleAssignmentInListResponse(r, domainA_admin_entity)
        self.assertRoleAssignmentInListResponse(r, domainA_user_entity)

    def test_domain_admin_list_assignments_of_another_domain_failed(self):
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        collection_url = self.build_role_assignment_query_url(
            domain_id=self.domainB['id'])
        self.get(collection_url, auth=self.auth,
                 expected_status=http_client.FORBIDDEN)

    def test_domain_user_list_assignments_of_domain_failed(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        collection_url = self.build_role_assignment_query_url(
            domain_id=self.domainA['id'])
        self.get(collection_url, auth=self.auth,
                 expected_status=http_client.FORBIDDEN)

    def test_cloud_admin_list_assignments_of_project(self):
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        collection_url = self.build_role_assignment_query_url(
            project_id=self.project['id'])
        r = self.get(collection_url, auth=self.auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=2, resource_url=collection_url)

        project_admin_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.project_admin_user['id'],
            role_id=self.admin_role['id'],
            inherited_to_projects=False)
        project_user_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.just_a_user['id'],
            role_id=self.role['id'],
            inherited_to_projects=False)

        self.assertRoleAssignmentInListResponse(r, project_admin_entity)
        self.assertRoleAssignmentInListResponse(r, project_user_entity)

    def test_admin_project_list_assignments_of_project(self):
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        collection_url = self.build_role_assignment_query_url(
            project_id=self.project['id'])
        r = self.get(collection_url, auth=self.auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=2, resource_url=collection_url)

        project_admin_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.project_admin_user['id'],
            role_id=self.admin_role['id'],
            inherited_to_projects=False)
        project_user_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.just_a_user['id'],
            role_id=self.role['id'],
            inherited_to_projects=False)

        self.assertRoleAssignmentInListResponse(r, project_admin_entity)
        self.assertRoleAssignmentInListResponse(r, project_user_entity)

    def test_project_admin_list_assignments_of_another_project_failed(self):
        projectB = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(projectB['id'], projectB)
        admin_auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        collection_url = self.build_role_assignment_query_url(
            project_id=projectB['id'])
        self.get(collection_url, auth=admin_auth,
                 expected_status=exception.ForbiddenAction.code)

    @utils.wip('waiting on bug #1437407')
    def test_domain_admin_list_assignments_of_project(self):
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        collection_url = self.build_role_assignment_query_url(
            project_id=self.project['id'])
        r = self.get(collection_url, auth=self.auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=2, resource_url=collection_url)

        project_admin_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.project_admin_user['id'],
            role_id=self.admin_role['id'],
            inherited_to_projects=False)
        project_user_entity = self.build_role_assignment_entity(
            project_id=self.project['id'],
            user_id=self.just_a_user['id'],
            role_id=self.role['id'],
            inherited_to_projects=False)

        self.assertRoleAssignmentInListResponse(r, project_admin_entity)
        self.assertRoleAssignmentInListResponse(r, project_user_entity)

    def test_domain_admin_list_assignment_tree(self):
        # Add a child project to the standard test data
        sub_project = unit.new_project_ref(domain_id=self.domainA['id'],
                                           parent_id=self.project['id'])
        PROVIDERS.resource_api.create_project(sub_project['id'], sub_project)
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.just_a_user['id'],
            project_id=sub_project['id']
        )

        collection_url = self.build_role_assignment_query_url(
            project_id=self.project['id'])
        collection_url += '&include_subtree=True'

        # The domain admin should be able to list the assignment tree
        auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        r = self.get(collection_url, auth=auth)
        self.assertValidRoleAssignmentListResponse(
            r, expected_length=3, resource_url=collection_url)

        # A project admin should not be able to
        auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        r = self.get(collection_url, auth=auth,
                     expected_status=http_client.FORBIDDEN)

        # A neither should a domain admin from a different domain
        domainB_admin_user = unit.create_user(
            PROVIDERS.identity_api,
            domain_id=self.domainB['id'])
        PROVIDERS.assignment_api.create_grant(
            self.admin_role['id'], user_id=domainB_admin_user['id'],
            domain_id=self.domainB['id']
        )
        auth = self.build_authentication_request(
            user_id=domainB_admin_user['id'],
            password=domainB_admin_user['password'],
            domain_id=self.domainB['id'])

        r = self.get(collection_url, auth=auth,
                     expected_status=http_client.FORBIDDEN)

    def test_domain_user_list_assignments_of_project_failed(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        collection_url = self.build_role_assignment_query_url(
            project_id=self.project['id'])
        self.get(collection_url, auth=self.auth,
                 expected_status=http_client.FORBIDDEN)

    def test_cloud_admin(self):
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_domain_management(
            expected=exception.ForbiddenAction.code)

        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_domain_management()

    def test_admin_project(self):
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._test_domain_management(
            expected=exception.ForbiddenAction.code)

        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._test_domain_management()

    def test_domain_admin_get_domain(self):
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])
        entity_url = '/domains/%s' % self.domainA['id']
        self.get(entity_url, auth=self.auth)

    def test_project_admin_get_own_domain(self):
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])
        entity_url = '/domains/%s' % self.domainA['id']
        self.get(entity_url, auth=self.auth)

    def test_project_admin_get_other_domain_failed(self):
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])
        entity_url = '/domains/%s' % self.domainB['id']
        self.get(entity_url, auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)

    def test_list_user_credentials(self):
        credential_user = unit.new_credential_ref(self.just_a_user['id'])
        PROVIDERS.credential_api.create_credential(
            credential_user['id'], credential_user
        )
        credential_admin = unit.new_credential_ref(self.cloud_admin_user['id'])
        PROVIDERS.credential_api.create_credential(
            credential_admin['id'], credential_admin
        )

        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        url = '/credentials?user_id=%s' % self.just_a_user['id']
        self.get(url, auth=self.auth)
        url = '/credentials?user_id=%s' % self.cloud_admin_user['id']
        self.get(url, auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)
        url = '/credentials'
        self.get(url, auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)

    def test_get_and_delete_ec2_credentials(self):
        """Test getting and deleting ec2 credentials through the ec2 API."""
        another_user = unit.create_user(PROVIDERS.identity_api,
                                        domain_id=self.domainA['id'])

        # create a credential for just_a_user
        just_user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])
        url = '/users/%s/credentials/OS-EC2' % self.just_a_user['id']
        r = self.post(url, body={'tenant_id': self.project['id']},
                      auth=just_user_auth)

        # another normal user can't get the credential
        another_user_auth = self.build_authentication_request(
            user_id=another_user['id'],
            password=another_user['password'])
        another_user_url = '/users/%s/credentials/OS-EC2/%s' % (
            another_user['id'], r.result['credential']['access'])
        self.get(another_user_url, auth=another_user_auth,
                 expected_status=exception.ForbiddenAction.code)

        # the owner can get the credential
        just_user_url = '/users/%s/credentials/OS-EC2/%s' % (
            self.just_a_user['id'], r.result['credential']['access'])
        self.get(just_user_url, auth=just_user_auth)

        # another normal user can't delete the credential
        self.delete(another_user_url, auth=another_user_auth,
                    expected_status=exception.ForbiddenAction.code)

        # the owner can get the credential
        self.delete(just_user_url, auth=just_user_auth)

    def test_user_validate_same_token(self):
        # Given a non-admin user token, the token can be used to validate
        # itself.
        # This is GET /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.get('/auth/tokens', token=token,
                 headers={'X-Subject-Token': token})

    def test_user_validate_user_token(self):
        # A user can validate one of their own tokens.
        # This is GET /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.get('/auth/tokens', token=token1,
                 headers={'X-Subject-Token': token2})

    def test_user_validate_other_user_token_rejected(self):
        # A user cannot validate another user's token.
        # This is GET /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.get('/auth/tokens', token=user1_token,
                 headers={'X-Subject-Token': user2_token},
                 expected_status=http_client.FORBIDDEN)

    def test_admin_validate_user_token(self):
        # An admin can validate a user's token.
        # This is GET /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/auth/tokens', token=admin_token,
                 headers={'X-Subject-Token': user_token})

    def test_admin_project_validate_user_token(self):
        # An admin can validate a user's token.
        # This is GET /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/auth/tokens', token=admin_token,
                 headers={'X-Subject-Token': user_token})

    def test_user_check_same_token(self):
        # Given a non-admin user token, the token can be used to check
        # itself.
        # This is HEAD /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token,
                  headers={'X-Subject-Token': token},
                  expected_status=http_client.OK)

    def test_user_check_user_token(self):
        # A user can check one of their own tokens.
        # This is HEAD /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token1,
                  headers={'X-Subject-Token': token2},
                  expected_status=http_client.OK)

    def test_user_check_other_user_token_rejected(self):
        # A user cannot check another user's token.
        # This is HEAD /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.head('/auth/tokens', token=user1_token,
                  headers={'X-Subject-Token': user2_token},
                  expected_status=http_client.FORBIDDEN)

    def test_admin_check_user_token(self):
        # An admin can check a user's token.
        # This is HEAD /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.head('/auth/tokens', token=admin_token,
                  headers={'X-Subject-Token': user_token},
                  expected_status=http_client.OK)

    def test_user_revoke_same_token(self):
        # Given a non-admin user token, the token can be used to revoke
        # itself.
        # This is DELETE /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token,
                    headers={'X-Subject-Token': token})

    def test_user_revoke_user_token(self):
        # A user can revoke one of their own tokens.
        # This is DELETE /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token1,
                    headers={'X-Subject-Token': token2})

    def test_user_revoke_other_user_token_rejected(self):
        # A user cannot revoke another user's token.
        # This is DELETE /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.delete('/auth/tokens', token=user1_token,
                    headers={'X-Subject-Token': user2_token},
                    expected_status=http_client.FORBIDDEN)

    def test_admin_revoke_user_token(self):
        # An admin can revoke a user's token.
        # This is DELETE /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.delete('/auth/tokens', token=admin_token,
                    headers={'X-Subject-Token': user_token})

    def test_list_revoke_events_is_protected(self):
        # An admin can list revoke events, a regular user cannot
        # This is GET /v3/OS-REVOKE/events

        admin_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/OS-REVOKE/events', token=admin_token)
        self.get('/OS-REVOKE/events', token=user_token, expected_status=403)

    def test_user_with_a_role_get_project(self):
        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        # Test user can get project for one they have a role in
        self.get('/projects/%s' % self.project['id'], auth=user_auth)

        # Test user can not get project for one they don't have a role in,
        # even if they have a role on another project
        project2 = unit.new_project_ref(domain_id=self.domainA['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        self.get('/projects/%s' % project2['id'], auth=user_auth,
                 expected_status=exception.ForbiddenAction.code)

    def test_project_admin_get_project(self):
        admin_auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        resp = self.get('/projects/%s' % self.project['id'], auth=admin_auth)
        self.assertEqual(self.project['id'],
                         jsonutils.loads(resp.body)['project']['id'])

    def test_role_management_no_admin_no_rights(self):
        # A non-admin domain user shouldn't be able to manipulate roles
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._role_management_cases(expected=exception.ForbiddenAction.code)

        # ...and nor should non-admin project user
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._role_management_cases(expected=exception.ForbiddenAction.code)

    def test_role_management_with_project_admin(self):
        # A project admin user should be able to get and list, but not be able
        # to create/update/delete global roles
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._role_management_cases(read_status_OK=True,
                                    expected=exception.ForbiddenAction.code)

    def test_role_management_with_domain_admin(self):
        # A domain admin user should be able to get and list, but not be able
        # to create/update/delete global roles
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._role_management_cases(read_status_OK=True,
                                    expected=exception.ForbiddenAction.code)

    def test_role_management_with_cloud_admin(self):
        # A cloud admin user should have rights to manipulate global roles
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._role_management_cases()

    def test_domain_role_management_no_admin_no_rights(self):
        # A non-admin domain user shouldn't be able to manipulate domain roles
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._domain_role_management_cases(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

        # ...and nor should non-admin project user
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._domain_role_management_cases(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

    def test_domain_role_management_with_cloud_admin(self):
        # A cloud admin user should have rights to manipulate domain roles
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        self._domain_role_management_cases(self.domainA['id'])

    def test_domain_role_management_with_domain_admin(self):
        # A domain admin user should only be able to manipulate the domain
        # specific roles in their own domain
        self.auth = self.build_authentication_request(
            user_id=self.domainB_admin_user['id'],
            password=self.domainB_admin_user['password'],
            domain_id=self.domainB['id'])

        # Try to access the domain specific roles in another domain
        self._domain_role_management_cases(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

        # ...but they should be able to work with those in their own domain
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._domain_role_management_cases(self.domainA['id'])

    def test_domain_role_management_with_project_admin(self):
        # A project admin user should have not access to domain specific roles
        # in another domain. They should be able to get and list domain
        # specific roles from their own domain, but not be able to create,
        # update or delete them,
        self.auth = self.build_authentication_request(
            user_id=self.project_adminB_user['id'],
            password=self.project_adminB_user['password'],
            project_id=self.projectB['id'])

        # Try access the domain specific roless in another domain
        self._domain_role_management_cases(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

        # ...but they should be ablet to work with those in their own domain
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._domain_role_management_cases(
            self.domainA['id'], read_status_OK=True,
            expected=exception.ForbiddenAction.code)


class IdentityTestImpliedDomainSpecificRoles(IdentityTestv3CloudPolicySample):
    """Test Domain specific Implied Roles via the REST API."""

    def setUp(self):
        super(IdentityTestImpliedDomainSpecificRoles, self).setUp()

        domain_admin_auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])
        self.admin_token = self.get_requested_token(domain_admin_auth)

        self.appdev_role = unit.new_role_ref(domain_id=self.domainA['id'])
        PROVIDERS.role_api.create_role(
            self.appdev_role['id'], self.appdev_role
        )

        self.appadmin_role = unit.new_role_ref(domain_id=self.domainA['id'])
        PROVIDERS.role_api.create_role(
            self.appadmin_role['id'], self.appadmin_role
        )

    def _create_implied_role(self):
        PROVIDERS.role_api.create_implied_role(
            self.appadmin_role['id'], self.appdev_role['id']
        )

    def test_get(self):
        # A domain admin should be able to get an existing implied role
        # on the domain for which they are the admin.
        self._create_implied_role()

        self.get('/roles/%s/implies/%s'
                 % (self.appadmin_role['id'], self.appdev_role['id']),
                 token=self.admin_token)

    def test_list(self):
        # A domain admin should be able to list the implications of an
        # existing implied role on the domain for which they are the admin.
        self._create_implied_role()

        self.get('/roles/%s/implies' % (self.appadmin_role['id'], ),
                 token=self.admin_token)

    def test_check(self):
        # A domain admin should be able to check an existing implied role
        # on the domain for which they are the admin.
        self._create_implied_role()

        self.head('/roles/%s/implies/%s'
                  % (self.appadmin_role['id'], self.appdev_role['id']),
                  token=self.admin_token)

    def test_put(self):
        # A domain admin should be able to create an implied role on the
        # domain for which they are the admin.
        self.put('/roles/%s/implies/%s'
                 % (self.appadmin_role['id'], self.appdev_role['id']),
                 token=self.admin_token,
                 expected_status=http_client.CREATED)

    def test_delete(self):
        # A domain admin should be able to check an existing implied role
        # on the domain for which they are the admin.
        self._create_implied_role()

        self.delete('/roles/%s/implies/%s'
                    % (self.appadmin_role['id'], self.appdev_role['id']),
                    token=self.admin_token)

    def test_forbidden_role_implication_from_different_domain(self):
        domain2 = unit.new_domain_ref(domain_id=uuid.uuid4().hex)
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)

        role2 = unit.new_role_ref(domain_id=domain2['id'])
        implied = PROVIDERS.role_api.create_role(role2['id'], role2)

        self.put('/roles/%s/implies/%s'
                 % (self.appdev_role['id'], implied['id']),
                 token=self.admin_token,
                 expected_status=http_client.FORBIDDEN)

    def test_allowed_role_implication_different_domains_as_cloud_admin(self):
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            project_id=self.admin_project['id'])

        domain2 = unit.new_domain_ref(domain_id=uuid.uuid4().hex)
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)

        role2 = unit.new_role_ref(domain_id=domain2['id'])
        implied = PROVIDERS.role_api.create_role(role2['id'], role2)

        self.put('/roles/%s/implies/%s'
                 % (self.appdev_role['id'], implied['id']),
                 auth=self.auth,
                 expected_status=http_client.CREATED)
