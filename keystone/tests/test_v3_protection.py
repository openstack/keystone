# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import tempfile
import uuid

from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.policy.backends import rules
from keystone import tests
from keystone.tests import test_v3


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class IdentityTestProtectedCase(test_v3.RestfulTestCase):
    """Test policy enforcement on the v3 Identity API."""

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
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestProtectedCase, self).setUp()

        # Initialize the policy engine and allow us to write to a temp
        # file in each test to create the policies
        self.orig_policy_file = CONF.policy_file
        rules.reset()
        _unused, self.tmpfilename = tempfile.mkstemp()
        self.opt(policy_file=self.tmpfilename)

        # A default auth request we can use - un-scoped user token
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'])

    def tearDown(self):
        super(IdentityTestProtectedCase, self).tearDown()
        rules.reset()
        self.opt(policy_file=self.orig_policy_file)

    def load_sample_data(self):
        # Start by creating a couple of domains
        self.domainA = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainB['id'], self.domainB)
        self.domainC = self.new_domain_ref()
        self.domainC['enabled'] = False
        self.assignment_api.create_domain(self.domainC['id'], self.domainC)

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = self.new_user_ref(domain_id=self.domainA['id'])
        self.user1['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user1['id'], self.user1)

        self.user2 = self.new_user_ref(domain_id=self.domainB['id'])
        self.user2['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user2['id'], self.user2)

        self.user3 = self.new_user_ref(domain_id=self.domainB['id'])
        self.user3['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.user3['id'], self.user3)

        self.group1 = self.new_group_ref(domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group1['id'], self.group1)

        self.group2 = self.new_group_ref(domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group2['id'], self.group2)

        self.group3 = self.new_group_ref(domain_id=self.domainB['id'])
        self.identity_api.create_group(self.group3['id'], self.group3)

        self.role = self.new_role_ref()
        self.assignment_api.create_role(self.role['id'], self.role)
        self.role1 = self.new_role_ref()
        self.assignment_api.create_role(self.role1['id'], self.role1)
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user1['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user2['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user1['id'],
                                         domain_id=self.domainA['id'])

    def _get_id_list_from_ref_list(self, ref_list):
        result_list = []
        for x in ref_list:
            result_list.append(x['id'])
        return result_list

    def _set_policy(self, new_policy):
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))

    def test_list_users_unprotected(self):
        """GET /users (unprotected)

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

    def test_list_users_filtered_by_domain(self):
        """GET /users?domain_id=mydomain (filtered)

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
        """GET /users/{id} (match payload)

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
        """GET /users/{id} (match target)

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
        """DELETE /domains/{id}/users/{id}/roles/{id} (match target)

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
        """GET /users?domain_id=mydomain (protected)

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
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.user1['id'], id_list)

        # Now try for domainB, which should fail
        url_by_name = '/users?domain_id=%s' % self.domainB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_domain(self):
        """GET /groups?domain_id=mydomain (protected)

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
        self.assertEqual(len(id_list), 2)
        self.assertIn(self.group1['id'], id_list)
        self.assertIn(self.group2['id'], id_list)

        # Now try for domainB, which should fail
        url_by_name = '/groups?domain_id=%s' % self.domainB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_domain_and_filtered(self):
        """GET /groups?domain_id=mydomain&name=myname (protected)

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
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.group2['id'], id_list)

    def test_list_filtered_domains(self):
        """GET /domains?enabled=0

        Test Plan:
        - Update policy for no protection on api
        - Filter by the 'enabled' boolean to get disabled domains, which
          should return just domainC
        - Try the filter using different ways of specifying 'true'
          to test that our handling of booleans in filter matching is
          correct

        """
        new_policy = {"identity:list_domains": []}
        self._set_policy(new_policy)
        r = self.get('/domains?enabled=0', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.domainC['id'], id_list)

        # Now try a few ways of specifying 'true' when we should get back
        # the other two domains, plus the default domain
        r = self.get('/domains?enabled=1', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(len(id_list), 3)
        self.assertIn(self.domainA['id'], id_list)
        self.assertIn(self.domainB['id'], id_list)
        self.assertIn(DEFAULT_DOMAIN_ID, id_list)

        r = self.get('/domains?enabled', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(len(id_list), 3)
        self.assertIn(self.domainA['id'], id_list)
        self.assertIn(self.domainB['id'], id_list)
        self.assertIn(DEFAULT_DOMAIN_ID, id_list)

    def test_multiple_filters(self):
        """GET /domains?enabled&name=myname

        Test Plan:
        - Update policy for no protection on api
        - Filter by the 'enabled' boolean and name - this should
          return a single domain

        """
        new_policy = {"identity:list_domains": []}
        self._set_policy(new_policy)

        my_url = '/domains?enableds&name=%s' % self.domainA['name']
        r = self.get(my_url, auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.domainA['id'], id_list)


class IdentityTestv3CloudPolicySample(test_v3.RestfulTestCase):
    """Test policy enforcement of the sample v3 cloud policy file."""

    def setUp(self):
        """Setup for v3 Cloud Policy Sample Test Cases.

        The following data is created:

        - Three domains: A, B and admin_domain, and one project
        - DomainA has users: domain_admin and just_a_user. domain_admin has
          role 'admin', just_a_user does not
        - admin_domain has user cloud_admin, with a plain role
        - domain_admin and just_a_user gave the same roles on the project

        We test various api protection rules from the cloud sample policy
        file to make sure the sample is valid and that we correctly enforce it.

        """
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestv3CloudPolicySample, self).setUp()

        # Finally, switch to the v3 sample policy file
        self.orig_policy_file = CONF.policy_file
        rules.reset()
        self.opt(policy_file=tests.etcdir('policy.v3cloudsample.json'))

    def load_sample_data(self):
        # Start by creating a couple of domains
        self.domainA = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainB['id'], self.domainB)
        self.admin_domain = {'id': 'admin_domain_id', 'name': 'Admin_domain'}
        self.assignment_api.create_domain(self.admin_domain['id'],
                                          self.admin_domain)

        # And our users
        self.cloud_admin_user = self.new_user_ref(
            domain_id=self.admin_domain['id'])
        self.cloud_admin_user['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.cloud_admin_user['id'],
                                      self.cloud_admin_user)
        self.just_a_user = self.new_user_ref(domain_id=self.domainA['id'])
        self.just_a_user['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.just_a_user['id'], self.just_a_user)
        self.domain_admin_user = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.domain_admin_user['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.domain_admin_user['id'],
                                      self.domain_admin_user)
        self.project_admin_user = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.project_admin_user['password'] = uuid.uuid4().hex
        self.identity_api.create_user(self.project_admin_user['id'],
                                      self.project_admin_user)

        # The admin role and another plain role
        self.admin_role = {'id': uuid.uuid4().hex, 'name': 'admin'}
        self.assignment_api.create_role(self.admin_role['id'], self.admin_role)
        self.role = self.new_role_ref()
        self.assignment_api.create_role(self.role['id'], self.role)

        # The cloud admin just gets the admin role
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.cloud_admin_user['id'],
                                         domain_id=self.admin_domain['id'])

        # Assign roles to the domain
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.domain_admin_user['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.just_a_user['id'],
                                         domain_id=self.domainA['id'])

        # Create a assign roles to the project
        self.project = self.new_project_ref(domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.project['id'], self.project)
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.project_admin_user['id'],
                                         project_id=self.project['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.just_a_user['id'],
                                         project_id=self.project['id'])

    def tearDown(self):
        super(IdentityTestv3CloudPolicySample, self).tearDown()
        rules.reset()
        self.opt(policy_file=self.orig_policy_file)

    def _stati(self, expected_status):
        # Return the expected return codes for APIs with and without data
        # with any specified status overriding the normal values
        if expected_status is None:
            return (200, 201, 204)
        else:
            return (expected_status, expected_status, expected_status)

    def _test_user_management(self, domain_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/users/%s' % self.just_a_user['id']
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

        user_ref = self.new_user_ref(domain_id=domain_id)
        self.post('/users', auth=self.auth, body={'user': user_ref},
                  expected_status=status_created)

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

        proj_ref = self.new_project_ref(domain_id=domain_id)
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

        domain_ref = self.new_domain_ref()
        self.post('/domains', auth=self.auth, body={'domain': domain_ref},
                  expected_status=status_created)

    def _test_grants(self, target, entity_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        a_role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assignment_api.create_role(a_role['id'], a_role)

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
        self.get(collection_url, auth=self.auth,
                 expected_status=status_OK)
        self.delete(member_url, auth=self.auth,
                    expected_status=status_no_data)

    def test_user_management(self):
        # First, authentication with a user that does not have the domain
        # admin role - houldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_user_management(
            self.domainA['id'], expected=exception.ForbiddenAction.code)

        # Now, authentication with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_user_management(self.domainA['id'])

    def test_project_management(self):
        # First, authentication with a user that does not have the project
        # admin role - houldn't be able to do much.
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

        # Now, authentication with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_project_management(self.domainA['id'])

    def test_domain_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authentication with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.domain_admin_user['id'],
            password=self.domain_admin_user['password'],
            domain_id=self.domainA['id'])

        self._test_grants('domains', self.domainA['id'])

    def test_project_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authentication with a user that does have the domain admin role
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'])

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
            domain_id=self.admin_domain['id'])

        self._test_domain_management()
