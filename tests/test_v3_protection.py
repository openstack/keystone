# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import json
import tempfile
import uuid

import nose.exc

from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.policy.backends import rules

import test_v3


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class IdentityTestProtectedCase(test_v3.RestfulTestCase):
    """Test policy protection of a sample of v3 identity apis"""

    def setUp(self):
        """Setup for Identity Protection Test Cases.

        As well as the usual housekeeping, create a set of domains,
        users, roles and projects for the subsequent tests:

        - Three domains: A,B & C.  C is disabled.
        - DomainA has user1, DomainB has user2 and user3
        - DomainA has group1 and group2, DomainB has group3
        - User1 has a role on DomainA

        Remember that there will also be a fourth domain in existence,
        the default domain.

        """
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestProtectedCase, self).setUp(load_sample_data=False)
        # Start by creating a couple of domains
        self.domainA = self.new_domain_ref()
        domainA_ref = self.identity_api.create_domain(self.domainA['id'],
                                                      self.domainA)
        self.domainB = self.new_domain_ref()
        domainB_ref = self.identity_api.create_domain(self.domainB['id'],
                                                      self.domainB)
        self.domainC = self.new_domain_ref()
        self.domainC['enabled'] = False
        domainC_ref = self.identity_api.create_domain(self.domainC['id'],
                                                      self.domainC)

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = self.new_user_ref(
            domain_id=self.domainA['id'])
        self.user1['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user1['id'],
                                                 self.user1)

        self.user2 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user2['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user2['id'],
                                                 self.user2)

        self.user3 = self.new_user_ref(
            domain_id=self.domainB['id'])
        self.user3['password'] = uuid.uuid4().hex
        user_ref = self.identity_api.create_user(self.user3['id'],
                                                 self.user3)

        self.group1 = self.new_group_ref(
            domain_id=self.domainA['id'])
        user_ref = self.identity_api.create_group(self.group1['id'],
                                                  self.group1)

        self.group2 = self.new_group_ref(
            domain_id=self.domainA['id'])
        user_ref = self.identity_api.create_group(self.group2['id'],
                                                  self.group2)

        self.group3 = self.new_group_ref(
            domain_id=self.domainB['id'])
        user_ref = self.identity_api.create_group(self.group3['id'],
                                                  self.group3)

        self.role = self.new_role_ref()
        self.identity_api.create_role(self.role['id'], self.role)
        self.identity_api.create_grant(self.role['id'],
                                       user_id=self.user1['id'],
                                       domain_id=self.domainA['id'])

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
        id_list = self._get_id_list_from_ref_list(r.body.get('users'))
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
        id_list = self._get_id_list_from_ref_list(r.body.get('users'))
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
        # TODO (henry-nash, ayoung): It would be good to expand this
        # test for further test flattening, e.g. protect on, say, an
        # attribute of an object being created
        new_policy = {"identity:get_user": [["user_id:%(user_id)s"]]}
        self._set_policy(new_policy)
        url_by_name = '/users/%s' % self.user1['id']
        r = self.get(url_by_name, auth=self.auth)
        body = r.body
        self.assertEquals(self.user1['id'], body['user']['id'])

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
        id_list = self._get_id_list_from_ref_list(r.body.get('users'))
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
        id_list = self._get_id_list_from_ref_list(r.body.get('groups'))
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
        id_list = self._get_id_list_from_ref_list(r.body.get('groups'))
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
        id_list = self._get_id_list_from_ref_list(r.body.get('domains'))
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.domainC['id'], id_list)

        # Now try a few ways of specifying 'true' when we should get back
        # the other two domains, plus the default domain
        r = self.get('/domains?enabled=1', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.body.get('domains'))
        self.assertEqual(len(id_list), 3)
        self.assertIn(self.domainA['id'], id_list)
        self.assertIn(self.domainB['id'], id_list)
        self.assertIn(DEFAULT_DOMAIN_ID, id_list)

        r = self.get('/domains?enabled', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.body.get('domains'))
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
        id_list = self._get_id_list_from_ref_list(r.body.get('domains'))
        self.assertEqual(len(id_list), 1)
        self.assertIn(self.domainA['id'], id_list)
