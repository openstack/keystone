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

import tempfile
import uuid

from keystone import config
from keystone.openstack.common import jsonutils
from keystone.policy.backends import rules
from keystone.tests import filtering
from keystone.tests import test_v3


CONF = config.CONF


class IdentityTestFilteredCase(filtering.FilterTests,
                               test_v3.RestfulTestCase):
    """Test filter enforcement on the v3 Identity API."""

    def setUp(self):
        """Setup for Identity Filter Test Cases."""

        super(IdentityTestFilteredCase, self).setUp()

        # Initialize the policy engine and allow us to write to a temp
        # file in each test to create the policies
        self.orig_policy_file = CONF.policy_file
        rules.reset()
        _unused, self.tmpfilename = tempfile.mkstemp()
        self.opt(policy_file=self.tmpfilename)

        #drop the policy rules
        self.addCleanup(rules.reset)

    def load_sample_data(self):
        """Create sample data for these tests.

        As well as the usual housekeeping, create a set of domains,
        users, roles and projects for the subsequent tests:

        - Three domains: A,B & C.  C is disabled.
        - DomainA has user1, DomainB has user2 and user3
        - DomainA has group1 and group2, DomainB has group3
        - User1 has a role on DomainA

        Remember that there will also be a fourth domain in existence,
        the default domain.

        """
        # Start by creating a few domains
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

        self.role = self.new_role_ref()
        self.assignment_api.create_role(self.role['id'], self.role)
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user1['id'],
                                         domain_id=self.domainA['id'])

        # A default auth request we can use - un-scoped user token
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'])

    def _get_id_list_from_ref_list(self, ref_list):
        result_list = []
        for x in ref_list:
            result_list.append(x['id'])
        return result_list

    def _set_policy(self, new_policy):
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))

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
        self.assertIn(CONF.identity.default_domain_id, id_list)

        r = self.get('/domains?enabled', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(len(id_list), 3)
        self.assertIn(self.domainA['id'], id_list)
        self.assertIn(self.domainB['id'], id_list)
        self.assertIn(CONF.identity.default_domain_id, id_list)

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

    def test_list_users_filtered_by_funny_name(self):
        """GET /users?name=%myname%

        Test Plan:
        - Update policy so api is unprotected
        - Update a user with name that has filter escape characters
        - Ensure we can filter on it

        """
        self._set_policy({"identity:list_users": []})
        user = self.user1
        user['name'] = '%my%name%'
        self.identity_api.update_user(user['id'], user)

        url_by_name = '/users?name=%my%name%'
        r = self.get(url_by_name, auth=self.auth)

        self.assertEqual(len(r.result.get('users')), 1)
        self.assertEqual(r.result.get('users')[0]['id'], user['id'])

    def test_inexact_filters(self):
        # Create 20 users
        user_list = self._create_test_data('user', 20)
        # Set up some names that we can filter on
        user = user_list[5]
        user['name'] = 'The'
        self.identity_api.update_user(user['id'], user)
        user = user_list[6]
        user['name'] = 'The Ministry'
        self.identity_api.update_user(user['id'], user)
        user = user_list[7]
        user['name'] = 'The Ministry of'
        self.identity_api.update_user(user['id'], user)
        user = user_list[8]
        user['name'] = 'The Ministry of Silly'
        self.identity_api.update_user(user['id'], user)
        user = user_list[9]
        user['name'] = 'The Ministry of Silly Walks'
        self.identity_api.update_user(user['id'], user)
        # ...and one for useful case insensitivity testing
        user = user_list[10]
        user['name'] = 'the ministry of silly walks OF'
        self.identity_api.update_user(user['id'], user)

        self._set_policy({"identity:list_users": []})

        url_by_name = '/users?name__contains=Ministry'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 4)
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=6, list_end=10)

        url_by_name = '/users?name__icontains=miNIstry'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 5)
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=6, list_end=11)

        url_by_name = '/users?name__startswith=The'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 5)
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=5, list_end=10)

        url_by_name = '/users?name__istartswith=the'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 6)
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=5, list_end=11)

        url_by_name = '/users?name__endswith=of'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 1)
        self.assertEqual(r.result.get('users')[0]['id'], user_list[7]['id'])

        url_by_name = '/users?name__iendswith=OF'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(len(r.result.get('users')), 2)
        self.assertEqual(r.result.get('users')[0]['id'], user_list[7]['id'])
        self.assertEqual(r.result.get('users')[1]['id'], user_list[10]['id'])

        self._delete_test_data('user', user_list)

    def test_filter_sql_injection_attack(self):
        """GET /users?name=<injected sql_statement>

        Test Plan:
        - Attempt to get all entities back by passing a two-term attribute
        - Attempt to piggyback filter to damage DB (e.g. drop table)

        """
        self._set_policy({"identity:list_users": [],
                          "identity:list_groups": [],
                          "identity:create_group": []})

        url_by_name = "/users?name=anything' or 'x'='x"
        r = self.get(url_by_name, auth=self.auth)

        self.assertEqual(len(r.result.get('users')), 0)

        # See if we can add a SQL command...use the group table instead of the
        # user table since 'user' is reserved word for SQLAlchemy.
        group = self.new_group_ref(domain_id=self.domainB['id'])
        self.identity_api.create_group(group['id'], group)

        url_by_name = "/users?name=x'; drop table group"
        r = self.get(url_by_name, auth=self.auth)

        # Check group table is still there...
        url_by_name = "/groups"
        r = self.get(url_by_name, auth=self.auth)
        self.assertTrue(len(r.result.get('groups')) > 0)
