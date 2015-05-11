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

import uuid

from oslo_config import cfg
from oslo_serialization import jsonutils
from six.moves import range

from keystone.tests.unit import filtering
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class IdentityTestFilteredCase(filtering.FilterTests,
                               test_v3.RestfulTestCase):
    """Test filter enforcement on the v3 Identity API."""

    def setUp(self):
        """Setup for Identity Filter Test Cases."""

        super(IdentityTestFilteredCase, self).setUp()
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        self.config_fixture.config(group='oslo_policy',
                                   policy_file=self.tmpfilename)

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
        self._populate_default_domain()
        self.domainA = self.new_domain_ref()
        self.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = self.new_domain_ref()
        self.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.domainC = self.new_domain_ref()
        self.domainC['enabled'] = False
        self.resource_api.create_domain(self.domainC['id'], self.domainC)

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = self.new_user_ref(domain_id=self.domainA['id'])
        password = uuid.uuid4().hex
        self.user1['password'] = password
        self.user1 = self.identity_api.create_user(self.user1)
        self.user1['password'] = password

        self.user2 = self.new_user_ref(domain_id=self.domainB['id'])
        self.user2['password'] = password
        self.user2 = self.identity_api.create_user(self.user2)
        self.user2['password'] = password

        self.user3 = self.new_user_ref(domain_id=self.domainB['id'])
        self.user3['password'] = password
        self.user3 = self.identity_api.create_user(self.user3)
        self.user3['password'] = password

        self.role = self.new_role_ref()
        self.role_api.create_role(self.role['id'], self.role)
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
        - Try the filter using different ways of specifying True/False
          to test that our handling of booleans in filter matching is
          correct

        """
        new_policy = {"identity:list_domains": []}
        self._set_policy(new_policy)
        r = self.get('/domains?enabled=0', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.domainC['id'], id_list)

        # Try a few ways of specifying 'false'
        for val in ('0', 'false', 'False', 'FALSE', 'n', 'no', 'off'):
            r = self.get('/domains?enabled=%s' % val, auth=self.auth)
            id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
            self.assertEqual([self.domainC['id']], id_list)

        # Now try a few ways of specifying 'true' when we should get back
        # the other two domains, plus the default domain
        for val in ('1', 'true', 'True', 'TRUE', 'y', 'yes', 'on'):
            r = self.get('/domains?enabled=%s' % val, auth=self.auth)
            id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
            self.assertEqual(3, len(id_list))
            self.assertIn(self.domainA['id'], id_list)
            self.assertIn(self.domainB['id'], id_list)
            self.assertIn(CONF.identity.default_domain_id, id_list)

        r = self.get('/domains?enabled', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(3, len(id_list))
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

        my_url = '/domains?enabled&name=%s' % self.domainA['name']
        r = self.get(my_url, auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.domainA['id'], id_list)
        self.assertIs(True, r.result.get('domains')[0]['enabled'])

    def test_invalid_filter_is_ignored(self):
        """GET /domains?enableds&name=myname

        Test Plan:

        - Update policy for no protection on api
        - Filter by name and 'enableds', which does not exist
        - Assert 'enableds' is ignored

        """
        new_policy = {"identity:list_domains": []}
        self._set_policy(new_policy)

        my_url = '/domains?enableds=0&name=%s' % self.domainA['name']
        r = self.get(my_url, auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('domains'))

        # domainA is returned and it is enabled, since enableds=0 is not the
        # same as enabled=0
        self.assertEqual(1, len(id_list))
        self.assertIn(self.domainA['id'], id_list)
        self.assertIs(True, r.result.get('domains')[0]['enabled'])

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

        self.assertEqual(1, len(r.result.get('users')))
        self.assertEqual(user['id'], r.result.get('users')[0]['id'])

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
        self.assertEqual(4, len(r.result.get('users')))
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=6, list_end=10)

        url_by_name = '/users?name__icontains=miNIstry'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(5, len(r.result.get('users')))
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=6, list_end=11)

        url_by_name = '/users?name__startswith=The'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(5, len(r.result.get('users')))
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=5, list_end=10)

        url_by_name = '/users?name__istartswith=the'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(6, len(r.result.get('users')))
        self._match_with_list(r.result.get('users'), user_list,
                              list_start=5, list_end=11)

        url_by_name = '/users?name__endswith=of'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(1, len(r.result.get('users')))
        self.assertEqual(r.result.get('users')[0]['id'], user_list[7]['id'])

        url_by_name = '/users?name__iendswith=OF'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(2, len(r.result.get('users')))
        self.assertEqual(user_list[7]['id'], r.result.get('users')[0]['id'])
        self.assertEqual(user_list[10]['id'], r.result.get('users')[1]['id'])

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

        self.assertEqual(0, len(r.result.get('users')))

        # See if we can add a SQL command...use the group table instead of the
        # user table since 'user' is reserved word for SQLAlchemy.
        group = self.new_group_ref(domain_id=self.domainB['id'])
        group = self.identity_api.create_group(group)

        url_by_name = "/users?name=x'; drop table group"
        r = self.get(url_by_name, auth=self.auth)

        # Check group table is still there...
        url_by_name = "/groups"
        r = self.get(url_by_name, auth=self.auth)
        self.assertTrue(len(r.result.get('groups')) > 0)


class IdentityTestListLimitCase(IdentityTestFilteredCase):
    """Test list limiting enforcement on the v3 Identity API."""
    content_type = 'json'

    def setUp(self):
        """Setup for Identity Limit Test Cases."""

        super(IdentityTestListLimitCase, self).setUp()

        # Create 10 entries for each of the entities we are going to test
        self.ENTITY_TYPES = ['user', 'group', 'project']
        self.entity_lists = {}
        for entity in self.ENTITY_TYPES:
            self.entity_lists[entity] = self._create_test_data(entity, 10)
            # Make sure we clean up when finished
            self.addCleanup(self.clean_up_entity, entity)

        self.service_list = []
        self.addCleanup(self.clean_up_service)
        for _ in range(10):
            new_entity = {'id': uuid.uuid4().hex, 'type': uuid.uuid4().hex}
            service = self.catalog_api.create_service(new_entity['id'],
                                                      new_entity)
            self.service_list.append(service)

        self.policy_list = []
        self.addCleanup(self.clean_up_policy)
        for _ in range(10):
            new_entity = {'id': uuid.uuid4().hex, 'type': uuid.uuid4().hex,
                          'blob': uuid.uuid4().hex}
            policy = self.policy_api.create_policy(new_entity['id'],
                                                   new_entity)
            self.policy_list.append(policy)

    def clean_up_entity(self, entity):
        """Clean up entity test data from Identity Limit Test Cases."""

        self._delete_test_data(entity, self.entity_lists[entity])

    def clean_up_service(self):
        """Clean up service test data from Identity Limit Test Cases."""

        for service in self.service_list:
            self.catalog_api.delete_service(service['id'])

    def clean_up_policy(self):
        """Clean up policy test data from Identity Limit Test Cases."""

        for policy in self.policy_list:
            self.policy_api.delete_policy(policy['id'])

    def _test_entity_list_limit(self, entity, driver):
        """GET /<entities> (limited)

        Test Plan:

        - For the specified type of entity:
            - Update policy for no protection on api
            - Add a bunch of entities
            - Set the global list limit to 5, and check that getting all
            - entities only returns 5
            - Set the driver list_limit to 4, and check that now only 4 are
            - returned

        """
        if entity == 'policy':
            plural = 'policies'
        else:
            plural = '%ss' % entity

        self._set_policy({"identity:list_%s" % plural: []})
        self.config_fixture.config(list_limit=5)
        self.config_fixture.config(group=driver, list_limit=None)
        r = self.get('/%s' % plural, auth=self.auth)
        self.assertEqual(5, len(r.result.get(plural)))
        self.assertIs(r.result.get('truncated'), True)

        self.config_fixture.config(group=driver, list_limit=4)
        r = self.get('/%s' % plural, auth=self.auth)
        self.assertEqual(4, len(r.result.get(plural)))
        self.assertIs(r.result.get('truncated'), True)

    def test_users_list_limit(self):
        self._test_entity_list_limit('user', 'identity')

    def test_groups_list_limit(self):
        self._test_entity_list_limit('group', 'identity')

    def test_projects_list_limit(self):
        self._test_entity_list_limit('project', 'resource')

    def test_services_list_limit(self):
        self._test_entity_list_limit('service', 'catalog')

    def test_non_driver_list_limit(self):
        """Check list can be limited without driver level support.

        Policy limiting is not done at the driver level (since it
        really isn't worth doing it there).  So use this as a test
        for ensuring the controller level will successfully limit
        in this case.

        """
        self._test_entity_list_limit('policy', 'policy')

    def test_no_limit(self):
        """Check truncated attribute not set when list not limited."""

        self._set_policy({"identity:list_services": []})
        r = self.get('/services', auth=self.auth)
        self.assertEqual(10, len(r.result.get('services')))
        self.assertIsNone(r.result.get('truncated'))

    def test_at_limit(self):
        """Check truncated attribute not set when list at max size."""

        # Test this by overriding the general limit with a higher
        # driver-specific limit (allowing all entities to be returned
        # in the collection), which should result in a non truncated list
        self._set_policy({"identity:list_services": []})
        self.config_fixture.config(list_limit=5)
        self.config_fixture.config(group='catalog', list_limit=10)
        r = self.get('/services', auth=self.auth)
        self.assertEqual(10, len(r.result.get('services')))
        self.assertIsNone(r.result.get('truncated'))
