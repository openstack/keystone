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

import datetime

import freezegun
import http.client
from oslo_config import fixture as config_fixture
from oslo_serialization import jsonutils

from keystone.common import provider_api
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import filtering
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class IdentityTestFilteredCase(filtering.FilterTests,
                               test_v3.RestfulTestCase):
    """Test filter enforcement on the v3 Identity API."""

    def _policy_fixture(self):
        return ksfixtures.Policy(
            self.config_fixture, policy_file=self.tmpfilename
        )

    def setUp(self):
        """Setup for Identity Filter Test Cases."""
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        super(IdentityTestFilteredCase, self).setUp()

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
        self.domainA = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainA['id'], self.domainA)
        self.domainB = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domainB['id'], self.domainB)
        self.domainC = unit.new_domain_ref()
        self.domainC['enabled'] = False
        PROVIDERS.resource_api.create_domain(self.domainC['id'], self.domainC)

        # Now create some users, one in domainA and two of them in domainB
        self.user1 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainA['id'])
        self.user2 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])
        self.user3 = unit.create_user(PROVIDERS.identity_api,
                                      domain_id=self.domainB['id'])

        self.role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(self.role['id'], self.role)
        PROVIDERS.assignment_api.create_grant(
            self.role['id'], user_id=self.user1['id'],
            domain_id=self.domainA['id']
        )

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

    def test_list_filtered_domains(self):
        """GET /domains?enabled=0.

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
        """GET /domains?enabled&name=myname.

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
        """GET /domains?enableds&name=myname.

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
        """GET /users?name=%myname%.

        Test Plan:

        - Update policy so api is unprotected
        - Update a user with name that has filter escape characters
        - Ensure we can filter on it

        """
        # NOTE(lbragstad): Since Fernet tokens do not support sub-second
        # precision we must freeze the clock and ensure we increment the time
        # by a full second after a recovation event has occurred. Otherwise the
        # token will be considered revoked even though it is actually a valid
        # token.
        time = datetime.datetime.utcnow()
        with freezegun.freeze_time(time) as frozen_datetime:

            self._set_policy({"identity:list_users": []})
            user = self.user1
            user['name'] = '%my%name%'
            PROVIDERS.identity_api.update_user(user['id'], user)

            frozen_datetime.tick(delta=datetime.timedelta(seconds=1))

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
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = user_list[6]
        user['name'] = 'The Ministry'
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = user_list[7]
        user['name'] = 'The Ministry of'
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = user_list[8]
        user['name'] = 'The Ministry of Silly'
        PROVIDERS.identity_api.update_user(user['id'], user)
        user = user_list[9]
        user['name'] = 'The Ministry of Silly Walks'
        PROVIDERS.identity_api.update_user(user['id'], user)
        # ...and one for useful case insensitivity testing
        user = user_list[10]
        user['name'] = 'the ministry of silly walks OF'
        PROVIDERS.identity_api.update_user(user['id'], user)

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
        self.assertEqual(user_list[7]['id'], r.result.get('users')[0]['id'])

        url_by_name = '/users?name__iendswith=OF'
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(2, len(r.result.get('users')))
        self.assertEqual(user_list[7]['id'], r.result.get('users')[0]['id'])
        self.assertEqual(user_list[10]['id'], r.result.get('users')[1]['id'])

        self._delete_test_data('user', user_list)

    def test_filter_sql_injection_attack(self):
        """GET /users?name=<injected sql_statement>.

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
        group = unit.new_group_ref(domain_id=self.domainB['id'])
        group = PROVIDERS.identity_api.create_group(group)

        url_by_name = "/users?name=x'; drop table group"
        r = self.get(url_by_name, auth=self.auth)

        # Check group table is still there...
        url_by_name = "/groups"
        r = self.get(url_by_name, auth=self.auth)
        self.assertGreater(len(r.result.get('groups')), 0)


class IdentityPasswordExpiryFilteredTestCase(filtering.FilterTests,
                                             test_v3.RestfulTestCase):
    """Test password expiring filter on the v3 Identity API."""

    def setUp(self):
        """Setup for Identity Filter Test Cases."""
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        super(IdentityPasswordExpiryFilteredTestCase, self).setUp()

    def load_sample_data(self):
        """Create sample data for password expiry tests.

        The test environment will consist of a single domain, containing
        a single project. It will create three users and one group.
        Each user is going to be given a role assignment on the project
        and the domain. Two of the three users are going to be placed into
        the group, which won't have any role assignments to either the
        project or the domain.

        """
        self._populate_default_domain()
        self.domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domain['id'], self.domain)
        self.domain_id = self.domain['id']
        self.project = unit.new_project_ref(domain_id=self.domain_id)
        self.project_id = self.project['id']
        self.project = PROVIDERS.resource_api.create_project(
            self.project_id, self.project
        )
        self.group = unit.new_group_ref(domain_id=self.domain_id)
        self.group = PROVIDERS.identity_api.create_group(self.group)
        self.group_id = self.group['id']
        # Creates three users each with password expiration offset
        # by one day, starting with the current time frozen.
        self.starttime = datetime.datetime.utcnow()
        with freezegun.freeze_time(self.starttime):
            self.config_fixture.config(group='security_compliance',
                                       password_expires_days=1)
            self.user = unit.create_user(PROVIDERS.identity_api,
                                         domain_id=self.domain_id)
            self.config_fixture.config(group='security_compliance',
                                       password_expires_days=2)
            self.user2 = unit.create_user(PROVIDERS.identity_api,
                                          domain_id=self.domain_id)
            self.config_fixture.config(group='security_compliance',
                                       password_expires_days=3)
            self.user3 = unit.create_user(PROVIDERS.identity_api,
                                          domain_id=self.domain_id)
        self.role = unit.new_role_ref(name='admin')
        PROVIDERS.role_api.create_role(self.role['id'], self.role)
        self.role_id = self.role['id']
        # Grant admin role to the users created.
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user['id'], domain_id=self.domain_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user2['id'], domain_id=self.domain_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user3['id'], domain_id=self.domain_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user['id'], project_id=self.project_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user2['id'], project_id=self.project_id
        )
        PROVIDERS.assignment_api.create_grant(
            self.role_id, user_id=self.user3['id'], project_id=self.project_id
        )
        # Add the last two users to the group.
        PROVIDERS.identity_api.add_user_to_group(
            self.user2['id'], self.group_id
        )
        PROVIDERS.identity_api.add_user_to_group(
            self.user3['id'], self.group_id
        )

    def _list_users_by_password_expires_at(self, time, operator=None):
        """Call `list_users` with `password_expires_at` filter.

        GET /users?password_expires_at={operator}:{timestamp}

        """
        url = '/users?password_expires_at='
        if operator:
            url += operator + ':'
        url += str(time)
        return url

    def _list_users_by_multiple_password_expires_at(
            self, first_time, first_operator, second_time, second_operator):
        """Call `list_users` with two `password_expires_at` filters.

        GET /users?password_expires_at={operator}:{timestamp}&
        {operator}:{timestamp}

        """
        url = ('/users?password_expires_at=%s:%s&password_expires_at=%s:%s' %
               (first_operator, first_time, second_operator, second_time))
        return url

    def _format_timestamp(self, timestamp):
        return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_list_users_by_password_expires_at(self):
        """Ensure users can be filtered on no operator, eq and neq.

        GET /users?password_expires_at={timestamp}
        GET /users?password_expires_at=eq:{timestamp}

        """
        expire_at_url = self._list_users_by_password_expires_at(
            self._format_timestamp(
                self.starttime + datetime.timedelta(days=2)))
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        # Same call as above, only explicitly stating equals
        expire_at_url = self._list_users_by_password_expires_at(
            self._format_timestamp(
                self.starttime + datetime.timedelta(days=2)), 'eq')
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        expire_at_url = self._list_users_by_password_expires_at(
            self._format_timestamp(
                self.starttime + datetime.timedelta(days=2)), 'neq')
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user['id'], resp_users[0]['id'])
        self.assertEqual(self.user3['id'], resp_users[1]['id'])

    def test_list_users_by_password_expires_before(self):
        """Ensure users can be filtered on lt and lte.

        GET /users?password_expires_at=lt:{timestamp}
        GET /users?password_expires_at=lte:{timestamp}

        """
        expire_before_url = self._list_users_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2, seconds=1)), 'lt')
        resp_users = self.get(expire_before_url).result.get('users')
        self.assertEqual(self.user['id'], resp_users[0]['id'])
        self.assertEqual(self.user2['id'], resp_users[1]['id'])

        expire_before_url = self._list_users_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'lte')
        resp_users = self.get(expire_before_url).result.get('users')
        self.assertEqual(self.user['id'], resp_users[0]['id'])
        self.assertEqual(self.user2['id'], resp_users[1]['id'])

    def test_list_users_by_password_expires_after(self):
        """Ensure users can be filtered on gt and gte.

        GET /users?password_expires_at=gt:{timestamp}
        GET /users?password_expires_at=gte:{timestamp}

        """
        expire_after_url = self._list_users_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2, seconds=1)), 'gt')
        resp_users = self.get(expire_after_url).result.get('users')
        self.assertEqual(self.user3['id'], resp_users[0]['id'])

        expire_after_url = self._list_users_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'gte')
        resp_users = self.get(expire_after_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])
        self.assertEqual(self.user3['id'], resp_users[1]['id'])

    def test_list_users_by_password_expires_interval(self):
        """Ensure users can be filtered on time intervals.

        GET /users?password_expires_at=lt:{timestamp}&gt:{timestamp}
        GET /users?password_expires_at=lte:{timestamp}&gte:{timestamp}

        Time intervals are defined by using lt or lte and gt or gte,
        where the lt/lte time is greater than the gt/gte time.

        """
        expire_interval_url = (
            self._list_users_by_multiple_password_expires_at(
                self._format_timestamp(self.starttime + datetime.timedelta(
                    days=3)), 'lt', self._format_timestamp(
                        self.starttime + datetime.timedelta(days=1)), 'gt'))
        resp_users = self.get(expire_interval_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        expire_interval_url = (
            self._list_users_by_multiple_password_expires_at(
                self._format_timestamp(self.starttime + datetime.timedelta(
                    days=2)), 'gte', self._format_timestamp(
                        self.starttime + datetime.timedelta(
                            days=2, seconds=1)), 'lte'))
        resp_users = self.get(expire_interval_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

    def test_list_users_by_password_expires_with_bad_operator_fails(self):
        """Ensure an invalid operator returns a Bad Request.

        GET /users?password_expires_at={invalid_operator}:{timestamp}
        GET /users?password_expires_at={operator}:{timestamp}&
        {invalid_operator}:{timestamp}

        """
        bad_op_url = self._list_users_by_password_expires_at(
            self._format_timestamp(self.starttime), 'x')
        self.get(bad_op_url, expected_status=http.client.BAD_REQUEST)

        bad_op_url = self._list_users_by_multiple_password_expires_at(
            self._format_timestamp(self.starttime), 'lt',
            self._format_timestamp(self.starttime), 'x')
        self.get(bad_op_url, expected_status=http.client.BAD_REQUEST)

    def test_list_users_by_password_expires_with_bad_timestamp_fails(self):
        """Ensure an invalid timestamp returns a Bad Request.

        GET /users?password_expires_at={invalid_timestamp}
        GET /users?password_expires_at={operator}:{timestamp}&
        {operator}:{invalid_timestamp}

        """
        bad_ts_url = self._list_users_by_password_expires_at(
            self.starttime.strftime('%S:%M:%ST%Y-%m-%d'))
        self.get(bad_ts_url, expected_status=http.client.BAD_REQUEST)

        bad_ts_url = self._list_users_by_multiple_password_expires_at(
            self._format_timestamp(self.starttime), 'lt',
            self.starttime.strftime('%S:%M:%ST%Y-%m-%d'), 'gt')
        self.get(bad_ts_url, expected_status=http.client.BAD_REQUEST)

    def _list_users_in_group_by_password_expires_at(
            self, time, operator=None, expected_status=http.client.OK):
        """Call `list_users_in_group` with `password_expires_at` filter.

        GET /groups/{group_id}/users?password_expires_at=
        {operator}:{timestamp}&{operator}:{timestamp}

        """
        url = '/groups/' + self.group_id + '/users?password_expires_at='
        if operator:
            url += operator + ':'
        url += str(time)
        return url

    def _list_users_in_group_by_multiple_password_expires_at(
            self, first_time, first_operator, second_time, second_operator,
            expected_status=http.client.OK):
        """Call `list_users_in_group` with two `password_expires_at` filters.

        GET /groups/{group_id}/users?password_expires_at=
        {operator}:{timestamp}&{operator}:{timestamp}

        """
        url = ('/groups/' + self.group_id + '/users'
               '?password_expires_at=%s:%s&password_expires_at=%s:%s' %
               (first_operator, first_time, second_operator, second_time))
        return url

    def test_list_users_in_group_by_password_expires_at(self):
        """Ensure users in a group can be filtered on no operator, eq, and neq.

        GET /groups/{groupid}/users?password_expires_at={timestamp}
        GET /groups/{groupid}/users?password_expires_at=eq:{timestamp}

        """
        expire_at_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(
                self.starttime + datetime.timedelta(days=2)))
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        # Same call as above, only explicitly stating equals
        expire_at_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'eq')
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        expire_at_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'neq')
        resp_users = self.get(expire_at_url).result.get('users')
        self.assertEqual(self.user3['id'], resp_users[0]['id'])

    def test_list_users_in_group_by_password_expires_before(self):
        """Ensure users in a group can be filtered on with lt and lte.

        GET /groups/{groupid}/users?password_expires_at=lt:{timestamp}
        GET /groups/{groupid}/users?password_expires_at=lte:{timestamp}

        """
        expire_before_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2, seconds=1)), 'lt')
        resp_users = self.get(expire_before_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

        expire_before_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'lte')
        resp_users = self.get(expire_before_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])

    def test_list_users_in_group_by_password_expires_after(self):
        """Ensure users in a group can be filtered on with gt and gte.

        GET /groups/{groupid}/users?password_expires_at=gt:{timestamp}
        GET /groups/{groupid}/users?password_expires_at=gte:{timestamp}

        """
        expire_after_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2, seconds=1)), 'gt')
        resp_users = self.get(expire_after_url).result.get('users')
        self.assertEqual(self.user3['id'], resp_users[0]['id'])

        expire_after_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime + datetime.timedelta(
                days=2)), 'gte')
        resp_users = self.get(expire_after_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])
        self.assertEqual(self.user3['id'], resp_users[1]['id'])

    def test_list_users_in_group_by_password_expires_interval(self):
        """Ensure users in a group can be filtered on time intervals.

        GET /groups/{groupid}/users?password_expires_at=
        lt:{timestamp}&gt:{timestamp}
        GET /groups/{groupid}/users?password_expires_at=
        lte:{timestamp}&gte:{timestamp}

        Time intervals are defined by using lt or lte and gt or gte,
        where the lt/lte time is greater than the gt/gte time.

        """
        expire_interval_url = (
            self._list_users_in_group_by_multiple_password_expires_at(
                self._format_timestamp(self.starttime), 'gt',
                self._format_timestamp(self.starttime + datetime.timedelta(
                    days=3, seconds=1)), 'lt'))
        resp_users = self.get(expire_interval_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])
        self.assertEqual(self.user3['id'], resp_users[1]['id'])

        expire_interval_url = (
            self._list_users_in_group_by_multiple_password_expires_at(
                self._format_timestamp(self.starttime + datetime.timedelta(
                    days=2)), 'gte',
                self._format_timestamp(self.starttime + datetime.timedelta(
                    days=3)), 'lte'))
        resp_users = self.get(expire_interval_url).result.get('users')
        self.assertEqual(self.user2['id'], resp_users[0]['id'])
        self.assertEqual(self.user3['id'], resp_users[1]['id'])

    def test_list_users_in_group_by_password_expires_bad_operator_fails(self):
        """Ensure an invalid operator returns a Bad Request.

        GET /groups/{groupid}/users?password_expires_at=
        {invalid_operator}:{timestamp}
        GET /groups/{group_id}/users?password_expires_at=
        {operator}:{timestamp}&{invalid_operator}:{timestamp}

        """
        bad_op_url = self._list_users_in_group_by_password_expires_at(
            self._format_timestamp(self.starttime), 'bad')
        self.get(bad_op_url, expected_status=http.client.BAD_REQUEST)

        bad_op_url = self._list_users_in_group_by_multiple_password_expires_at(
            self._format_timestamp(self.starttime), 'lt',
            self._format_timestamp(self.starttime), 'x')
        self.get(bad_op_url, expected_status=http.client.BAD_REQUEST)

    def test_list_users_in_group_by_password_expires_bad_timestamp_fails(self):
        """Ensure and invalid timestamp returns a Bad Request.

        GET /groups/{groupid}/users?password_expires_at={invalid_timestamp}
        GET /groups/{groupid}/users?password_expires_at={operator}:{timestamp}&
        {operator}:{invalid_timestamp}

        """
        bad_ts_url = self._list_users_in_group_by_password_expires_at(
            self.starttime.strftime('%S:%M:%ST%Y-%m-%d'))
        self.get(bad_ts_url, expected_status=http.client.BAD_REQUEST)

        bad_ts_url = self._list_users_in_group_by_multiple_password_expires_at(
            self._format_timestamp(self.starttime), 'lt',
            self.starttime.strftime('%S:%M:%ST%Y-%m-%d'), 'gt')
        self.get(bad_ts_url, expected_status=http.client.BAD_REQUEST)


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
            new_entity = unit.new_service_ref()
            service = PROVIDERS.catalog_api.create_service(
                new_entity['id'], new_entity
            )
            self.service_list.append(service)

        self.policy_list = []
        self.addCleanup(self.clean_up_policy)
        for _ in range(10):
            new_entity = unit.new_policy_ref()
            policy = PROVIDERS.policy_api.create_policy(
                new_entity['id'], new_entity
            )
            self.policy_list.append(policy)

    def clean_up_entity(self, entity):
        """Clean up entity test data from Identity Limit Test Cases."""
        self._delete_test_data(entity, self.entity_lists[entity])

    def clean_up_service(self):
        """Clean up service test data from Identity Limit Test Cases."""
        for service in self.service_list:
            PROVIDERS.catalog_api.delete_service(service['id'])

    def clean_up_policy(self):
        """Clean up policy test data from Identity Limit Test Cases."""
        for policy in self.policy_list:
            PROVIDERS.policy_api.delete_policy(policy['id'])

    def _test_entity_list_limit(self, entity, driver):
        """GET /<entities> (limited).

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
        self.assertNotIn('truncated', r.result)

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
        self.assertNotIn('truncated', r.result)
