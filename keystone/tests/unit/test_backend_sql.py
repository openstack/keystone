# Copyright 2012 OpenStack Foundation
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
import functools
import uuid

import freezegun
import mock
from oslo_db import exception as db_exception
from oslo_db import options
from six.moves import range
import sqlalchemy
from sqlalchemy import exc
from testtools import matchers

from keystone.common import driver_hints
from keystone.common import sql
import keystone.conf
from keystone.credential.providers import fernet as credential_provider
from keystone import exception
from keystone.identity.backends import sql_model as identity_sql
from keystone.resource.backends import base as resource
from keystone.tests import unit
from keystone.tests.unit.assignment import test_backends as assignment_tests
from keystone.tests.unit.catalog import test_backends as catalog_tests
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.identity import test_backends as identity_tests
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit.policy import test_backends as policy_tests
from keystone.tests.unit.resource import test_backends as resource_tests
from keystone.tests.unit.token import test_backends as token_tests
from keystone.tests.unit.trust import test_backends as trust_tests
from keystone.token.persistence.backends import sql as token_sql


CONF = keystone.conf.CONF


class SqlTests(unit.SQLDriverOverrides, unit.TestCase):

    def setUp(self):
        super(SqlTests, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

        # populate the engine with tables & fixtures
        self.load_fixtures(default_fixtures)
        # defaulted by the data load
        self.user_foo['enabled'] = True

    def config_files(self):
        config_files = super(SqlTests, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files


class SqlModels(SqlTests):

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 sql.ModelBase.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertExpectedSchema(self, table, expected_schema):
        """Assert that a table's schema is what we expect.

        :param string table: the name of the table to inspect
        :param tuple expected_schema: a tuple of tuples containing the
            expected schema
        :raises AssertionError: when the database schema doesn't match the
            expected schema

        The expected_schema format is simply::

            (
                ('column name', sql type, qualifying detail),
                ...
            )

        The qualifying detail varies based on the type of the column::

          - sql.Boolean columns must indicate the column's default value or
            None if there is no default
          - Columns with a length, like sql.String, must indicate the
            column's length
          - All other column types should use None

        Example::

            cols = (('id', sql.String, 64),
                    ('enabled', sql.Boolean, True),
                    ('extra', sql.JsonBlob, None))
            self.assertExpectedSchema('table_name', cols)

        """
        table = self.select_table(table)

        actual_schema = []
        for column in table.c:
            if isinstance(column.type, sql.Boolean):
                default = None
                if column._proxies[0].default:
                    default = column._proxies[0].default.arg
                actual_schema.append((column.name, type(column.type), default))
            elif (hasattr(column.type, 'length') and
                    not isinstance(column.type, sql.Enum)):
                # NOTE(dstanek): Even though sql.Enum columns have a length
                # set we don't want to catch them here. Maybe in the future
                # we'll check to see that they contain a list of the correct
                # possible values.
                actual_schema.append((column.name,
                                      type(column.type),
                                      column.type.length))
            else:
                actual_schema.append((column.name, type(column.type), None))

        self.assertItemsEqual(expected_schema, actual_schema)

    def test_user_model(self):
        cols = (('id', sql.String, 64),
                ('domain_id', sql.String, 64),
                ('default_project_id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('extra', sql.JsonBlob, None),
                ('created_at', sql.DateTime, None),
                ('last_active_at', sqlalchemy.Date, None))
        self.assertExpectedSchema('user', cols)

    def test_local_user_model(self):
        cols = (('id', sql.Integer, None),
                ('user_id', sql.String, 64),
                ('name', sql.String, 255),
                ('domain_id', sql.String, 64),
                ('failed_auth_count', sql.Integer, None),
                ('failed_auth_at', sql.DateTime, None))
        self.assertExpectedSchema('local_user', cols)

    def test_password_model(self):
        cols = (('id', sql.Integer, None),
                ('local_user_id', sql.Integer, None),
                ('password', sql.String, 128),
                ('created_at', sql.DateTime, None),
                ('expires_at', sql.DateTime, None),
                ('self_service', sql.Boolean, False))
        self.assertExpectedSchema('password', cols)

    def test_federated_user_model(self):
        cols = (('id', sql.Integer, None),
                ('user_id', sql.String, 64),
                ('idp_id', sql.String, 64),
                ('protocol_id', sql.String, 64),
                ('unique_id', sql.String, 255),
                ('display_name', sql.String, 255))
        self.assertExpectedSchema('federated_user', cols)

    def test_nonlocal_user_model(self):
        cols = (('domain_id', sql.String, 64),
                ('name', sql.String, 255),
                ('user_id', sql.String, 64))
        self.assertExpectedSchema('nonlocal_user', cols)

    def test_group_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 64),
                ('description', sql.Text, None),
                ('domain_id', sql.String, 64),
                ('extra', sql.JsonBlob, None))
        self.assertExpectedSchema('group', cols)

    def test_project_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 64),
                ('description', sql.Text, None),
                ('domain_id', sql.String, 64),
                ('enabled', sql.Boolean, None),
                ('extra', sql.JsonBlob, None),
                ('parent_id', sql.String, 64),
                ('is_domain', sql.Boolean, False))
        self.assertExpectedSchema('project', cols)

    def test_role_assignment_model(self):
        cols = (('type', sql.Enum, None),
                ('actor_id', sql.String, 64),
                ('target_id', sql.String, 64),
                ('role_id', sql.String, 64),
                ('inherited', sql.Boolean, False))
        self.assertExpectedSchema('assignment', cols)

    def test_user_group_membership(self):
        cols = (('group_id', sql.String, 64),
                ('user_id', sql.String, 64))
        self.assertExpectedSchema('user_group_membership', cols)

    def test_revocation_event_model(self):
        cols = (('id', sql.Integer, None),
                ('domain_id', sql.String, 64),
                ('project_id', sql.String, 64),
                ('user_id', sql.String, 64),
                ('role_id', sql.String, 64),
                ('trust_id', sql.String, 64),
                ('consumer_id', sql.String, 64),
                ('access_token_id', sql.String, 64),
                ('issued_before', sql.DateTime, None),
                ('expires_at', sql.DateTime, None),
                ('revoked_at', sql.DateTime, None),
                ('audit_id', sql.String, 32),
                ('audit_chain_id', sql.String, 32))
        self.assertExpectedSchema('revocation_event', cols)


class SqlIdentity(SqlTests,
                  identity_tests.IdentityTests,
                  assignment_tests.AssignmentTests,
                  resource_tests.ResourceTests):
    def test_password_hashed(self):
        with sql.session_for_read() as session:
            user_ref = self.identity_api._get_user(session,
                                                   self.user_foo['id'])
            self.assertNotEqual(self.user_foo['password'],
                                user_ref['password'])

    def test_create_user_with_null_password(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        user_dict["password"] = None
        new_user_dict = self.identity_api.create_user(user_dict)
        with sql.session_for_read() as session:
            new_user_ref = self.identity_api._get_user(session,
                                                       new_user_dict['id'])
            self.assertIsNone(new_user_ref.password)

    def test_update_user_with_null_password(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.assertTrue(user_dict['password'])
        new_user_dict = self.identity_api.create_user(user_dict)
        new_user_dict["password"] = None
        new_user_dict = self.identity_api.update_user(new_user_dict['id'],
                                                      new_user_dict)
        with sql.session_for_read() as session:
            new_user_ref = self.identity_api._get_user(session,
                                                       new_user_dict['id'])
            self.assertIsNone(new_user_ref.password)

    def test_delete_user_with_project_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user['id'])
        self.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          self.assignment_api.list_projects_for_user,
                          user['id'])

    def test_create_null_user_name(self):
        user = unit.new_user_ref(name=None,
                                 domain_id=CONF.identity.default_domain_id)
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          user)
        self.assertRaises(exception.UserNotFound,
                          self.identity_api.get_user_by_name,
                          user['name'],
                          CONF.identity.default_domain_id)

    def test_create_user_case_sensitivity(self):
        # user name case sensitivity is down to the fact that it is marked as
        # an SQL UNIQUE column, which may not be valid for other backends, like
        # LDAP.

        # create a ref with a lowercase name
        ref = unit.new_user_ref(name=uuid.uuid4().hex.lower(),
                                domain_id=CONF.identity.default_domain_id)
        ref = self.identity_api.create_user(ref)

        # assign a new ID with the same name, but this time in uppercase
        ref['name'] = ref['name'].upper()
        self.identity_api.create_user(ref)

    def test_create_project_case_sensitivity(self):
        # project name case sensitivity is down to the fact that it is marked
        # as an SQL UNIQUE column, which may not be valid for other backends,
        # like LDAP.

        # create a ref with a lowercase name
        ref = unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(ref['id'], ref)

        # assign a new ID with the same name, but this time in uppercase
        ref['id'] = uuid.uuid4().hex
        ref['name'] = ref['name'].upper()
        self.resource_api.create_project(ref['id'], ref)

    def test_delete_project_with_user_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_bar['id'],
                                                user['id'])
        self.resource_api.delete_project(self.tenant_bar['id'])
        tenants = self.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual([], tenants)

    def test_update_project_returns_extra(self):
        """Test for backward compatibility with an essex/folsom bug.

        Non-indexed attributes were returned in an 'extra' attribute, instead
        of on the entity itself; for consistency and backwards compatibility,
        those attributes should be included twice.

        This behavior is specific to the SQL driver.

        """
        arbitrary_key = uuid.uuid4().hex
        arbitrary_value = uuid.uuid4().hex
        project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        project[arbitrary_key] = arbitrary_value
        ref = self.resource_api.create_project(project['id'], project)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('extra'))

        ref['name'] = uuid.uuid4().hex
        ref = self.resource_api.update_project(ref['id'], ref)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertEqual(arbitrary_value, ref['extra'][arbitrary_key])

    def test_update_user_returns_extra(self):
        """Test for backwards-compatibility with an essex/folsom bug.

        Non-indexed attributes were returned in an 'extra' attribute, instead
        of on the entity itself; for consistency and backwards compatibility,
        those attributes should be included twice.

        This behavior is specific to the SQL driver.

        """
        arbitrary_key = uuid.uuid4().hex
        arbitrary_value = uuid.uuid4().hex
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user[arbitrary_key] = arbitrary_value
        del user["id"]
        ref = self.identity_api.create_user(user)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertIsNone(ref.get('password'))
        self.assertIsNone(ref.get('extra'))

        user['name'] = uuid.uuid4().hex
        user['password'] = uuid.uuid4().hex
        ref = self.identity_api.update_user(ref['id'], user)
        self.assertIsNone(ref.get('password'))
        self.assertIsNone(ref['extra'].get('password'))
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertEqual(arbitrary_value, ref['extra'][arbitrary_key])

    def test_sql_user_to_dict_null_default_project_id(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        with sql.session_for_read() as session:
            query = session.query(identity_sql.User)
            query = query.filter_by(id=user['id'])
            raw_user_ref = query.one()
            self.assertIsNone(raw_user_ref.default_project_id)
            user_ref = raw_user_ref.to_dict()
            self.assertNotIn('default_project_id', user_ref)
            session.close()

    def test_list_domains_for_user(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        user = unit.new_user_ref(domain_id=domain['id'])

        test_domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(test_domain1['id'], test_domain1)
        test_domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(test_domain2['id'], test_domain2)

        user = self.identity_api.create_user(user)
        user_domains = self.assignment_api.list_domains_for_user(user['id'])
        self.assertEqual(0, len(user_domains))
        self.assignment_api.create_grant(user_id=user['id'],
                                         domain_id=test_domain1['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(user_id=user['id'],
                                         domain_id=test_domain2['id'],
                                         role_id=self.role_member['id'])
        user_domains = self.assignment_api.list_domains_for_user(user['id'])
        self.assertThat(user_domains, matchers.HasLength(2))

    def test_list_domains_for_user_with_grants(self):
        # Create two groups each with a role on a different domain, and
        # make user1 a member of both groups.  Both these new domains
        # should now be included, along with any direct user grants.
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        user = unit.new_user_ref(domain_id=domain['id'])
        user = self.identity_api.create_user(user)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = self.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = self.identity_api.create_group(group2)

        test_domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(test_domain1['id'], test_domain1)
        test_domain2 = unit.new_domain_ref()
        self.resource_api.create_domain(test_domain2['id'], test_domain2)
        test_domain3 = unit.new_domain_ref()
        self.resource_api.create_domain(test_domain3['id'], test_domain3)

        self.identity_api.add_user_to_group(user['id'], group1['id'])
        self.identity_api.add_user_to_group(user['id'], group2['id'])

        # Create 3 grants, one user grant, the other two as group grants
        self.assignment_api.create_grant(user_id=user['id'],
                                         domain_id=test_domain1['id'],
                                         role_id=self.role_member['id'])
        self.assignment_api.create_grant(group_id=group1['id'],
                                         domain_id=test_domain2['id'],
                                         role_id=self.role_admin['id'])
        self.assignment_api.create_grant(group_id=group2['id'],
                                         domain_id=test_domain3['id'],
                                         role_id=self.role_admin['id'])
        user_domains = self.assignment_api.list_domains_for_user(user['id'])
        self.assertThat(user_domains, matchers.HasLength(3))

    def test_list_domains_for_user_with_inherited_grants(self):
        """Test that inherited roles on the domain are excluded.

        Test Plan:

        - Create two domains, one user, group and role
        - Domain1 is given an inherited user role, Domain2 an inherited
          group role (for a group of which the user is a member)
        - When listing domains for user, neither domain should be returned

        """
        domain1 = unit.new_domain_ref()
        domain1 = self.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        domain2 = self.resource_api.create_domain(domain2['id'], domain2)
        user = unit.new_user_ref(domain_id=domain1['id'])
        user = self.identity_api.create_user(user)
        group = unit.new_group_ref(domain_id=domain1['id'])
        group = self.identity_api.create_group(group)
        self.identity_api.add_user_to_group(user['id'], group['id'])
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)

        # Create a grant on each domain, one user grant, one group grant,
        # both inherited.
        self.assignment_api.create_grant(user_id=user['id'],
                                         domain_id=domain1['id'],
                                         role_id=role['id'],
                                         inherited_to_projects=True)
        self.assignment_api.create_grant(group_id=group['id'],
                                         domain_id=domain2['id'],
                                         role_id=role['id'],
                                         inherited_to_projects=True)

        user_domains = self.assignment_api.list_domains_for_user(user['id'])
        # No domains should be returned since both domains have only inherited
        # roles assignments.
        self.assertThat(user_domains, matchers.HasLength(0))

    def test_storing_null_domain_id_in_project_ref(self):
        """Test the special storage of domain_id=None in sql resource driver.

        The resource driver uses a special value in place of None for domain_id
        in the project record. This shouldn't escape the driver. Hence we test
        the interface to ensure that you can store a domain_id of None, and
        that any special value used inside the driver does not escape through
        the interface.

        """
        spoiler_project = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        self.resource_api.create_project(spoiler_project['id'],
                                         spoiler_project)

        # First let's create a project with a None domain_id and make sure we
        # can read it back.
        project = unit.new_project_ref(domain_id=None, is_domain=True)
        project = self.resource_api.create_project(project['id'], project)
        ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project, ref)

        # Can we get it by name?
        ref = self.resource_api.get_project_by_name(project['name'], None)
        self.assertDictEqual(project, ref)

        # Can we filter for them - create a second domain to ensure we are
        # testing the receipt of more than one.
        project2 = unit.new_project_ref(domain_id=None, is_domain=True)
        project2 = self.resource_api.create_project(project2['id'], project2)
        hints = driver_hints.Hints()
        hints.add_filter('domain_id', None)
        refs = self.resource_api.list_projects(hints)
        self.assertThat(refs, matchers.HasLength(2 + self.domain_count))
        self.assertIn(project, refs)
        self.assertIn(project2, refs)

        # Can we update it?
        project['name'] = uuid.uuid4().hex
        self.resource_api.update_project(project['id'], project)
        ref = self.resource_api.get_project(project['id'])
        self.assertDictEqual(project, ref)

        # Finally, make sure we can delete it
        project['enabled'] = False
        self.resource_api.update_project(project['id'], project)
        self.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          self.resource_api.get_project,
                          project['id'])

    def test_hidden_project_domain_root_is_really_hidden(self):
        """Ensure we cannot access the hidden root of all project domains.

        Calling any of the driver methods should result in the same as
        would be returned if we passed a project that does not exist. We don't
        test create_project, since we do not allow a caller of our API to
        specify their own ID for a new entity.

        """
        def _exercise_project_api(ref_id):
            driver = self.resource_api.driver
            self.assertRaises(exception.ProjectNotFound,
                              driver.get_project,
                              ref_id)

            self.assertRaises(exception.ProjectNotFound,
                              driver.get_project_by_name,
                              resource.NULL_DOMAIN_ID,
                              ref_id)

            project_ids = [x['id'] for x in
                           driver.list_projects(driver_hints.Hints())]
            self.assertNotIn(ref_id, project_ids)

            projects = driver.list_projects_from_ids([ref_id])
            self.assertThat(projects, matchers.HasLength(0))

            project_ids = [x for x in
                           driver.list_project_ids_from_domain_ids([ref_id])]
            self.assertNotIn(ref_id, project_ids)

            self.assertRaises(exception.DomainNotFound,
                              driver.list_projects_in_domain,
                              ref_id)

            project_ids = [
                x['id'] for x in
                driver.list_projects_acting_as_domain(driver_hints.Hints())]
            self.assertNotIn(ref_id, project_ids)

            projects = driver.list_projects_in_subtree(ref_id)
            self.assertThat(projects, matchers.HasLength(0))

            self.assertRaises(exception.ProjectNotFound,
                              driver.list_project_parents,
                              ref_id)

            # A non-existing project just returns True from the driver
            self.assertTrue(driver.is_leaf_project(ref_id))

            self.assertRaises(exception.ProjectNotFound,
                              driver.update_project,
                              ref_id,
                              {})

            self.assertRaises(exception.ProjectNotFound,
                              driver.delete_project,
                              ref_id)

            # Deleting list of projects that includes a non-existing project
            # should be silent
            driver.delete_projects_from_ids([ref_id])

        _exercise_project_api(uuid.uuid4().hex)
        _exercise_project_api(resource.NULL_DOMAIN_ID)

    def test_list_users_call_count(self):
        """There should not be O(N) queries."""
        # create 10 users. 10 is just a random number
        for i in range(10):
            user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
            self.identity_api.create_user(user)

        # sqlalchemy emits various events and allows to listen to them. Here
        # bound method `query_counter` will be called each time when a query
        # is compiled
        class CallCounter(object):
            def __init__(self):
                self.calls = 0

            def reset(self):
                self.calls = 0

            def query_counter(self, query):
                self.calls += 1

        counter = CallCounter()
        sqlalchemy.event.listen(sqlalchemy.orm.query.Query, 'before_compile',
                                counter.query_counter)

        first_call_users = self.identity_api.list_users()
        first_call_counter = counter.calls
        # add 10 more users
        for i in range(10):
            user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
            self.identity_api.create_user(user)
        counter.reset()
        second_call_users = self.identity_api.list_users()
        # ensure that the number of calls does not depend on the number of
        # users fetched.
        self.assertNotEqual(len(first_call_users), len(second_call_users))
        self.assertEqual(first_call_counter, counter.calls)


class SqlTrust(SqlTests, trust_tests.TrustTests):
    pass


class SqlToken(SqlTests, token_tests.TokenTests):
    def test_token_revocation_list_uses_right_columns(self):
        # This query used to be heavy with too many columns. We want
        # to make sure it is only running with the minimum columns
        # necessary.

        expected_query_args = (token_sql.TokenModel.id,
                               token_sql.TokenModel.expires,
                               token_sql.TokenModel.extra,)

        with mock.patch.object(token_sql, 'sql') as mock_sql:
            tok = token_sql.Token()
            tok.list_revoked_tokens()

        mock_query = mock_sql.session_for_read().__enter__().query
        mock_query.assert_called_with(*expected_query_args)

    def test_flush_expired_tokens_batch(self):
        # TODO(dstanek): This test should be rewritten to be less
        # brittle. The code will likely need to be changed first. I
        # just copied the spirit of the existing test when I rewrote
        # mox -> mock. These tests are brittle because they have the
        # call structure for SQLAlchemy encoded in them.

        # test sqlite dialect
        with mock.patch.object(token_sql, 'sql') as mock_sql:
            mock_sql.get_session().bind.dialect.name = 'sqlite'
            tok = token_sql.Token()
            tok.flush_expired_tokens()

        filter_mock = mock_sql.get_session().query().filter()
        self.assertFalse(filter_mock.limit.called)
        self.assertTrue(filter_mock.delete.called_once)

    def test_flush_expired_tokens_batch_mysql(self):
        # test mysql dialect, we don't need to test IBM DB SA separately, since
        # other tests below test the differences between how they use the batch
        # strategy
        with mock.patch.object(token_sql, 'sql') as mock_sql:
            mock_sql.session_for_write().__enter__(
            ).query().filter().delete.return_value = 0

            mock_sql.session_for_write().__enter__(
            ).bind.dialect.name = 'mysql'

            tok = token_sql.Token()
            expiry_mock = mock.Mock()
            ITERS = [1, 2, 3]
            expiry_mock.return_value = iter(ITERS)
            token_sql._expiry_range_batched = expiry_mock
            tok.flush_expired_tokens()

            # The expiry strategy is only invoked once, the other calls are via
            # the yield return.
            self.assertEqual(1, expiry_mock.call_count)

            mock_delete = mock_sql.session_for_write().__enter__(
            ).query().filter().delete

            self.assertThat(mock_delete.call_args_list,
                            matchers.HasLength(len(ITERS)))

    def test_expiry_range_batched(self):
        upper_bound_mock = mock.Mock(side_effect=[1, "final value"])
        sess_mock = mock.Mock()
        query_mock = sess_mock.query().filter().order_by().offset().limit()
        query_mock.one.side_effect = [['test'], sql.NotFound()]
        for i, x in enumerate(token_sql._expiry_range_batched(sess_mock,
                                                              upper_bound_mock,
                                                              batch_size=50)):
            if i == 0:
                # The first time the batch iterator returns, it should return
                # the first result that comes back from the database.
                self.assertEqual('test', x)
            elif i == 1:
                # The second time, the database range function should return
                # nothing, so the batch iterator returns the result of the
                # upper_bound function
                self.assertEqual("final value", x)
            else:
                self.fail("range batch function returned more than twice")

    def test_expiry_range_strategy_sqlite(self):
        tok = token_sql.Token()
        sqlite_strategy = tok._expiry_range_strategy('sqlite')
        self.assertEqual(token_sql._expiry_range_all, sqlite_strategy)

    def test_expiry_range_strategy_ibm_db_sa(self):
        tok = token_sql.Token()
        db2_strategy = tok._expiry_range_strategy('ibm_db_sa')
        self.assertIsInstance(db2_strategy, functools.partial)
        self.assertEqual(token_sql._expiry_range_batched, db2_strategy.func)
        self.assertEqual({'batch_size': 100}, db2_strategy.keywords)

    def test_expiry_range_strategy_mysql(self):
        tok = token_sql.Token()
        mysql_strategy = tok._expiry_range_strategy('mysql')
        self.assertIsInstance(mysql_strategy, functools.partial)
        self.assertEqual(token_sql._expiry_range_batched, mysql_strategy.func)
        self.assertEqual({'batch_size': 1000}, mysql_strategy.keywords)

    def test_expiry_range_with_allow_expired(self):
        window_secs = 200
        self.config_fixture.config(group='token',
                                   allow_expired_window=window_secs)

        tok = token_sql.Token()
        time = datetime.datetime.utcnow()

        with freezegun.freeze_time(time):
            # unknown strategy just ensures we are getting the dumbest strategy
            # that will remove everything in one go
            strategy = tok._expiry_range_strategy('unkown')
            upper_bound_func = token_sql._expiry_upper_bound_func

            # session is ignored for dumb strategy
            expiry_times = list(strategy(session=None,
                                         upper_bound_func=upper_bound_func))

            # basically just ensure that we are removing things in the past
            delta = datetime.timedelta(seconds=window_secs)
            previous_time = datetime.datetime.utcnow() - delta

        self.assertEqual([previous_time], expiry_times)


class SqlCatalog(SqlTests, catalog_tests.CatalogTests):

    _legacy_endpoint_id_in_endpoint = True
    _enabled_default_to_true_when_creating_endpoint = True

    def test_catalog_ignored_malformed_urls(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        malformed_url = "http://192.168.1.104:8774/v2/$(tenant)s"
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         url=malformed_url,
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

        # NOTE(dstanek): there are no valid URLs, so nothing is in the catalog
        catalog = self.catalog_api.get_catalog('fake-user', 'fake-tenant')
        self.assertEqual({}, catalog)

    def test_get_catalog_with_empty_public_url(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(url='', service_id=service['id'],
                                         region_id=None)
        self.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

        catalog = self.catalog_api.get_catalog('user', 'tenant')
        catalog_endpoint = catalog[endpoint['region_id']][service['type']]
        self.assertEqual(service['name'], catalog_endpoint['name'])
        self.assertEqual(endpoint['id'], catalog_endpoint['id'])
        self.assertEqual('', catalog_endpoint['publicURL'])
        self.assertIsNone(catalog_endpoint.get('adminURL'))
        self.assertIsNone(catalog_endpoint.get('internalURL'))

    def test_create_endpoint_region_returns_not_found(self):
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(region_id=uuid.uuid4().hex,
                                         service_id=service['id'])

        self.assertRaises(exception.ValidationError,
                          self.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint.copy())

    def test_create_region_invalid_id(self):
        region = unit.new_region_ref(id='0' * 256)

        self.assertRaises(exception.StringLengthExceeded,
                          self.catalog_api.create_region,
                          region)

    def test_create_region_invalid_parent_id(self):
        region = unit.new_region_ref(parent_region_id='0' * 256)

        self.assertRaises(exception.RegionNotFound,
                          self.catalog_api.create_region,
                          region)

    def test_delete_region_with_endpoint(self):
        # create a region
        region = unit.new_region_ref()
        self.catalog_api.create_region(region)

        # create a child region
        child_region = unit.new_region_ref(parent_region_id=region['id'])
        self.catalog_api.create_region(child_region)
        # create a service
        service = unit.new_service_ref()
        self.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service and child region
        child_endpoint = unit.new_endpoint_ref(region_id=child_region['id'],
                                               service_id=service['id'])

        self.catalog_api.create_endpoint(child_endpoint['id'], child_endpoint)
        self.assertRaises(exception.RegionDeletionError,
                          self.catalog_api.delete_region,
                          child_region['id'])

        # create an endpoint attached to the service and parent region
        endpoint = unit.new_endpoint_ref(region_id=region['id'],
                                         service_id=service['id'])

        self.catalog_api.create_endpoint(endpoint['id'], endpoint)
        self.assertRaises(exception.RegionDeletionError,
                          self.catalog_api.delete_region,
                          region['id'])

    def test_v3_catalog_domain_scoped_token(self):
        # test the case that tenant_id is None.
        srv_1 = unit.new_service_ref()
        self.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        self.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)

        srv_2 = unit.new_service_ref()
        self.catalog_api.create_service(srv_2['id'], srv_2)
        endpoint_2 = unit.new_endpoint_ref(service_id=srv_2['id'],
                                           region_id=None)
        self.catalog_api.create_endpoint(endpoint_2['id'], endpoint_2)

        self.config_fixture.config(group='endpoint_filter',
                                   return_all_endpoints_if_no_filter=True)
        catalog_ref = self.catalog_api.get_v3_catalog(uuid.uuid4().hex, None)
        self.assertThat(catalog_ref, matchers.HasLength(2))
        self.config_fixture.config(group='endpoint_filter',
                                   return_all_endpoints_if_no_filter=False)
        catalog_ref = self.catalog_api.get_v3_catalog(uuid.uuid4().hex, None)
        self.assertThat(catalog_ref, matchers.HasLength(0))

    def test_v3_catalog_endpoint_filter_enabled(self):
        srv_1 = unit.new_service_ref()
        self.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        self.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)
        endpoint_2 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        self.catalog_api.create_endpoint(endpoint_2['id'], endpoint_2)
        # create endpoint-project association.
        self.catalog_api.add_endpoint_to_project(
            endpoint_1['id'],
            self.tenant_bar['id'])

        catalog_ref = self.catalog_api.get_v3_catalog(uuid.uuid4().hex,
                                                      self.tenant_bar['id'])
        self.assertThat(catalog_ref, matchers.HasLength(1))
        self.assertThat(catalog_ref[0]['endpoints'], matchers.HasLength(1))
        # the endpoint is that defined in the endpoint-project association.
        self.assertEqual(endpoint_1['id'],
                         catalog_ref[0]['endpoints'][0]['id'])

    def test_v3_catalog_endpoint_filter_disabled(self):
        # there is no endpoint-project association defined.
        self.config_fixture.config(group='endpoint_filter',
                                   return_all_endpoints_if_no_filter=True)
        srv_1 = unit.new_service_ref()
        self.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        self.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)

        srv_2 = unit.new_service_ref()
        self.catalog_api.create_service(srv_2['id'], srv_2)

        catalog_ref = self.catalog_api.get_v3_catalog(uuid.uuid4().hex,
                                                      self.tenant_bar['id'])
        self.assertThat(catalog_ref, matchers.HasLength(2))
        srv_id_list = [catalog_ref[0]['id'], catalog_ref[1]['id']]
        self.assertItemsEqual([srv_1['id'], srv_2['id']], srv_id_list)


class SqlPolicy(SqlTests, policy_tests.PolicyTests):
    pass


class SqlInheritance(SqlTests, assignment_tests.InheritanceTests):
    pass


class SqlImpliedRoles(SqlTests, assignment_tests.ImpliedRoleTests):
    pass


class SqlTokenCacheInvalidationWithUUID(SqlTests,
                                        token_tests.TokenCacheInvalidation):
    def setUp(self):
        super(SqlTokenCacheInvalidationWithUUID, self).setUp()
        self._create_test_data()

    def config_overrides(self):
        super(SqlTokenCacheInvalidationWithUUID, self).config_overrides()
        # NOTE(lbragstad): The TokenCacheInvalidation tests are coded to work
        # against a persistent token backend. Only run these with token
        # providers that issue persistent tokens.
        self.config_fixture.config(group='token', provider='uuid')


# NOTE(lbragstad): The Fernet token provider doesn't persist tokens in a
# backend, so running the TokenCacheInvalidation tests here doesn't make sense.


class SqlFilterTests(SqlTests, identity_tests.FilterTests):

    def clean_up_entities(self):
        """Clean up entity test data from Filter Test Cases."""
        for entity in ['user', 'group', 'project']:
            self._delete_test_data(entity, self.entity_list[entity])
            self._delete_test_data(entity, self.domain1_entity_list[entity])
        del self.entity_list
        del self.domain1_entity_list
        self.domain1['enabled'] = False
        self.resource_api.update_domain(self.domain1['id'], self.domain1)
        self.resource_api.delete_domain(self.domain1['id'])
        del self.domain1

    def test_list_entities_filtered_by_domain(self):
        # NOTE(henry-nash): This method is here rather than in
        # unit.identity.test_backends since any domain filtering with LDAP is
        # handled by the manager layer (and is already tested elsewhere) not at
        # the driver level.
        self.addCleanup(self.clean_up_entities)
        self.domain1 = unit.new_domain_ref()
        self.resource_api.create_domain(self.domain1['id'], self.domain1)

        self.entity_list = {}
        self.domain1_entity_list = {}
        for entity in ['user', 'group', 'project']:
            # Create 5 entities, 3 of which are in domain1
            DOMAIN1_ENTITIES = 3
            self.entity_list[entity] = self._create_test_data(entity, 2)
            self.domain1_entity_list[entity] = self._create_test_data(
                entity, DOMAIN1_ENTITIES, self.domain1['id'])

            # Should get back the DOMAIN1_ENTITIES in domain1
            hints = driver_hints.Hints()
            hints.add_filter('domain_id', self.domain1['id'])
            entities = self._list_entities(entity)(hints=hints)
            self.assertEqual(DOMAIN1_ENTITIES, len(entities))
            self._match_with_list(entities, self.domain1_entity_list[entity])
            # Check the driver has removed the filter from the list hints
            self.assertFalse(hints.get_exact_filter_by_name('domain_id'))

    def test_filter_sql_injection_attack(self):
        """Test against sql injection attack on filters.

        Test Plan:
        - Attempt to get all entities back by passing a two-term attribute
        - Attempt to piggyback filter to damage DB (e.g. drop table)

        """
        # Check we have some users
        users = self.identity_api.list_users()
        self.assertGreater(len(users), 0)

        hints = driver_hints.Hints()
        hints.add_filter('name', "anything' or 'x'='x")
        users = self.identity_api.list_users(hints=hints)
        self.assertEqual(0, len(users))

        # See if we can add a SQL command...use the group table instead of the
        # user table since 'user' is reserved word for SQLAlchemy.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)

        hints = driver_hints.Hints()
        hints.add_filter('name', "x'; drop table group")
        groups = self.identity_api.list_groups(hints=hints)
        self.assertEqual(0, len(groups))

        groups = self.identity_api.list_groups()
        self.assertGreater(len(groups), 0)


class SqlLimitTests(SqlTests, identity_tests.LimitTests):
    def setUp(self):
        super(SqlLimitTests, self).setUp()
        identity_tests.LimitTests.setUp(self)


class FakeTable(sql.ModelBase):
    __tablename__ = 'test_table'
    col = sql.Column(sql.String(32), primary_key=True)

    @sql.handle_conflicts('keystone')
    def insert(self):
        raise db_exception.DBDuplicateEntry

    @sql.handle_conflicts('keystone')
    def update(self):
        raise db_exception.DBError(
            inner_exception=exc.IntegrityError('a', 'a', 'a'))

    @sql.handle_conflicts('keystone')
    def lookup(self):
        raise KeyError


class SqlDecorators(unit.TestCase):

    def test_initialization_fail(self):
        self.assertRaises(exception.StringLengthExceeded,
                          FakeTable, col='a' * 64)

    def test_initialization(self):
        tt = FakeTable(col='a')
        self.assertEqual('a', tt.col)

    def test_conflict_happend(self):
        self.assertRaises(exception.Conflict, FakeTable().insert)
        self.assertRaises(exception.UnexpectedError, FakeTable().update)

    def test_not_conflict_error(self):
        self.assertRaises(KeyError, FakeTable().lookup)


class SqlModuleInitialization(unit.TestCase):

    @mock.patch.object(sql.core, 'CONF')
    @mock.patch.object(options, 'set_defaults')
    def test_initialize_module(self, set_defaults, CONF):
        sql.initialize()
        set_defaults.assert_called_with(CONF,
                                        connection='sqlite:///keystone.db')


class SqlCredential(SqlTests):

    def _create_credential_with_user_id(self, user_id=uuid.uuid4().hex):
        credential = unit.new_credential_ref(user_id=user_id,
                                             extra=uuid.uuid4().hex,
                                             type=uuid.uuid4().hex)
        self.credential_api.create_credential(credential['id'], credential)
        return credential

    def _validateCredentialList(self, retrieved_credentials,
                                expected_credentials):
        self.assertEqual(len(expected_credentials), len(retrieved_credentials))
        retrived_ids = [c['id'] for c in retrieved_credentials]
        for cred in expected_credentials:
            self.assertIn(cred['id'], retrived_ids)

    def setUp(self):
        self.useFixture(database.Database())
        super(SqlCredential, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_provider.MAX_ACTIVE_KEYS
            )
        )

        self.credentials = []
        for _ in range(3):
            self.credentials.append(
                self._create_credential_with_user_id())
        self.user_credentials = []
        for _ in range(3):
            cred = self._create_credential_with_user_id(self.user_foo['id'])
            self.user_credentials.append(cred)
            self.credentials.append(cred)

    def test_list_credentials(self):
        credentials = self.credential_api.list_credentials()
        self._validateCredentialList(credentials, self.credentials)
        # test filtering using hints
        hints = driver_hints.Hints()
        hints.add_filter('user_id', self.user_foo['id'])
        credentials = self.credential_api.list_credentials(hints)
        self._validateCredentialList(credentials, self.user_credentials)

    def test_list_credentials_for_user(self):
        credentials = self.credential_api.list_credentials_for_user(
            self.user_foo['id'])
        self._validateCredentialList(credentials, self.user_credentials)

    def test_list_credentials_for_user_and_type(self):
        cred = self.user_credentials[0]
        credentials = self.credential_api.list_credentials_for_user(
            self.user_foo['id'], type=cred['type'])
        self._validateCredentialList(credentials, [cred])

    def test_create_credential_is_encrypted_when_stored(self):
        credential = unit.new_credential_ref(user_id=uuid.uuid4().hex)
        credential_id = credential['id']
        returned_credential = self.credential_api.create_credential(
            credential_id,
            credential
        )

        # Make sure the `blob` is *not* encrypted when returned from the
        # credential API.
        self.assertEqual(returned_credential['blob'], credential['blob'])

        credential_from_backend = self.credential_api.driver.get_credential(
            credential_id
        )

        # Pull the credential directly from the backend, the `blob` should be
        # encrypted.
        self.assertNotEqual(
            credential_from_backend['encrypted_blob'],
            credential['blob']
        )

    def test_list_credentials_is_decrypted(self):
        credential = unit.new_credential_ref(user_id=uuid.uuid4().hex)
        credential_id = credential['id']

        created_credential = self.credential_api.create_credential(
            credential_id,
            credential
        )

        # Pull the credential directly from the backend, the `blob` should be
        # encrypted.
        credential_from_backend = self.credential_api.driver.get_credential(
            credential_id
        )
        self.assertNotEqual(
            credential_from_backend['encrypted_blob'],
            credential['blob']
        )

        # Make sure the `blob` values listed from the API are not encrypted.
        listed_credentials = self.credential_api.list_credentials()
        self.assertIn(created_credential, listed_credentials)
