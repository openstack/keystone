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
from unittest import mock
import uuid

import fixtures
import freezegun
from oslo_db import exception as db_exception
from oslo_db import options
from oslo_log import log
import sqlalchemy
from sqlalchemy import exc
from testtools import matchers

from keystone.common import driver_hints
from keystone.common import provider_api
from keystone.common import sql
from keystone.common.sql import core
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
from keystone.tests.unit.limit import test_backends as limit_tests
from keystone.tests.unit.policy import test_backends as policy_tests
from keystone.tests.unit.resource import test_backends as resource_tests
from keystone.tests.unit.trust import test_backends as trust_tests
from keystone.trust.backends import sql as trust_sql


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


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


class DataTypeRoundTrips(SqlTests):
    def test_json_blob_roundtrip(self):
        """Test round-trip of a JSON data structure with JsonBlob."""
        with sql.session_for_read() as session:
            val = session.scalar(
                sqlalchemy.select(
                    [sqlalchemy.literal({"key": "value"}, type_=core.JsonBlob)]
                )
            )

        self.assertEqual({"key": "value"}, val)

    def test_json_blob_sql_null(self):
        """Test that JsonBlob can accommodate a SQL NULL value in a result set.

        SQL NULL may be handled by JsonBlob in the case where a table is
        storing NULL in a JsonBlob column, as several models use this type
        in a column that is nullable.   It also comes back when the column
        is left NULL from being in an OUTER JOIN.  In Python, this means
        the None constant is handled by the datatype.

        """
        with sql.session_for_read() as session:
            val = session.scalar(
                sqlalchemy.select(
                    [sqlalchemy.cast(sqlalchemy.null(), type_=core.JsonBlob)]
                )
            )

        self.assertIsNone(val)

    def test_json_blob_python_none(self):
        """Test that JsonBlob round-trips a Python None.

        This is where JSON datatypes get a little nutty, in that JSON has
        a 'null' keyword, and JsonBlob right now will persist Python None
        as the json string 'null', not SQL NULL.

        """
        with sql.session_for_read() as session:
            val = session.scalar(
                sqlalchemy.select(
                    [sqlalchemy.literal(None, type_=core.JsonBlob)]
                )
            )

        self.assertIsNone(val)

    def test_json_blob_python_none_renders(self):
        """Test that JsonBlob actually renders JSON 'null' for Python None."""
        with sql.session_for_read() as session:
            val = session.scalar(
                sqlalchemy.select(
                    [
                        sqlalchemy.cast(
                            sqlalchemy.literal(None, type_=core.JsonBlob),
                            sqlalchemy.String,
                        )
                    ]
                )
            )

        self.assertEqual("null", val)

    def test_datetimeint_roundtrip(self):
        """Test round-trip of a Python datetime with DateTimeInt."""
        with sql.session_for_read() as session:
            datetime_value = datetime.datetime(2019, 5, 15, 10, 17, 55)
            val = session.scalar(
                sqlalchemy.select(
                    [
                        sqlalchemy.literal(
                            datetime_value, type_=core.DateTimeInt
                        ),
                    ]
                )
            )

        self.assertEqual(datetime_value, val)

    def test_datetimeint_persistence(self):
        """Test integer persistence with DateTimeInt."""
        with sql.session_for_read() as session:
            datetime_value = datetime.datetime(2019, 5, 15, 10, 17, 55)
            val = session.scalar(
                sqlalchemy.select(
                    [
                        sqlalchemy.cast(
                            sqlalchemy.literal(
                                datetime_value, type_=core.DateTimeInt
                            ),
                            sqlalchemy.Integer
                        )
                    ]
                )
            )

        self.assertEqual(1557915475000000, val)

    def test_datetimeint_python_none(self):
        """Test round-trip of a Python None with DateTimeInt."""
        with sql.session_for_read() as session:
            val = session.scalar(
                sqlalchemy.select(
                    [
                        sqlalchemy.literal(None, type_=core.DateTimeInt),
                    ]
                )
            )

        self.assertIsNone(val)


class SqlModels(SqlTests):

    def load_table(self, name):
        table = sqlalchemy.Table(name,
                                 sql.ModelBase.metadata,
                                 autoload=True)
        return table

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
        table = self.load_table(table)

        actual_schema = []
        for column in table.c:
            if isinstance(column.type, sql.Boolean):
                default = None
                if column.default:
                    default = column.default.arg
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

        self.assertCountEqual(expected_schema, actual_schema)

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
                ('password_hash', sql.String, 255),
                ('created_at', sql.DateTime, None),
                ('expires_at', sql.DateTime, None),
                ('created_at_int', sql.DateTimeInt, None),
                ('expires_at_int', sql.DateTimeInt, None),
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

    def test_project_tags_model(self):
        cols = (('project_id', sql.String, 64),
                ('name', sql.Unicode, 255))
        self.assertExpectedSchema('project_tag', cols)


class SqlIdentity(SqlTests,
                  identity_tests.IdentityTests,
                  assignment_tests.AssignmentTests,
                  assignment_tests.SystemAssignmentTests,
                  resource_tests.ResourceTests):
    def test_password_hashed(self):
        with sql.session_for_read() as session:
            user_ref = PROVIDERS.identity_api._get_user(
                session, self.user_foo['id']
            )
            self.assertNotEqual(self.user_foo['password'],
                                user_ref['password'])

    def test_create_user_with_null_password(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        user_dict["password"] = None
        new_user_dict = PROVIDERS.identity_api.create_user(user_dict)
        with sql.session_for_read() as session:
            new_user_ref = PROVIDERS.identity_api._get_user(
                session, new_user_dict['id']
            )
            self.assertIsNone(new_user_ref.password)

    def test_update_user_with_null_password(self):
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        self.assertTrue(user_dict['password'])
        new_user_dict = PROVIDERS.identity_api.create_user(user_dict)
        new_user_dict["password"] = None
        new_user_dict = PROVIDERS.identity_api.update_user(
            new_user_dict['id'], new_user_dict
        )
        with sql.session_for_read() as session:
            new_user_ref = PROVIDERS.identity_api._get_user(
                session, new_user_dict['id']
            )
            self.assertIsNone(new_user_ref.password)

    def test_delete_user_with_project_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'], self.project_bar['id'], role_member['id']
        )
        PROVIDERS.identity_api.delete_user(user['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.assignment_api.list_projects_for_user,
                          user['id'])

    def test_create_user_case_sensitivity(self):
        # user name case sensitivity is down to the fact that it is marked as
        # an SQL UNIQUE column, which may not be valid for other backends, like
        # LDAP.

        # create a ref with a lowercase name
        ref = unit.new_user_ref(name=uuid.uuid4().hex.lower(),
                                domain_id=CONF.identity.default_domain_id)
        ref = PROVIDERS.identity_api.create_user(ref)

        # assign a new ID with the same name, but this time in uppercase
        ref['name'] = ref['name'].upper()
        PROVIDERS.identity_api.create_user(ref)

    def test_create_project_case_sensitivity(self):
        # project name case sensitivity is down to the fact that it is marked
        # as an SQL UNIQUE column, which may not be valid for other backends,
        # like LDAP.

        # create a ref with a lowercase name
        ref = unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(ref['id'], ref)

        # assign a new ID with the same name, but this time in uppercase
        ref['id'] = uuid.uuid4().hex
        ref['name'] = ref['name'].upper()
        PROVIDERS.resource_api.create_project(ref['id'], ref)

    def test_delete_project_with_user_association(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)
        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user['id'], self.project_bar['id'], role_member['id']
        )
        PROVIDERS.resource_api.delete_project(self.project_bar['id'])
        projects = PROVIDERS.assignment_api.list_projects_for_user(user['id'])
        self.assertEqual([], projects)

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
        ref = PROVIDERS.resource_api.create_project(project['id'], project)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertNotIn('extra', ref)

        ref['name'] = uuid.uuid4().hex
        ref = PROVIDERS.resource_api.update_project(ref['id'], ref)
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
        ref = PROVIDERS.identity_api.create_user(user)
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertNotIn('password', ref)
        self.assertNotIn('extra', ref)

        user['name'] = uuid.uuid4().hex
        user['password'] = uuid.uuid4().hex
        ref = PROVIDERS.identity_api.update_user(ref['id'], user)
        self.assertNotIn('password', ref)
        self.assertNotIn('password', ref['extra'])
        self.assertEqual(arbitrary_value, ref[arbitrary_key])
        self.assertEqual(arbitrary_value, ref['extra'][arbitrary_key])

    def test_sql_user_to_dict_null_default_project_id(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = PROVIDERS.identity_api.create_user(user)
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
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.new_user_ref(domain_id=domain['id'])

        test_domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(test_domain1['id'], test_domain1)
        test_domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(test_domain2['id'], test_domain2)

        user = PROVIDERS.identity_api.create_user(user)
        user_domains = PROVIDERS.assignment_api.list_domains_for_user(
            user['id']
        )
        self.assertEqual(0, len(user_domains))
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], domain_id=test_domain1['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], domain_id=test_domain2['id'],
            role_id=self.role_member['id']
        )
        user_domains = PROVIDERS.assignment_api.list_domains_for_user(
            user['id']
        )
        self.assertThat(user_domains, matchers.HasLength(2))

    def test_list_domains_for_user_with_grants(self):
        # Create two groups each with a role on a different domain, and
        # make user1 a member of both groups.  Both these new domains
        # should now be included, along with any direct user grants.
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        user = unit.new_user_ref(domain_id=domain['id'])
        user = PROVIDERS.identity_api.create_user(user)
        group1 = unit.new_group_ref(domain_id=domain['id'])
        group1 = PROVIDERS.identity_api.create_group(group1)
        group2 = unit.new_group_ref(domain_id=domain['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)

        test_domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(test_domain1['id'], test_domain1)
        test_domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(test_domain2['id'], test_domain2)
        test_domain3 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(test_domain3['id'], test_domain3)

        PROVIDERS.identity_api.add_user_to_group(user['id'], group1['id'])
        PROVIDERS.identity_api.add_user_to_group(user['id'], group2['id'])

        # Create 3 grants, one user grant, the other two as group grants
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], domain_id=test_domain1['id'],
            role_id=self.role_member['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group1['id'], domain_id=test_domain2['id'],
            role_id=self.role_admin['id']
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group2['id'], domain_id=test_domain3['id'],
            role_id=self.role_admin['id']
        )
        user_domains = PROVIDERS.assignment_api.list_domains_for_user(
            user['id']
        )
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
        domain1 = PROVIDERS.resource_api.create_domain(domain1['id'], domain1)
        domain2 = unit.new_domain_ref()
        domain2 = PROVIDERS.resource_api.create_domain(domain2['id'], domain2)
        user = unit.new_user_ref(domain_id=domain1['id'])
        user = PROVIDERS.identity_api.create_user(user)
        group = unit.new_group_ref(domain_id=domain1['id'])
        group = PROVIDERS.identity_api.create_group(group)
        PROVIDERS.identity_api.add_user_to_group(user['id'], group['id'])
        role = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role['id'], role)

        # Create a grant on each domain, one user grant, one group grant,
        # both inherited.
        PROVIDERS.assignment_api.create_grant(
            user_id=user['id'], domain_id=domain1['id'], role_id=role['id'],
            inherited_to_projects=True
        )
        PROVIDERS.assignment_api.create_grant(
            group_id=group['id'], domain_id=domain2['id'], role_id=role['id'],
            inherited_to_projects=True
        )

        user_domains = PROVIDERS.assignment_api.list_domains_for_user(
            user['id']
        )
        # No domains should be returned since both domains have only inherited
        # roles assignments.
        self.assertThat(user_domains, matchers.HasLength(0))

    def test_list_groups_for_user(self):
        domain = self._get_domain_fixture()
        test_groups = []
        test_users = []
        GROUP_COUNT = 3
        USER_COUNT = 2

        for x in range(0, USER_COUNT):
            new_user = unit.new_user_ref(domain_id=domain['id'])
            new_user = PROVIDERS.identity_api.create_user(new_user)
            test_users.append(new_user)
        positive_user = test_users[0]
        negative_user = test_users[1]

        for x in range(0, USER_COUNT):
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                test_users[x]['id'])
            self.assertEqual(0, len(group_refs))

        for x in range(0, GROUP_COUNT):
            before_count = x
            after_count = x + 1
            new_group = unit.new_group_ref(domain_id=domain['id'])
            new_group = PROVIDERS.identity_api.create_group(new_group)
            test_groups.append(new_group)

            # add the user to the group and ensure that the
            # group count increases by one for each
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            PROVIDERS.identity_api.add_user_to_group(
                positive_user['id'],
                new_group['id'])
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))

            # Make sure the group count for the unrelated user did not change
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

        # remove the user from each group and ensure that
        # the group count reduces by one for each
        for x in range(0, 3):
            before_count = GROUP_COUNT - x
            after_count = GROUP_COUNT - x - 1
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(before_count, len(group_refs))
            PROVIDERS.identity_api.remove_user_from_group(
                positive_user['id'],
                test_groups[x]['id'])
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                positive_user['id'])
            self.assertEqual(after_count, len(group_refs))
            # Make sure the group count for the unrelated user
            # did not change
            group_refs = PROVIDERS.identity_api.list_groups_for_user(
                negative_user['id'])
            self.assertEqual(0, len(group_refs))

    def test_add_user_to_group_expiring_mapped(self):
        self._build_fed_resource()
        domain = self._get_domain_fixture()
        self.config_fixture.config(group='federation',
                                   default_authorization_ttl=5)
        time = datetime.datetime.utcnow()
        tick = datetime.timedelta(minutes=5)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)

        fed_dict = unit.new_federated_user_ref()
        fed_dict['idp_id'] = 'myidp'
        fed_dict['protocol_id'] = 'mapped'

        with freezegun.freeze_time(time - tick) as frozen_time:
            user = PROVIDERS.identity_api.shadow_federated_user(
                **fed_dict, group_ids=[new_group['id']])

            PROVIDERS.identity_api.check_user_in_group(user['id'],
                                                       new_group['id'])

            # Expiration
            frozen_time.tick(tick)
            self.assertRaises(exception.NotFound,
                              PROVIDERS.identity_api.check_user_in_group,
                              user['id'],
                              new_group['id'])

            # Renewal
            PROVIDERS.identity_api.shadow_federated_user(
                **fed_dict, group_ids=[new_group['id']])
            PROVIDERS.identity_api.check_user_in_group(user['id'],
                                                       new_group['id'])

    def test_add_user_to_group_expiring(self):
        self._build_fed_resource()
        domain = self._get_domain_fixture()
        time = datetime.datetime.utcnow()
        tick = datetime.timedelta(minutes=5)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)

        fed_dict = unit.new_federated_user_ref()
        fed_dict['idp_id'] = 'myidp'
        fed_dict['protocol_id'] = 'mapped'
        new_user = PROVIDERS.shadow_users_api.create_federated_user(
            domain['id'], fed_dict
        )

        with freezegun.freeze_time(time - tick) as frozen_time:
            PROVIDERS.shadow_users_api.add_user_to_group_expires(
                new_user['id'], new_group['id'])

            self.config_fixture.config(group='federation',
                                       default_authorization_ttl=0)
            self.assertRaises(exception.NotFound,
                              PROVIDERS.identity_api.check_user_in_group,
                              new_user['id'],
                              new_group['id'])

            self.config_fixture.config(group='federation',
                                       default_authorization_ttl=5)
            PROVIDERS.identity_api.check_user_in_group(new_user['id'],
                                                       new_group['id'])

            # Expiration
            frozen_time.tick(tick)
            self.assertRaises(exception.NotFound,
                              PROVIDERS.identity_api.check_user_in_group,
                              new_user['id'],
                              new_group['id'])

            # Renewal
            PROVIDERS.shadow_users_api.add_user_to_group_expires(
                new_user['id'], new_group['id'])
            PROVIDERS.identity_api.check_user_in_group(new_user['id'],
                                                       new_group['id'])

    def test_add_user_to_group_expiring_list(self):
        self._build_fed_resource()
        domain = self._get_domain_fixture()
        self.config_fixture.config(group='federation',
                                   default_authorization_ttl=5)
        time = datetime.datetime.utcnow()
        tick = datetime.timedelta(minutes=5)

        new_group = unit.new_group_ref(domain_id=domain['id'])
        new_group = PROVIDERS.identity_api.create_group(new_group)
        exp_new_group = unit.new_group_ref(domain_id=domain['id'])
        exp_new_group = PROVIDERS.identity_api.create_group(exp_new_group)

        fed_dict = unit.new_federated_user_ref()
        fed_dict['idp_id'] = 'myidp'
        fed_dict['protocol_id'] = 'mapped'
        new_user = PROVIDERS.shadow_users_api.create_federated_user(
            domain['id'], fed_dict
        )

        PROVIDERS.identity_api.add_user_to_group(new_user['id'],
                                                 new_group['id'])
        PROVIDERS.identity_api.check_user_in_group(new_user['id'],
                                                   new_group['id'])

        with freezegun.freeze_time(time - tick) as frozen_time:
            PROVIDERS.shadow_users_api.add_user_to_group_expires(
                new_user['id'], exp_new_group['id'])
            PROVIDERS.identity_api.check_user_in_group(new_user['id'],
                                                       new_group['id'])

            groups = PROVIDERS.identity_api.list_groups_for_user(
                new_user['id'])
            self.assertEqual(len(groups), 2)
            for group in groups:
                if group.get('membership_expires_at'):
                    self.assertEqual(group['membership_expires_at'], time)

            frozen_time.tick(tick)
            groups = PROVIDERS.identity_api.list_groups_for_user(
                new_user['id'])
            self.assertEqual(len(groups), 1)

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
        PROVIDERS.resource_api.create_project(
            spoiler_project['id'], spoiler_project
        )

        # First let's create a project with a None domain_id and make sure we
        # can read it back.
        project = unit.new_project_ref(domain_id=None, is_domain=True)
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, ref)

        # Can we get it by name?
        ref = PROVIDERS.resource_api.get_project_by_name(project['name'], None)
        self.assertDictEqual(project, ref)

        # Can we filter for them - create a second domain to ensure we are
        # testing the receipt of more than one.
        project2 = unit.new_project_ref(domain_id=None, is_domain=True)
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )
        hints = driver_hints.Hints()
        hints.add_filter('domain_id', None)
        refs = PROVIDERS.resource_api.list_projects(hints)
        self.assertThat(refs, matchers.HasLength(2 + self.domain_count))
        self.assertIn(project, refs)
        self.assertIn(project2, refs)

        # Can we update it?
        project['name'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_project(project['id'], project)
        ref = PROVIDERS.resource_api.get_project(project['id'])
        self.assertDictEqual(project, ref)

        # Finally, make sure we can delete it
        project['enabled'] = False
        PROVIDERS.resource_api.update_project(project['id'], project)
        PROVIDERS.resource_api.delete_project(project['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project['id'])

    def test_hidden_project_domain_root_is_really_hidden(self):
        """Ensure we cannot access the hidden root of all project domains.

        Calling any of the driver methods should result in the same as
        would be returned if we passed a project that does not exist. We don't
        test create_project, since we do not allow a caller of our API to
        specify their own ID for a new entity.

        """
        def _exercise_project_api(ref_id):
            driver = PROVIDERS.resource_api.driver
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
            # should be silent. The root domain <<keystone.domain.root>> can't
            # be deleted.
            if ref_id != resource.NULL_DOMAIN_ID:
                driver.delete_projects_from_ids([ref_id])

        _exercise_project_api(uuid.uuid4().hex)
        _exercise_project_api(resource.NULL_DOMAIN_ID)

    def test_list_users_call_count(self):
        """There should not be O(N) queries."""
        # create 10 users. 10 is just a random number
        for i in range(10):
            user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
            PROVIDERS.identity_api.create_user(user)

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

        first_call_users = PROVIDERS.identity_api.list_users()
        first_call_counter = counter.calls
        # add 10 more users
        for i in range(10):
            user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
            PROVIDERS.identity_api.create_user(user)
        counter.reset()
        second_call_users = PROVIDERS.identity_api.list_users()
        # ensure that the number of calls does not depend on the number of
        # users fetched.
        self.assertNotEqual(len(first_call_users), len(second_call_users))
        self.assertEqual(first_call_counter, counter.calls)
        self.assertEqual(3, counter.calls)

    def test_check_project_depth(self):
        # Create a 3 level project tree:
        #
        # default_domain
        #       |
        #   project_1
        #       |
        #   project_2
        project_1 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id)
        PROVIDERS.resource_api.create_project(project_1['id'], project_1)
        project_2 = unit.new_project_ref(
            domain_id=CONF.identity.default_domain_id,
            parent_id=project_1['id'])
        PROVIDERS.resource_api.create_project(project_2['id'], project_2)

        # if max_depth is None or >= current project depth, return nothing.
        resp = PROVIDERS.resource_api.check_project_depth(max_depth=None)
        self.assertIsNone(resp)
        resp = PROVIDERS.resource_api.check_project_depth(max_depth=3)
        self.assertIsNone(resp)
        resp = PROVIDERS.resource_api.check_project_depth(max_depth=4)
        self.assertIsNone(resp)
        # if max_depth < current project depth, raise LimitTreeExceedError
        self.assertRaises(exception.LimitTreeExceedError,
                          PROVIDERS.resource_api.check_project_depth,
                          2)

    def test_update_user_with_stale_data_forces_retry(self):
        # Capture log output so we know oslo.db attempted a retry
        log_fixture = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        # Create a new user
        user_dict = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id)
        new_user_dict = PROVIDERS.identity_api.create_user(user_dict)

        side_effects = [
            # Raise a StaleDataError simulating that another client has
            # updated the user's password while this client's request was
            # being processed
            sqlalchemy.orm.exc.StaleDataError,
            # The oslo.db library will retry the request, so the second
            # time this method is called let's return a valid session
            # object
            sql.session_for_write()
        ]
        with mock.patch('keystone.common.sql.session_for_write') as m:
            m.side_effect = side_effects

            # Update a user's attribute, the first attempt will fail but
            # oslo.db will handle the exception and retry, the second attempt
            # will succeed
            new_user_dict['email'] = uuid.uuid4().hex
            PROVIDERS.identity_api.update_user(
                new_user_dict['id'], new_user_dict)

        # Make sure oslo.db retried the update by checking the log output
        expected_log_message = (
            'Performing DB retry for function keystone.identity.backends.'
            'sql.Identity.update_user'
        )
        self.assertIn(expected_log_message, log_fixture.output)


class SqlTrust(SqlTests, trust_tests.TrustTests):

    def test_trust_expires_at_int_matches_expires_at(self):
        with sql.session_for_write() as session:
            new_id = uuid.uuid4().hex
            self.create_sample_trust(new_id)
            trust_ref = session.query(trust_sql.TrustModel).get(new_id)
            self.assertIsNotNone(trust_ref._expires_at)
            self.assertEqual(trust_ref._expires_at, trust_ref.expires_at_int)
            self.assertEqual(trust_ref.expires_at, trust_ref.expires_at_int)


class SqlCatalog(SqlTests, catalog_tests.CatalogTests):

    _legacy_endpoint_id_in_endpoint = True
    _enabled_default_to_true_when_creating_endpoint = True

    def test_get_v3_catalog_project_non_exist(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        malformed_url = "http://192.168.1.104:8774/v2/$(project)s"
        endpoint = unit.new_endpoint_ref(service_id=service['id'],
                                         url=malformed_url,
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.catalog_api.get_v3_catalog,
                          'fake-user',
                          'fake-project')

    def test_get_v3_catalog_with_empty_public_url(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(url='', service_id=service['id'],
                                         region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint.copy())

        catalog = PROVIDERS.catalog_api.get_v3_catalog(self.user_foo['id'],
                                                       self.project_bar['id'])
        catalog_endpoint = catalog[0]
        self.assertEqual(service['name'], catalog_endpoint['name'])
        self.assertEqual(service['id'], catalog_endpoint['id'])
        self.assertEqual([], catalog_endpoint['endpoints'])

    def test_create_endpoint_region_returns_not_found(self):
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        endpoint = unit.new_endpoint_ref(region_id=uuid.uuid4().hex,
                                         service_id=service['id'])

        self.assertRaises(exception.ValidationError,
                          PROVIDERS.catalog_api.create_endpoint,
                          endpoint['id'],
                          endpoint.copy())

    def test_create_region_invalid_id(self):
        region = unit.new_region_ref(id='0' * 256)

        self.assertRaises(exception.StringLengthExceeded,
                          PROVIDERS.catalog_api.create_region,
                          region)

    def test_create_region_invalid_parent_id(self):
        region = unit.new_region_ref(parent_region_id='0' * 256)

        self.assertRaises(exception.RegionNotFound,
                          PROVIDERS.catalog_api.create_region,
                          region)

    def test_delete_region_with_endpoint(self):
        # create a region
        region = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region)

        # create a child region
        child_region = unit.new_region_ref(parent_region_id=region['id'])
        PROVIDERS.catalog_api.create_region(child_region)
        # create a service
        service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service['id'], service)

        # create an endpoint attached to the service and child region
        child_endpoint = unit.new_endpoint_ref(region_id=child_region['id'],
                                               service_id=service['id'])

        PROVIDERS.catalog_api.create_endpoint(
            child_endpoint['id'], child_endpoint
        )
        self.assertRaises(exception.RegionDeletionError,
                          PROVIDERS.catalog_api.delete_region,
                          child_region['id'])

        # create an endpoint attached to the service and parent region
        endpoint = unit.new_endpoint_ref(region_id=region['id'],
                                         service_id=service['id'])

        PROVIDERS.catalog_api.create_endpoint(endpoint['id'], endpoint)
        self.assertRaises(exception.RegionDeletionError,
                          PROVIDERS.catalog_api.delete_region,
                          region['id'])

    def test_v3_catalog_domain_scoped_token(self):
        # test the case that project_id is None.
        srv_1 = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)

        srv_2 = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(srv_2['id'], srv_2)
        endpoint_2 = unit.new_endpoint_ref(service_id=srv_2['id'],
                                           region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint_2['id'], endpoint_2)

        self.config_fixture.config(group='endpoint_filter',
                                   return_all_endpoints_if_no_filter=True)
        catalog_ref = PROVIDERS.catalog_api.get_v3_catalog(
            uuid.uuid4().hex, None
        )
        self.assertThat(catalog_ref, matchers.HasLength(2))
        self.config_fixture.config(group='endpoint_filter',
                                   return_all_endpoints_if_no_filter=False)
        catalog_ref = PROVIDERS.catalog_api.get_v3_catalog(
            uuid.uuid4().hex, None
        )
        self.assertThat(catalog_ref, matchers.HasLength(0))

    def test_v3_catalog_endpoint_filter_enabled(self):
        srv_1 = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)
        endpoint_2 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint_2['id'], endpoint_2)
        # create endpoint-project association.
        PROVIDERS.catalog_api.add_endpoint_to_project(
            endpoint_1['id'],
            self.project_bar['id'])

        catalog_ref = PROVIDERS.catalog_api.get_v3_catalog(
            uuid.uuid4().hex, self.project_bar['id']
        )
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
        PROVIDERS.catalog_api.create_service(srv_1['id'], srv_1)
        endpoint_1 = unit.new_endpoint_ref(service_id=srv_1['id'],
                                           region_id=None)
        PROVIDERS.catalog_api.create_endpoint(endpoint_1['id'], endpoint_1)

        srv_2 = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(srv_2['id'], srv_2)

        catalog_ref = PROVIDERS.catalog_api.get_v3_catalog(
            uuid.uuid4().hex, self.project_bar['id']
        )
        self.assertThat(catalog_ref, matchers.HasLength(2))
        srv_id_list = [catalog_ref[0]['id'], catalog_ref[1]['id']]
        self.assertCountEqual([srv_1['id'], srv_2['id']], srv_id_list)


class SqlPolicy(SqlTests, policy_tests.PolicyTests):
    pass


class SqlInheritance(SqlTests, assignment_tests.InheritanceTests):
    pass


class SqlImpliedRoles(SqlTests, assignment_tests.ImpliedRoleTests):
    pass


class SqlFilterTests(SqlTests, identity_tests.FilterTests):

    def clean_up_entities(self):
        """Clean up entity test data from Filter Test Cases."""
        for entity in ['user', 'group', 'project']:
            self._delete_test_data(entity, self.entity_list[entity])
            self._delete_test_data(entity, self.domain1_entity_list[entity])
        del self.entity_list
        del self.domain1_entity_list
        self.domain1['enabled'] = False
        PROVIDERS.resource_api.update_domain(self.domain1['id'], self.domain1)
        PROVIDERS.resource_api.delete_domain(self.domain1['id'])
        del self.domain1

    def test_list_entities_filtered_by_domain(self):
        # NOTE(henry-nash): This method is here rather than in
        # unit.identity.test_backends since any domain filtering with LDAP is
        # handled by the manager layer (and is already tested elsewhere) not at
        # the driver level.
        self.addCleanup(self.clean_up_entities)
        self.domain1 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(self.domain1['id'], self.domain1)

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
        users = PROVIDERS.identity_api.list_users()
        self.assertGreater(len(users), 0)

        hints = driver_hints.Hints()
        hints.add_filter('name', "anything' or 'x'='x")
        users = PROVIDERS.identity_api.list_users(hints=hints)
        self.assertEqual(0, len(users))

        # See if we can add a SQL command...use the group table instead of the
        # user table since 'user' is reserved word for SQLAlchemy.
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        hints = driver_hints.Hints()
        hints.add_filter('name', "x'; drop table group")
        groups = PROVIDERS.identity_api.list_groups(hints=hints)
        self.assertEqual(0, len(groups))

        groups = PROVIDERS.identity_api.list_groups()
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
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )
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
        credentials = PROVIDERS.credential_api.list_credentials()
        self._validateCredentialList(credentials, self.credentials)
        # test filtering using hints
        hints = driver_hints.Hints()
        hints.add_filter('user_id', self.user_foo['id'])
        credentials = PROVIDERS.credential_api.list_credentials(hints)
        self._validateCredentialList(credentials, self.user_credentials)

    def test_list_credentials_for_user(self):
        credentials = PROVIDERS.credential_api.list_credentials_for_user(
            self.user_foo['id'])
        self._validateCredentialList(credentials, self.user_credentials)

    def test_list_credentials_for_user_and_type(self):
        cred = self.user_credentials[0]
        credentials = PROVIDERS.credential_api.list_credentials_for_user(
            self.user_foo['id'], type=cred['type'])
        self._validateCredentialList(credentials, [cred])

    def test_create_credential_is_encrypted_when_stored(self):
        credential = unit.new_credential_ref(user_id=uuid.uuid4().hex)
        credential_id = credential['id']
        returned_credential = PROVIDERS.credential_api.create_credential(
            credential_id,
            credential
        )

        # Make sure the `blob` is *not* encrypted when returned from the
        # credential API.
        self.assertEqual(returned_credential['blob'], credential['blob'])

        credential_from_backend = (
            PROVIDERS.credential_api.driver.get_credential(credential_id)
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

        created_credential = PROVIDERS.credential_api.create_credential(
            credential_id,
            credential
        )

        # Pull the credential directly from the backend, the `blob` should be
        # encrypted.
        credential_from_backend = (
            PROVIDERS.credential_api.driver.get_credential(credential_id)
        )
        self.assertNotEqual(
            credential_from_backend['encrypted_blob'],
            credential['blob']
        )

        # Make sure the `blob` values listed from the API are not encrypted.
        listed_credentials = PROVIDERS.credential_api.list_credentials()
        self.assertIn(created_credential, listed_credentials)


class SqlRegisteredLimit(SqlTests, limit_tests.RegisteredLimitTests):

    def setUp(self):
        super(SqlRegisteredLimit, self).setUp()

        fixtures_to_cleanup = []
        for service in default_fixtures.SERVICES:
            service_id = service['id']
            rv = PROVIDERS.catalog_api.create_service(service_id, service)
            attrname = service['extra']['name']
            setattr(self, attrname, rv)
            fixtures_to_cleanup.append(attrname)
        for region in default_fixtures.REGIONS:
            rv = PROVIDERS.catalog_api.create_region(region)
            attrname = region['id']
            setattr(self, attrname, rv)
            fixtures_to_cleanup.append(attrname)
        self.addCleanup(self.cleanup_instance(*fixtures_to_cleanup))


class SqlLimit(SqlTests, limit_tests.LimitTests):

    def setUp(self):
        super(SqlLimit, self).setUp()

        fixtures_to_cleanup = []
        for service in default_fixtures.SERVICES:
            service_id = service['id']
            rv = PROVIDERS.catalog_api.create_service(service_id, service)
            attrname = service['extra']['name']
            setattr(self, attrname, rv)
            fixtures_to_cleanup.append(attrname)
        for region in default_fixtures.REGIONS:
            rv = PROVIDERS.catalog_api.create_region(region)
            attrname = region['id']
            setattr(self, attrname, rv)
            fixtures_to_cleanup.append(attrname)
        self.addCleanup(self.cleanup_instance(*fixtures_to_cleanup))

        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_3 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='backup', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2, registered_limit_3])
