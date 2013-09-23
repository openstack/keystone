# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
"""
To run these tests against a live database:
1. Modify the file `keystone/tests/backend_sql.conf` to use the connection for
   your live database
2. Set up a blank, live database.
3. run the tests using
    ./run_tests.sh -N  test_sql_upgrade
    WARNING::
        Your database will be wiped.
    Do not do this against a Database with valuable data as
    all data will be lost.
"""
import copy
import json
import uuid

from migrate.versioning import api as versioning_api
import sqlalchemy

from keystone.common import sql
from keystone.common.sql import migration
from keystone.common import utils
from keystone import config
from keystone import credential
from keystone import exception
from keystone import tests
from keystone.tests import default_fixtures


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class SqlMigrateBase(tests.TestCase):
    def initialize_sql(self):
        self.metadata = sqlalchemy.MetaData()
        self.metadata.bind = self.engine

    _config_file_list = [tests.etcdir('keystone.conf.sample'),
                         tests.testsdir('test_overrides.conf'),
                         tests.testsdir('backend_sql.conf')]

    #override this to specify the complete list of configuration files
    def config_files(self):
        return self._config_file_list

    def repo_package(self):
        return None

    def setUp(self):
        super(SqlMigrateBase, self).setUp()

        self.config(self.config_files())
        self.base = sql.Base()

        # create and share a single sqlalchemy engine for testing
        self.engine = self.base.get_engine(allow_global_engine=False)
        sql.core.set_global_engine(self.engine)
        self.Session = self.base.get_sessionmaker(engine=self.engine,
                                                  autocommit=False)

        self.initialize_sql()
        self.repo_path = migration.find_migrate_repo(self.repo_package())
        self.schema = versioning_api.ControlledSchema.create(
            self.engine,
            self.repo_path, 0)

        # auto-detect the highest available schema version in the migrate_repo
        self.max_version = self.schema.repository.version().version

    def tearDown(self):
        sqlalchemy.orm.session.Session.close_all()
        table = sqlalchemy.Table("migrate_version", self.metadata,
                                 autoload=True)
        self.downgrade(0)
        table.drop(self.engine, checkfirst=True)
        sql.core.set_global_engine(None)
        super(SqlMigrateBase, self).tearDown()

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertTableExists(self, table_name):
        try:
            self.select_table(table_name)
        except sqlalchemy.exc.NoSuchTableError:
            raise AssertionError('Table "%s" does not exist' % table_name)

    def assertTableDoesNotExist(self, table_name):
        """Asserts that a given table exists cannot be selected by name."""
        # Switch to a different metadata otherwise you might still
        # detect renamed or dropped tables
        try:
            temp_metadata = sqlalchemy.MetaData()
            temp_metadata.bind = self.engine
            sqlalchemy.Table(table_name, temp_metadata, autoload=True)
        except sqlalchemy.exc.NoSuchTableError:
            pass
        else:
            raise AssertionError('Table "%s" already exists' % table_name)

    def upgrade(self, *args, **kwargs):
        self._migrate(*args, **kwargs)

    def downgrade(self, *args, **kwargs):
        self._migrate(*args, downgrade=True, **kwargs)

    def _migrate(self, version, repository=None, downgrade=False,
                 current_schema=None):
        repository = repository or self.repo_path
        err = ''
        version = versioning_api._migrate_version(self.schema,
                                                  version,
                                                  not downgrade,
                                                  err)
        if not current_schema:
            current_schema = self.schema
        changeset = current_schema.changeset(version)
        for ver, change in changeset:
            self.schema.runchange(ver, change, changeset.step)
        self.assertEqual(self.schema.version, version)

    def assertTableColumns(self, table_name, expected_cols):
        """Asserts that the table contains the expected set of columns."""
        self.initialize_sql()
        table = self.select_table(table_name)
        actual_cols = [col.name for col in table.columns]
        self.assertEqual(expected_cols, actual_cols, '%s table' % table_name)


class SqlUpgradeTests(SqlMigrateBase):

    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_start_version_0(self):
        version = migration.db_version()
        self.assertEqual(version, 0, "DB is at version 0")

    def test_two_steps_forward_one_step_back(self):
        """You should be able to cleanly undo and re-apply all upgrades.

        Upgrades are run in the following order::

            0 -> 1 -> 0 -> 1 -> 2 -> 1 -> 2 -> 3 -> 2 -> 3 ...
                 ^---------^    ^---------^    ^---------^

        """
        for x in range(1, self.max_version + 1):
            self.upgrade(x)
            self.downgrade(x - 1)
            self.upgrade(x)

    def test_upgrade_add_initial_tables(self):
        self.upgrade(1)
        self.assertTableColumns("user", ["id", "name", "extra"])
        self.assertTableColumns("tenant", ["id", "name", "extra"])
        self.assertTableColumns("role", ["id", "name"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])
        self.populate_user_table()

    def test_upgrade_add_policy(self):
        self.upgrade(5)
        self.assertTableDoesNotExist('policy')

        self.upgrade(6)
        self.assertTableExists('policy')
        self.assertTableColumns('policy', ['id', 'type', 'blob', 'extra'])

    def test_upgrade_normalize_identity(self):
        self.upgrade(8)
        self.populate_user_table()
        self.populate_tenant_table()
        self.upgrade(10)
        self.assertTableColumns("user",
                                ["id", "name", "extra",
                                 "password", "enabled"])
        self.assertTableColumns("tenant",
                                ["id", "name", "extra", "description",
                                 "enabled"])
        self.assertTableColumns("role", ["id", "name", "extra"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])
        session = self.Session()
        user_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        a_user = session.query(user_table).filter("id='foo'").one()
        self.assertTrue(a_user.enabled)
        a_user = session.query(user_table).filter("id='badguy'").one()
        self.assertFalse(a_user.enabled)
        tenant_table = sqlalchemy.Table("tenant",
                                        self.metadata,
                                        autoload=True)
        a_tenant = session.query(tenant_table).filter("id='baz'").one()
        self.assertEqual(a_tenant.description, 'description')
        session.commit()
        session.close()

    def test_upgrade_user_tenant_membership_to_metadata(self):
        self.upgrade(16)
        self.assertTableColumns(
            'user_project_membership',
            ['user_id', 'tenant_id'])

        user = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': 'default',
            'extra': json.dumps({}),
        }
        project = {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'domain_id': 'default',
            'extra': json.dumps({}),
        }
        metadata = {
            'user_id': user['id'],
            'tenant_id': project['id'],
        }
        session = self.Session()
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'project', project)
        self.insert_dict(session, 'user_project_membership', metadata)

        self.upgrade(17)
        user_project_metadata_table = sqlalchemy.Table(
            'user_project_metadata', self.metadata, autoload=True)

        result = session.query(user_project_metadata_table).one()
        self.assertEqual(result.user_id, user['id'])
        self.assertEqual(result.project_id, project['id'])
        self.assertEqual(
            json.loads(result.data),
            {'roles': [CONF.member_role_id]})

    def test_normalized_enabled_states(self):
        self.upgrade(8)

        users = {
            'bool_enabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': True})},
            'bool_disabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': False})},
            'str_enabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': 'True'})},
            'str_disabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': 'False'})},
            'int_enabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': 1})},
            'int_disabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': 0})},
            'null_enabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({'enabled': None})},
            'unset_enabled_user': {
                'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'password': uuid.uuid4().hex,
                'extra': json.dumps({})}}

        session = self.Session()
        for user in users.values():
            self.insert_dict(session, 'user', user)
        session.commit()

        self.upgrade(10)

        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        q = session.query(user_table, 'enabled')

        user = q.filter_by(id=users['bool_enabled_user']['id']).one()
        self.assertTrue(user.enabled)

        user = q.filter_by(id=users['bool_disabled_user']['id']).one()
        self.assertFalse(user.enabled)

        user = q.filter_by(id=users['str_enabled_user']['id']).one()
        self.assertTrue(user.enabled)

        user = q.filter_by(id=users['str_disabled_user']['id']).one()
        self.assertFalse(user.enabled)

        user = q.filter_by(id=users['int_enabled_user']['id']).one()
        self.assertTrue(user.enabled)

        user = q.filter_by(id=users['int_disabled_user']['id']).one()
        self.assertFalse(user.enabled)

        user = q.filter_by(id=users['null_enabled_user']['id']).one()
        self.assertTrue(user.enabled)

        user = q.filter_by(id=users['unset_enabled_user']['id']).one()
        self.assertTrue(user.enabled)

    def test_downgrade_10_to_8(self):
        self.upgrade(10)
        self.populate_user_table(with_pass_enab=True)
        self.populate_tenant_table(with_desc_enab=True)
        self.downgrade(8)
        self.assertTableColumns('user',
                                ['id', 'name', 'extra'])
        self.assertTableColumns('tenant',
                                ['id', 'name', 'extra'])
        session = self.Session()
        user_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        a_user = session.query(user_table).filter("id='badguy'").one()
        self.assertEqual(a_user.name, default_fixtures.USERS[2]['name'])
        tenant_table = sqlalchemy.Table("tenant",
                                        self.metadata,
                                        autoload=True)
        a_tenant = session.query(tenant_table).filter("id='baz'").one()
        self.assertEqual(a_tenant.name, default_fixtures.TENANTS[1]['name'])
        session.commit()
        session.close()

    def test_upgrade_endpoints(self):
        self.upgrade(10)
        service_extra = {
            'name': uuid.uuid4().hex,
        }
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'extra': json.dumps(service_extra),
        }
        endpoint_extra = {
            'publicurl': uuid.uuid4().hex,
            'internalurl': uuid.uuid4().hex,
            'adminurl': uuid.uuid4().hex,
        }
        endpoint = {
            'id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'service_id': service['id'],
            'extra': json.dumps(endpoint_extra),
        }

        session = self.Session()
        self.insert_dict(session, 'service', service)
        self.insert_dict(session, 'endpoint', endpoint)
        session.commit()
        session.close()

        self.upgrade(13)
        self.assertTableColumns(
            'service',
            ['id', 'type', 'extra'])
        self.assertTableColumns(
            'endpoint',
            ['id', 'legacy_endpoint_id', 'interface', 'region', 'service_id',
             'url', 'extra'])

        endpoint_table = sqlalchemy.Table(
            'endpoint', self.metadata, autoload=True)

        session = self.Session()
        self.assertEqual(session.query(endpoint_table).count(), 3)
        for interface in ['public', 'internal', 'admin']:
            q = session.query(endpoint_table)
            q = q.filter_by(legacy_endpoint_id=endpoint['id'])
            q = q.filter_by(interface=interface)
            ref = q.one()
            self.assertNotEqual(ref.id, endpoint['id'])
            self.assertEqual(ref.legacy_endpoint_id, endpoint['id'])
            self.assertEqual(ref.interface, interface)
            self.assertEqual(ref.region, endpoint['region'])
            self.assertEqual(ref.service_id, endpoint['service_id'])
            self.assertEqual(ref.url, endpoint_extra['%surl' % interface])
            self.assertEqual(ref.extra, '{}')
        session.commit()
        session.close()

    def assertTenantTables(self):
        self.assertTableExists('tenant')
        self.assertTableExists('user_tenant_membership')
        self.assertTableDoesNotExist('project')
        self.assertTableDoesNotExist('user_project_membership')

    def assertProjectTables(self):
        self.assertTableExists('project')
        self.assertTableExists('user_project_membership')
        self.assertTableDoesNotExist('tenant')
        self.assertTableDoesNotExist('user_tenant_membership')

    def test_upgrade_tenant_to_project(self):
        self.upgrade(14)
        self.assertTenantTables()
        self.upgrade(15)
        self.assertProjectTables()

    def test_downgrade_project_to_tenant(self):
        # TODO(henry-nash): Debug why we need to re-load the tenant
        # or user_tenant_membership ahead of upgrading to project
        # in order for the assertProjectTables to work on sqlite
        # (MySQL is fine without it)
        self.upgrade(14)
        self.assertTenantTables()
        self.upgrade(15)
        self.assertProjectTables()
        self.downgrade(14)
        self.assertTenantTables()

    def test_upgrade_add_group_tables(self):
        self.upgrade(13)
        self.upgrade(14)
        self.assertTableExists('group')
        self.assertTableExists('group_project_metadata')
        self.assertTableExists('group_domain_metadata')
        self.assertTableExists('user_group_membership')

    def test_upgrade_14_to_16(self):
        self.upgrade(14)
        self.populate_user_table(with_pass_enab=True)
        self.populate_tenant_table(with_desc_enab=True)
        self.upgrade(16)

        self.assertTableColumns("user",
                                ["id", "name", "extra",
                                 "password", "enabled", "domain_id"])
        session = self.Session()
        user_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        a_user = session.query(user_table).filter("id='foo'").one()
        self.assertTrue(a_user.enabled)
        self.assertEqual(a_user.domain_id, DEFAULT_DOMAIN_ID)
        a_user = session.query(user_table).filter("id='badguy'").one()
        self.assertEqual(a_user.name, default_fixtures.USERS[2]['name'])
        self.assertEqual(a_user.domain_id, DEFAULT_DOMAIN_ID)
        project_table = sqlalchemy.Table("project",
                                         self.metadata,
                                         autoload=True)
        a_project = session.query(project_table).filter("id='baz'").one()
        self.assertEqual(a_project.description,
                         default_fixtures.TENANTS[1]['description'])
        self.assertEqual(a_project.domain_id, DEFAULT_DOMAIN_ID)

        session.commit()
        session.close()

        self.check_uniqueness_constraints()

    def test_downgrade_16_to_14(self):
        self.upgrade(16)
        self.populate_user_table(with_pass_enab_domain=True)
        self.populate_tenant_table(with_desc_enab_domain=True)
        self.downgrade(14)
        self.assertTableColumns("user",
                                ["id", "name", "extra",
                                 "password", "enabled"])
        session = self.Session()
        user_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        a_user = session.query(user_table).filter("id='foo'").one()
        self.assertTrue(a_user.enabled)
        a_user = session.query(user_table).filter("id='badguy'").one()
        self.assertEqual(a_user.name, default_fixtures.USERS[2]['name'])
        tenant_table = sqlalchemy.Table("tenant",
                                        self.metadata,
                                        autoload=True)
        a_tenant = session.query(tenant_table).filter("id='baz'").one()
        self.assertEqual(a_tenant.description,
                         default_fixtures.TENANTS[1]['description'])
        session.commit()
        session.close()

    def test_downgrade_remove_group_tables(self):
        self.upgrade(14)
        self.downgrade(13)
        self.assertTableDoesNotExist('group')
        self.assertTableDoesNotExist('group_project_metadata')
        self.assertTableDoesNotExist('group_domain_metadata')
        self.assertTableDoesNotExist('user_group_membership')

    def test_downgrade_endpoints(self):
        self.upgrade(13)

        service_extra = {
            'name': uuid.uuid4().hex,
        }
        service = {
            'id': uuid.uuid4().hex,
            'type': uuid.uuid4().hex,
            'extra': json.dumps(service_extra),
        }

        common_endpoint_attrs = {
            'legacy_endpoint_id': uuid.uuid4().hex,
            'region': uuid.uuid4().hex,
            'service_id': service['id'],
            'extra': json.dumps({}),
        }
        endpoints = {
            'public': {
                'id': uuid.uuid4().hex,
                'interface': 'public',
                'url': uuid.uuid4().hex,
            },
            'internal': {
                'id': uuid.uuid4().hex,
                'interface': 'internal',
                'url': uuid.uuid4().hex,
            },
            'admin': {
                'id': uuid.uuid4().hex,
                'interface': 'admin',
                'url': uuid.uuid4().hex,
            },
        }

        session = self.Session()
        self.insert_dict(session, 'service', service)
        for endpoint in endpoints.values():
            endpoint.update(common_endpoint_attrs)
            self.insert_dict(session, 'endpoint', endpoint)
        session.commit()
        session.close()

        self.downgrade(9)

        self.assertTableColumns(
            'service',
            ['id', 'type', 'extra'])
        self.assertTableColumns(
            'endpoint',
            ['id', 'region', 'service_id', 'extra'])

        endpoint_table = sqlalchemy.Table(
            'endpoint', self.metadata, autoload=True)

        session = self.Session()
        self.assertEqual(session.query(endpoint_table).count(), 1)
        q = session.query(endpoint_table)
        q = q.filter_by(id=common_endpoint_attrs['legacy_endpoint_id'])
        ref = q.one()
        self.assertEqual(ref.id, common_endpoint_attrs['legacy_endpoint_id'])
        self.assertEqual(ref.region, endpoint['region'])
        self.assertEqual(ref.service_id, endpoint['service_id'])
        extra = json.loads(ref.extra)
        for interface in ['public', 'internal', 'admin']:
            expected_url = endpoints[interface]['url']
            self.assertEqual(extra['%surl' % interface], expected_url)
        session.commit()
        session.close()

    def insert_dict(self, session, table_name, d):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        this_table = sqlalchemy.Table(table_name, self.metadata, autoload=True)
        insert = this_table.insert()
        insert.execute(d)
        session.commit()

    def test_upgrade_31_to_32(self):
        self.upgrade(32)

        user_table = self.select_table("user")
        self.assertEquals(user_table.c.name.type.length, 255)

    def test_downgrade_32_to_31(self):
        self.upgrade(32)
        session = self.Session()
        # NOTE(aloga): we need a different metadata object
        user_table = sqlalchemy.Table('user',
                                      sqlalchemy.MetaData(),
                                      autoload=True,
                                      autoload_with=self.engine)
        user_id = uuid.uuid4().hex
        ins = user_table.insert().values(
            {'id': user_id,
             'name': 'a' * 255,
             'password': uuid.uuid4().hex,
             'enabled': True,
             'domain_id': DEFAULT_DOMAIN_ID,
             'extra': '{}'})
        session.execute(ins)
        session.commit()

        self.downgrade(31)
        # Check that username has been truncated
        q = session.query(user_table.c.name)
        q = q.filter(user_table.c.id == user_id)
        r = q.one()
        user_name = r[0]
        self.assertEquals(len(user_name), 64)

        user_table = self.select_table("user")
        self.assertEquals(user_table.c.name.type.length, 64)

    def test_downgrade_to_0(self):
        self.upgrade(self.max_version)

        if self.engine.name == 'mysql':
            self._mysql_check_all_tables_innodb()

        self.downgrade(0)
        for table_name in ["user", "token", "role", "user_tenant_membership",
                           "metadata"]:
            self.assertTableDoesNotExist(table_name)

    def test_upgrade_add_domain_tables(self):
        self.upgrade(6)
        self.assertTableDoesNotExist('credential')
        self.assertTableDoesNotExist('domain')
        self.assertTableDoesNotExist('user_domain_metadata')

        self.upgrade(7)
        self.assertTableExists('credential')
        self.assertTableColumns('credential', ['id', 'user_id', 'project_id',
                                               'blob', 'type', 'extra'])
        self.assertTableExists('domain')
        self.assertTableColumns('domain', ['id', 'name', 'enabled', 'extra'])
        self.assertTableExists('user_domain_metadata')
        self.assertTableColumns('user_domain_metadata',
                                ['user_id', 'domain_id', 'data'])

    def test_metadata_table_migration(self):
        # Scaffolding
        session = self.Session()

        self.upgrade(16)
        domain_table = sqlalchemy.Table('domain', self.metadata, autoload=True)
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        project_table = sqlalchemy.Table(
            'project', self.metadata, autoload=True)
        metadata_table = sqlalchemy.Table(
            'metadata', self.metadata, autoload=True)

        # Create a Domain
        domain = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex,
                  'enabled': True}
        session.execute(domain_table.insert().values(domain))

        # Create a Project
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain['id'],
                   'extra': "{}"}
        session.execute(project_table.insert().values(project))

        # Create another Project
        project2 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': domain['id'],
                    'extra': "{}"}
        session.execute(project_table.insert().values(project2))

        # Create a User
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': domain['id'],
                'password': uuid.uuid4().hex,
                'enabled': True,
                'extra': json.dumps({})}
        session.execute(user_table.insert().values(user))

        # Create a Role
        role = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
        session.execute(role_table.insert().values(role))

        # And another role
        role2 = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex}
        session.execute(role_table.insert().values(role2))

        # Grant Role to User
        role_grant = {'user_id': user['id'],
                      'tenant_id': project['id'],
                      'data': json.dumps({"roles": [role['id']]})}
        session.execute(metadata_table.insert().values(role_grant))

        role_grant = {'user_id': user['id'],
                      'tenant_id': project2['id'],
                      'data': json.dumps({"roles": [role2['id']]})}
        session.execute(metadata_table.insert().values(role_grant))

        # Create another user to test the case where member_role_id is already
        # assigned.
        user2 = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': domain['id'],
                 'password': uuid.uuid4().hex,
                 'enabled': True,
                 'extra': json.dumps({})}
        session.execute(user_table.insert().values(user2))

        # Grant CONF.member_role_id to User2
        role_grant = {'user_id': user2['id'],
                      'tenant_id': project['id'],
                      'data': json.dumps({"roles": [CONF.member_role_id]})}
        session.execute(metadata_table.insert().values(role_grant))

        session.commit()

        self.upgrade(17)

        user_project_metadata_table = sqlalchemy.Table(
            'user_project_metadata', self.metadata, autoload=True)

        s = sqlalchemy.select([metadata_table.c.data]).where(
            (metadata_table.c.user_id == user['id']) &
            (metadata_table.c.tenant_id == project['id']))
        r = session.execute(s)
        test_project1 = json.loads(r.fetchone()['data'])
        self.assertEqual(len(test_project1['roles']), 1)
        self.assertIn(role['id'], test_project1['roles'])

        # Test user in project2 has role2
        s = sqlalchemy.select([metadata_table.c.data]).where(
            (metadata_table.c.user_id == user['id']) &
            (metadata_table.c.tenant_id == project2['id']))
        r = session.execute(s)
        test_project2 = json.loads(r.fetchone()['data'])
        self.assertEqual(len(test_project2['roles']), 1)
        self.assertIn(role2['id'], test_project2['roles'])

        # Test for user in project has role in user_project_metadata
        # Migration 17 does not properly migrate this data, so this should
        # be None.
        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project['id']))
        r = session.execute(s)
        self.assertIsNone(r.fetchone())

        # Create a conflicting user-project in user_project_metadata with
        # a different role
        data = json.dumps({"roles": [role2['id']]})
        role_grant = {'user_id': user['id'],
                      'project_id': project['id'],
                      'data': data}
        cmd = user_project_metadata_table.insert().values(role_grant)
        self.engine.execute(cmd)

        # Create another conflicting user-project for User2
        data = json.dumps({"roles": [role2['id']]})
        role_grant = {'user_id': user2['id'],
                      'project_id': project['id'],
                      'data': data}
        cmd = user_project_metadata_table.insert().values(role_grant)
        self.engine.execute(cmd)
        # End Scaffolding

        session.commit()

        # Migrate to 20
        self.upgrade(20)

        # The user-project pairs should have all roles from the previous
        # metadata table in addition to any roles currently in
        # user_project_metadata
        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project['id']))
        r = session.execute(s)
        role_ids = json.loads(r.fetchone()['data'])['roles']
        self.assertEqual(len(role_ids), 3)
        self.assertIn(CONF.member_role_id, role_ids)
        self.assertIn(role['id'], role_ids)
        self.assertIn(role2['id'], role_ids)

        # pairs that only existed in old metadata table should be in
        # user_project_metadata
        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project2['id']))
        r = session.execute(s)
        role_ids = json.loads(r.fetchone()['data'])['roles']
        self.assertEqual(len(role_ids), 2)
        self.assertIn(CONF.member_role_id, role_ids)
        self.assertIn(role2['id'], role_ids)

        self.assertTableDoesNotExist('metadata')

    def test_upgrade_default_roles(self):
        def count_member_roles():
            session = self.Session()
            query_string = ("select count(*) as c from role "
                            "where name='%s'" % config.CONF.member_role_name)
            role_count = session.execute(query_string).fetchone()['c']
            session.close()
            return role_count

        self.upgrade(16)
        self.assertEquals(0, count_member_roles())
        self.upgrade(17)
        self.assertEquals(1, count_member_roles())
        self.downgrade(16)
        self.assertEquals(0, count_member_roles())

    def check_uniqueness_constraints(self):
        # Check uniqueness constraints for User & Project tables are
        # correct following schema modification.  The Group table's
        # schema is never modified, so we don't bother to check that.
        domain_table = sqlalchemy.Table('domain',
                                        self.metadata,
                                        autoload=True)
        domain1 = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'enabled': True}
        domain2 = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'enabled': True}
        cmd = domain_table.insert().values(domain1)
        self.engine.execute(cmd)
        cmd = domain_table.insert().values(domain2)
        self.engine.execute(cmd)

        # First, the User table.
        this_table = sqlalchemy.Table('user',
                                      self.metadata,
                                      autoload=True)
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': domain1['id'],
                'password': uuid.uuid4().hex,
                'enabled': True,
                'extra': json.dumps({})}
        cmd = this_table.insert().values(user)
        self.engine.execute(cmd)
        # now insert a user with the same name into a different
        # domain - which should work.
        user['id'] = uuid.uuid4().hex
        user['domain_id'] = domain2['id']
        cmd = this_table.insert().values(user)
        self.engine.execute(cmd)
        # TODO(henry-nash): For now, as part of clean-up we delete one of these
        # users.  Although not part of this test, unless we do so the
        # downgrade(16->15) that is part of teardown with fail due to having
        # two uses with clashing name as we try to revert to a single global
        # name space.  This limitation is raised as Bug #1125046 and the delete
        # could be removed depending on how that bug is resolved.
        cmd = this_table.delete(id=user['id'])
        self.engine.execute(cmd)

        # Now, the Project table.
        this_table = sqlalchemy.Table('project',
                                      self.metadata,
                                      autoload=True)
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain1['id'],
                   'description': uuid.uuid4().hex,
                   'enabled': True,
                   'extra': json.dumps({})}
        cmd = this_table.insert().values(project)
        self.engine.execute(cmd)
        # now insert a project with the same name into a different
        # domain - which should work.
        project['id'] = uuid.uuid4().hex
        project['domain_id'] = domain2['id']
        cmd = this_table.insert().values(project)
        self.engine.execute(cmd)
        # TODO(henry-nash): For now, we delete one of the projects for the same
        # reason as we delete one of the users (Bug #1125046). This delete
        # could be removed depending on that bug resolution.
        cmd = this_table.delete(id=project['id'])
        self.engine.execute(cmd)

    def test_upgrade_trusts(self):
        self.assertEqual(self.schema.version, 0, "DB is at version 0")
        self.upgrade(20)
        self.assertTableColumns("token",
                                ["id", "expires", "extra", "valid"])
        self.upgrade(21)
        self.assertTableColumns("trust",
                                ["id", "trustor_user_id",
                                 "trustee_user_id",
                                 "project_id", "impersonation",
                                 "deleted_at",
                                 "expires_at", "extra"])
        self.assertTableColumns("trust_role",
                                ["trust_id", "role_id"])
        self.assertTableColumns("token",
                                ["id", "expires", "extra", "valid",
                                 "trust_id", "user_id"])

    def test_fixup_role(self):
        session = self.Session()
        self.assertEqual(self.schema.version, 0, "DB is at version 0")
        self.upgrade(1)
        self.insert_dict(session, "role", {"id": "test", "name": "test"})
        self.upgrade(18)
        self.insert_dict(session, "role", {"id": "test2",
                                           "name": "test2",
                                           "extra": None})
        r = session.execute('select count(*) as c from role '
                            'where extra is null')
        self.assertEqual(r.fetchone()['c'], 2)
        session.commit()
        self.upgrade(19)
        r = session.execute('select count(*) as c from role '
                            'where extra is null')
        self.assertEqual(r.fetchone()['c'], 0)

    def test_legacy_endpoint_id(self):
        session = self.Session()
        self.upgrade(21)

        service = {
            'id': uuid.uuid4().hex,
            'name': 'keystone',
            'type': 'identity'}
        self.insert_dict(session, 'service', service)

        legacy_endpoint_id = uuid.uuid4().hex
        endpoint = {
            'id': uuid.uuid4().hex,
            'service_id': service['id'],
            'interface': uuid.uuid4().hex[:8],
            'url': uuid.uuid4().hex,
            'extra': json.dumps({
                'legacy_endpoint_id': legacy_endpoint_id})}
        self.insert_dict(session, 'endpoint', endpoint)

        session.commit()
        self.upgrade(22)

        endpoint_table = sqlalchemy.Table(
            'endpoint', self.metadata, autoload=True)

        self.assertEqual(session.query(endpoint_table).count(), 1)
        ref = session.query(endpoint_table).one()
        self.assertEqual(ref.id, endpoint['id'], ref)
        self.assertEqual(ref.service_id, endpoint['service_id'])
        self.assertEqual(ref.interface, endpoint['interface'])
        self.assertEqual(ref.url, endpoint['url'])
        self.assertEqual(ref.legacy_endpoint_id, legacy_endpoint_id)
        self.assertEqual(ref.extra, '{}')

    def test_group_project_FK_fixup(self):
        # To create test data we must start before we broke in the
        # group_project_metadata table in 015.
        self.upgrade(14)
        session = self.Session()

        domain_table = sqlalchemy.Table('domain', self.metadata, autoload=True)
        group_table = sqlalchemy.Table('group', self.metadata, autoload=True)
        tenant_table = sqlalchemy.Table('tenant', self.metadata, autoload=True)
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        group_project_metadata_table = sqlalchemy.Table(
            'group_project_metadata', self.metadata, autoload=True)

        # Create a Domain
        domain = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex,
                  'enabled': True}
        session.execute(domain_table.insert().values(domain))

        # Create two Tenants
        tenant = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex,
                  'extra': "{}"}
        session.execute(tenant_table.insert().values(tenant))

        tenant1 = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'extra': "{}"}
        session.execute(tenant_table.insert().values(tenant1))

        # Create a Group
        group = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': domain['id'],
                 'extra': json.dumps({})}
        session.execute(group_table.insert().values(group))

        # Create roles
        role_list = []
        for _ in range(2):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            session.execute(role_table.insert().values(role))
            role_list.append(role)

        # Grant Role to User on Project
        role_grant = {'group_id': group['id'],
                      'project_id': tenant['id'],
                      'data': json.dumps({'roles': [role_list[0]['id']]})}
        session.execute(
            group_project_metadata_table.insert().values(role_grant))

        role_grant = {'group_id': group['id'],
                      'project_id': tenant1['id'],
                      'data': json.dumps({'roles': [role_list[1]['id']]})}
        session.execute(
            group_project_metadata_table.insert().values(role_grant))

        session.commit()

        # Now upgrade and fix up the FKs
        self.upgrade(28)
        self.assertTableExists('group_project_metadata')
        self.assertTableExists('project')
        self.assertTableDoesNotExist('tenant')

        s = sqlalchemy.select([group_project_metadata_table.c.data]).where(
            (group_project_metadata_table.c.group_id == group['id']) &
            (group_project_metadata_table.c.project_id == tenant['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[0]['id'], data['roles'])

        s = sqlalchemy.select([group_project_metadata_table.c.data]).where(
            (group_project_metadata_table.c.group_id == group['id']) &
            (group_project_metadata_table.c.project_id == tenant1['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[1]['id'], data['roles'])

        self.downgrade(27)
        self.assertTableExists('group_project_metadata')
        self.assertTableExists('project')
        self.assertTableDoesNotExist('tenant')

    def test_assignment_metadata_migration(self):
        self.upgrade(28)
        # Scaffolding
        session = self.Session()

        domain_table = sqlalchemy.Table('domain', self.metadata, autoload=True)
        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        group_table = sqlalchemy.Table('group', self.metadata, autoload=True)
        role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
        project_table = sqlalchemy.Table(
            'project', self.metadata, autoload=True)
        user_project_metadata_table = sqlalchemy.Table(
            'user_project_metadata', self.metadata, autoload=True)
        user_domain_metadata_table = sqlalchemy.Table(
            'user_domain_metadata', self.metadata, autoload=True)
        group_project_metadata_table = sqlalchemy.Table(
            'group_project_metadata', self.metadata, autoload=True)
        group_domain_metadata_table = sqlalchemy.Table(
            'group_domain_metadata', self.metadata, autoload=True)

        # Create a Domain
        domain = {'id': uuid.uuid4().hex,
                  'name': uuid.uuid4().hex,
                  'enabled': True}
        session.execute(domain_table.insert().values(domain))

        # Create anther Domain
        domain2 = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'enabled': True}
        session.execute(domain_table.insert().values(domain2))

        # Create a Project
        project = {'id': uuid.uuid4().hex,
                   'name': uuid.uuid4().hex,
                   'domain_id': domain['id'],
                   'extra': "{}"}
        session.execute(project_table.insert().values(project))

        # Create another Project
        project2 = {'id': uuid.uuid4().hex,
                    'name': uuid.uuid4().hex,
                    'domain_id': domain['id'],
                    'extra': "{}"}
        session.execute(project_table.insert().values(project2))

        # Create a User
        user = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex,
                'domain_id': domain['id'],
                'password': uuid.uuid4().hex,
                'enabled': True,
                'extra': json.dumps({})}
        session.execute(user_table.insert().values(user))

        # Create a Group
        group = {'id': uuid.uuid4().hex,
                 'name': uuid.uuid4().hex,
                 'domain_id': domain['id'],
                 'extra': json.dumps({})}
        session.execute(group_table.insert().values(group))

        # Create roles
        role_list = []
        for _ in range(7):
            role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
            session.execute(role_table.insert().values(role))
            role_list.append(role)

        # Grant Role to User on Project
        role_grant = {'user_id': user['id'],
                      'project_id': project['id'],
                      'data': json.dumps({'roles': [role_list[0]['id']]})}
        session.execute(
            user_project_metadata_table.insert().values(role_grant))

        role_grant = {'user_id': user['id'],
                      'project_id': project2['id'],
                      'data': json.dumps({'roles': [role_list[1]['id']]})}
        session.execute(
            user_project_metadata_table.insert().values(role_grant))

        # Grant Role to Group on different Project
        role_grant = {'group_id': group['id'],
                      'project_id': project2['id'],
                      'data': json.dumps({'roles': [role_list[2]['id']]})}
        session.execute(
            group_project_metadata_table.insert().values(role_grant))

        # Grant Role to User on Domain
        role_grant = {'user_id': user['id'],
                      'domain_id': domain['id'],
                      'data': json.dumps({'roles': [role_list[3]['id']]})}
        session.execute(user_domain_metadata_table.insert().values(role_grant))

        # Grant Role to Group on Domain
        role_grant = {'group_id': group['id'],
                      'domain_id': domain['id'],
                      'data': json.dumps(
                          {'roles': [role_list[4]['id']],
                           'other': 'somedata'})}
        session.execute(
            group_domain_metadata_table.insert().values(role_grant))

        session.commit()

        self.upgrade(29)
        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn({'id': role_list[0]['id']}, data['roles'])

        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project2['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn({'id': role_list[1]['id']}, data['roles'])

        s = sqlalchemy.select([group_project_metadata_table.c.data]).where(
            (group_project_metadata_table.c.group_id == group['id']) &
            (group_project_metadata_table.c.project_id == project2['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn({'id': role_list[2]['id']}, data['roles'])

        s = sqlalchemy.select([user_domain_metadata_table.c.data]).where(
            (user_domain_metadata_table.c.user_id == user['id']) &
            (user_domain_metadata_table.c.domain_id == domain['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn({'id': role_list[3]['id']}, data['roles'])

        s = sqlalchemy.select([group_domain_metadata_table.c.data]).where(
            (group_domain_metadata_table.c.group_id == group['id']) &
            (group_domain_metadata_table.c.domain_id == domain['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn({'id': role_list[4]['id']}, data['roles'])
        self.assertIn('other', data)

        # Now add an entry that has one regular and one inherited role
        role_grant = {'user_id': user['id'],
                      'domain_id': domain2['id'],
                      'data': json.dumps(
                          {'roles': [{'id': role_list[5]['id']},
                                     {'id': role_list[6]['id'],
                                      'inherited_to': 'projects'}]})}
        session.execute(user_domain_metadata_table.insert().values(role_grant))

        session.commit()
        self.downgrade(28)

        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[0]['id'], data['roles'])

        s = sqlalchemy.select([user_project_metadata_table.c.data]).where(
            (user_project_metadata_table.c.user_id == user['id']) &
            (user_project_metadata_table.c.project_id == project2['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[1]['id'], data['roles'])

        s = sqlalchemy.select([group_project_metadata_table.c.data]).where(
            (group_project_metadata_table.c.group_id == group['id']) &
            (group_project_metadata_table.c.project_id == project2['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[2]['id'], data['roles'])

        s = sqlalchemy.select([user_domain_metadata_table.c.data]).where(
            (user_domain_metadata_table.c.user_id == user['id']) &
            (user_domain_metadata_table.c.domain_id == domain['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[3]['id'], data['roles'])

        s = sqlalchemy.select([group_domain_metadata_table.c.data]).where(
            (group_domain_metadata_table.c.group_id == group['id']) &
            (group_domain_metadata_table.c.domain_id == domain['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[4]['id'], data['roles'])
        self.assertIn('other', data)

        # For user-domain2, where we had one regular and one inherited role,
        # only the direct role should remain, the inherited role should
        # have been deleted during the downgrade
        s = sqlalchemy.select([user_domain_metadata_table.c.data]).where(
            (user_domain_metadata_table.c.user_id == user['id']) &
            (user_domain_metadata_table.c.domain_id == domain2['id']))
        r = session.execute(s)
        data = json.loads(r.fetchone()['data'])
        self.assertEqual(len(data['roles']), 1)
        self.assertIn(role_list[5]['id'], data['roles'])

    def test_drop_credential_constraint(self):
        ec2_credential = {
            'id': '100',
            'user_id': 'foo',
            'project_id': 'bar',
            'type': 'ec2',
            'blob': json.dumps({
                "access": "12345",
                "secret": "12345"
            })
        }
        user = {
            'id': 'foo',
            'name': 'FOO',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'enabled': True})
        }
        tenant = {
            'id': 'bar',
            'name': 'BAR',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        session = self.Session()
        self.upgrade(7)
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'tenant', tenant)
        self.insert_dict(session, 'credential', ec2_credential)
        session.commit()
        self.upgrade(30)
        cred_table = sqlalchemy.Table('credential',
                                      self.metadata,
                                      autoload=True)
        cred = session.query(cred_table).filter("id='100'").one()
        self.assertEqual(cred.user_id,
                         ec2_credential['user_id'])

    def test_drop_credential_indexes(self):
        self.upgrade(31)
        table = sqlalchemy.Table('credential', self.metadata, autoload=True)
        self.assertEqual(len(table.indexes), 0)

    def test_downgrade_30(self):
        self.upgrade(31)
        self.downgrade(30)
        table = sqlalchemy.Table('credential', self.metadata, autoload=True)
        index_data = [(idx.name, idx.columns.keys())
                      for idx in table.indexes]
        if self.engine.name == 'mysql':
            self.assertIn(('user_id', ['user_id']), index_data)
            self.assertIn(('credential_project_id_fkey', ['project_id']),
                          index_data)
        else:
            self.assertEqual(len(index_data), 0)

    def test_migrate_ec2_credential(self):
        user = {
            'id': 'foo',
            'name': 'FOO',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'enabled': True})
        }
        project = {
            'id': 'bar',
            'name': 'BAR',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        ec2_credential = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': user['id'],
            'tenant_id': project['id'],
        }
        session = self.Session()
        self.upgrade(7)
        self.insert_dict(session, 'ec2_credential', ec2_credential)
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'tenant', project)
        self.upgrade(33)
        self.assertTableDoesNotExist('ec2_credential')
        cred_table = sqlalchemy.Table('credential',
                                      self.metadata,
                                      autoload=True)
        expected_credential_id = utils.hash_access_key(
            ec2_credential['access'])
        cred = session.query(cred_table).filter_by(
            id=expected_credential_id).one()
        self.assertEqual(cred.user_id, ec2_credential['user_id'])
        self.assertEqual(cred.project_id, ec2_credential['tenant_id'])
        # test list credential using credential manager.
        credential_api = credential.Manager()
        self.assertNotEmpty(credential_api.
                            list_credentials(
                            user_id=ec2_credential['user_id']))
        self.downgrade(32)
        session.commit()
        self.assertTableExists('ec2_credential')
        ec2_cred_table = sqlalchemy.Table('ec2_credential',
                                          self.metadata,
                                          autoload=True)
        ec2_cred = session.query(ec2_cred_table).filter_by(
            access=ec2_credential['access']).one()
        self.assertEqual(ec2_cred.user_id, ec2_credential['user_id'])

    def test_migrate_ec2_credential_with_conflict_project(self):
        user = {
            'id': 'foo',
            'name': 'FOO',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'enabled': True})
        }
        project_1 = {
            'id': 'bar',
            'name': 'BAR',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        project_2 = {
            'id': 'baz',
            'name': 'BAZ',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        ec2_credential = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': user['id'],
            'tenant_id': project_1['id'],
        }
        blob = {'access': ec2_credential['access'],
                'secret': ec2_credential['secret']}
        v3_credential = {
            'id': utils.hash_access_key(ec2_credential['access']),
            'user_id': user['id'],
            # set the project id to simulate a conflict
            'project_id': project_2['id'],
            'blob': json.dumps(blob),
            'type': 'ec2',
            'extra': json.dumps({})
        }
        session = self.Session()
        self.upgrade(7)
        self.insert_dict(session, 'ec2_credential', ec2_credential)
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'tenant', project_1)
        self.insert_dict(session, 'tenant', project_2)
        self.upgrade(32)
        self.insert_dict(session, 'credential', v3_credential)
        self.assertRaises(exception.Conflict, self.upgrade, 33)

    def test_migrate_ec2_credential_with_conflict_secret(self):
        user = {
            'id': 'foo',
            'name': 'FOO',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'enabled': True})
        }
        project_1 = {
            'id': 'bar',
            'name': 'BAR',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        project_2 = {
            'id': 'baz',
            'name': 'BAZ',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        ec2_credential = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': user['id'],
            'tenant_id': project_1['id'],
        }
        blob = {'access': ec2_credential['access'],
                'secret': 'different secret'}
        v3_cred_different_secret = {
            'id': utils.hash_access_key(ec2_credential['access']),
            'user_id': user['id'],
            'project_id': project_1['id'],
            'blob': json.dumps(blob),
            'type': 'ec2',
            'extra': json.dumps({})
        }

        session = self.Session()
        self.upgrade(7)
        self.insert_dict(session, 'ec2_credential', ec2_credential)
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'tenant', project_1)
        self.insert_dict(session, 'tenant', project_2)
        self.upgrade(32)
        self.insert_dict(session, 'credential', v3_cred_different_secret)
        self.assertRaises(exception.Conflict, self.upgrade, 33)

    def test_migrate_ec2_credential_with_invalid_blob(self):
        user = {
            'id': 'foo',
            'name': 'FOO',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'enabled': True})
        }
        project_1 = {
            'id': 'bar',
            'name': 'BAR',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        project_2 = {
            'id': 'baz',
            'name': 'BAZ',
            'description': 'description',
            'enabled': True,
            'extra': json.dumps({'enabled': True})
        }
        ec2_credential = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'user_id': user['id'],
            'tenant_id': project_1['id'],
        }
        blob = '{"abc":"def"d}'
        v3_cred_invalid_blob = {
            'id': utils.hash_access_key(ec2_credential['access']),
            'user_id': user['id'],
            'project_id': project_1['id'],
            'blob': json.dumps(blob),
            'type': 'ec2',
            'extra': json.dumps({})
        }

        session = self.Session()
        self.upgrade(7)
        self.insert_dict(session, 'ec2_credential', ec2_credential)
        self.insert_dict(session, 'user', user)
        self.insert_dict(session, 'tenant', project_1)
        self.insert_dict(session, 'tenant', project_2)
        self.upgrade(32)
        self.insert_dict(session, 'credential', v3_cred_invalid_blob)
        self.assertRaises(exception.ValidationError, self.upgrade, 33)

    def test_migrate_add_default_project_id_column_upgrade(self):
        user1 = {
            'id': 'foo1',
            'name': 'FOO1',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'tenantId': 'bar'}),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        user2 = {
            'id': 'foo2',
            'name': 'FOO2',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'tenant_id': 'bar'}),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        user3 = {
            'id': 'foo3',
            'name': 'FOO3',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'default_project_id': 'bar'}),
            'domain_id': DEFAULT_DOMAIN_ID
        }
        user4 = {
            'id': 'foo4',
            'name': 'FOO4',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({'tenantId': 'baz',
                                 'default_project_id': 'bar'}),
            'domain_id': DEFAULT_DOMAIN_ID
        }

        session = self.Session()
        self.upgrade(33)
        self.insert_dict(session, 'user', user1)
        self.insert_dict(session, 'user', user2)
        self.insert_dict(session, 'user', user3)
        self.insert_dict(session, 'user', user4)
        self.assertTableColumns('user',
                                ['id', 'name', 'extra', 'password',
                                 'enabled', 'domain_id'])
        session.commit()
        session.close()
        self.upgrade(34)
        session = self.Session()
        self.assertTableColumns('user',
                                ['id', 'name', 'extra', 'password',
                                 'enabled', 'domain_id', 'default_project_id'])

        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        updated_user1 = session.query(user_table).filter_by(id='foo1').one()
        old_json_data = json.loads(user1['extra'])
        new_json_data = json.loads(updated_user1.extra)
        self.assertNotIn('tenantId', new_json_data)
        self.assertEqual(old_json_data['tenantId'],
                         updated_user1.default_project_id)
        updated_user2 = session.query(user_table).filter_by(id='foo2').one()
        old_json_data = json.loads(user2['extra'])
        new_json_data = json.loads(updated_user2.extra)
        self.assertNotIn('tenant_id', new_json_data)
        self.assertEqual(old_json_data['tenant_id'],
                         updated_user2.default_project_id)
        updated_user3 = session.query(user_table).filter_by(id='foo3').one()
        old_json_data = json.loads(user3['extra'])
        new_json_data = json.loads(updated_user3.extra)
        self.assertNotIn('default_project_id', new_json_data)
        self.assertEqual(old_json_data['default_project_id'],
                         updated_user3.default_project_id)
        updated_user4 = session.query(user_table).filter_by(id='foo4').one()
        old_json_data = json.loads(user4['extra'])
        new_json_data = json.loads(updated_user4.extra)
        self.assertNotIn('default_project_id', new_json_data)
        self.assertNotIn('tenantId', new_json_data)
        self.assertEqual(old_json_data['default_project_id'],
                         updated_user4.default_project_id)

    def test_migrate_add_default_project_id_column_downgrade(self):
        user1 = {
            'id': 'foo1',
            'name': 'FOO1',
            'password': 'foo2',
            'enabled': True,
            'email': 'foo@bar.com',
            'extra': json.dumps({}),
            'default_project_id': 'bar',
            'domain_id': DEFAULT_DOMAIN_ID
        }

        self.upgrade(34)
        session = self.Session()
        self.insert_dict(session, 'user', user1)
        self.assertTableColumns('user',
                                ['id', 'name', 'extra', 'password',
                                 'enabled', 'domain_id', 'default_project_id'])
        session.commit()
        session.close()
        self.downgrade(33)
        session = self.Session()
        self.assertTableColumns('user',
                                ['id', 'name', 'extra', 'password',
                                 'enabled', 'domain_id'])

        user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
        updated_user1 = session.query(user_table).filter_by(id='foo1').one()
        new_json_data = json.loads(updated_user1.extra)
        self.assertIn('tenantId', new_json_data)
        self.assertIn('default_project_id', new_json_data)
        self.assertEqual(user1['default_project_id'],
                         new_json_data['tenantId'])
        self.assertEqual(user1['default_project_id'],
                         new_json_data['default_project_id'])
        self.assertEqual(user1['default_project_id'],
                         new_json_data['tenant_id'])

    def populate_user_table(self, with_pass_enab=False,
                            with_pass_enab_domain=False):
        # Populate the appropriate fields in the user
        # table, depending on the parameters:
        #
        # Default: id, name, extra
        # pass_enab: Add password, enabled as well
        # pass_enab_domain: Add password, enabled and domain as well
        #
        this_table = sqlalchemy.Table("user",
                                      self.metadata,
                                      autoload=True)
        for user in default_fixtures.USERS:
            extra = copy.deepcopy(user)
            extra.pop('id')
            extra.pop('name')

            if with_pass_enab:
                password = extra.pop('password', None)
                enabled = extra.pop('enabled', True)
                ins = this_table.insert().values(
                    {'id': user['id'],
                     'name': user['name'],
                     'password': password,
                     'enabled': bool(enabled),
                     'extra': json.dumps(extra)})
            else:
                if with_pass_enab_domain:
                    password = extra.pop('password', None)
                    enabled = extra.pop('enabled', True)
                    extra.pop('domain_id')
                    ins = this_table.insert().values(
                        {'id': user['id'],
                         'name': user['name'],
                         'domain_id': user['domain_id'],
                         'password': password,
                         'enabled': bool(enabled),
                         'extra': json.dumps(extra)})
                else:
                    ins = this_table.insert().values(
                        {'id': user['id'],
                         'name': user['name'],
                         'extra': json.dumps(extra)})
            self.engine.execute(ins)

    def populate_tenant_table(self, with_desc_enab=False,
                              with_desc_enab_domain=False):
        # Populate the appropriate fields in the tenant or
        # project table, depending on the parameters
        #
        # Default: id, name, extra
        # desc_enab: Add description, enabled as well
        # desc_enab_domain: Add description, enabled and domain as well,
        #                   plus use project instead of tenant
        #
        if with_desc_enab_domain:
            # By this time tenants are now projects
            this_table = sqlalchemy.Table("project",
                                          self.metadata,
                                          autoload=True)
        else:
            this_table = sqlalchemy.Table("tenant",
                                          self.metadata,
                                          autoload=True)

        for tenant in default_fixtures.TENANTS:
            extra = copy.deepcopy(tenant)
            extra.pop('id')
            extra.pop('name')

            if with_desc_enab:
                desc = extra.pop('description', None)
                enabled = extra.pop('enabled', True)
                ins = this_table.insert().values(
                    {'id': tenant['id'],
                     'name': tenant['name'],
                     'description': desc,
                     'enabled': bool(enabled),
                     'extra': json.dumps(extra)})
            else:
                if with_desc_enab_domain:
                    desc = extra.pop('description', None)
                    enabled = extra.pop('enabled', True)
                    extra.pop('domain_id')
                    ins = this_table.insert().values(
                        {'id': tenant['id'],
                         'name': tenant['name'],
                         'domain_id': tenant['domain_id'],
                         'description': desc,
                         'enabled': bool(enabled),
                         'extra': json.dumps(extra)})
                else:
                    ins = this_table.insert().values(
                        {'id': tenant['id'],
                         'name': tenant['name'],
                         'extra': json.dumps(extra)})
            self.engine.execute(ins)

    def _mysql_check_all_tables_innodb(self):
        database = self.engine.url.database

        connection = self.engine.connect()
        # sanity check
        total = connection.execute("SELECT count(*) "
                                   "from information_schema.TABLES "
                                   "where TABLE_SCHEMA='%(database)s'" %
                                   dict(database=database))
        self.assertTrue(total.scalar() > 0, "No tables found. Wrong schema?")

        noninnodb = connection.execute("SELECT table_name "
                                       "from information_schema.TABLES "
                                       "where TABLE_SCHEMA='%(database)s' "
                                       "and ENGINE!='InnoDB' "
                                       "and TABLE_NAME!='migrate_version'" %
                                       dict(database=database))
        names = [x[0] for x in noninnodb]
        self.assertEqual(names, [],
                         "Non-InnoDB tables exist")

        connection.close()
