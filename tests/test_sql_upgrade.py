# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import copy
import json
import uuid

from migrate.versioning import api as versioning_api
import sqlalchemy

from keystone.common import sql
from keystone import config
from keystone import test
from keystone.common.sql import migration
import default_fixtures


CONF = config.CONF


class SqlUpgradeTests(test.TestCase):
    def setUp(self):
        super(SqlUpgradeTests, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_sql.conf')])

        # create and share a single sqlalchemy engine for testing
        base = sql.Base()
        self.engine = base.get_engine(allow_global_engine=False)
        self.Session = base.get_sessionmaker(
            engine=self.engine,
            autocommit=False)
        self.metadata = sqlalchemy.MetaData()

        # populate the engine with tables & fixtures
        self.metadata.bind = self.engine
        self.repo_path = migration._find_migrate_repo()
        self.schema = versioning_api.ControlledSchema.create(self.engine,
                                                             self.repo_path, 0)

    def tearDown(self):
        super(SqlUpgradeTests, self).tearDown()

    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_start_version_0(self):
        version = migration.db_version()
        self.assertEqual(version, 0, "DB is at version 0")

    def assertTableColumns(self, table_name, expected_cols):
        """Asserts that the table contains the expected set of columns."""
        table = self.select_table(table_name)
        actual_cols = [col.name for col in table.columns]
        self.assertEqual(expected_cols, actual_cols, '%s table' % table_name)

    def test_upgrade_0_to_1(self):
        self.upgrade(1)
        self.assertTableColumns("user", ["id", "name", "extra"])
        self.assertTableColumns("tenant", ["id", "name", "extra"])
        self.assertTableColumns("role", ["id", "name"])
        self.assertTableColumns("user_tenant_membership",
                                ["user_id", "tenant_id"])
        self.assertTableColumns("metadata", ["user_id", "tenant_id", "data"])
        self.populate_user_table()

    def test_upgrade_5_to_6(self):
        self.upgrade(5)
        self.assertTableDoesNotExist('policy')

        self.upgrade(6)
        self.assertTableExists('policy')
        self.assertTableColumns('policy', ['id', 'type', 'blob', 'extra'])

    def test_upgrade_7_to_9(self):
        self.upgrade(7)
        self.populate_user_table()
        self.populate_tenant_table()
        self.upgrade(9)
        self.assertTableColumns("user",
                                ["id", "name", "extra", "password",
                                 "enabled"])
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

    def test_downgrade_9_to_7(self):
        self.upgrade(9)
        self.downgrade(7)

    def test_upgrade_9_to_12(self):
        self.upgrade(9)

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

        self.upgrade(12)

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

    def test_upgrade_12_to_13(self):
        self.upgrade(12)
        self.upgrade(13)
        self.assertTableExists('group')
        self.assertTableExists('group_project_metadata')
        self.assertTableExists('group_domain_metadata')
        self.assertTableExists('user_group_membership')

    def test_downgrade_13_to_12(self):
        self.upgrade(13)
        self.downgrade(12)
        self.assertTableDoesNotExist('group')
        self.assertTableDoesNotExist('group_project_metadata')
        self.assertTableDoesNotExist('group_domain_metadata')
        self.assertTableDoesNotExist('user_group_membership')

    def test_downgrade_12_to_9(self):
        self.upgrade(12)

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

        self.downgrade(8)

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

    def insert_dict(self, session, table_name, d):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        session.execute(
            'INSERT INTO `%s` (%s) VALUES (%s)' % (
                table_name,
                ', '.join('%s' % k for k in d.keys()),
                ', '.join("'%s'" % v for v in d.values())))

    def test_downgrade_to_0(self):
        self.upgrade(13)
        self.downgrade(0)
        for table_name in ["user", "token", "role", "user_tenant_membership",
                           "metadata"]:
            self.assertTableDoesNotExist(table_name)

    def test_upgrade_6_to_7(self):
        self.upgrade(6)
        self.assertTableDoesNotExist('credential')
        self.assertTableDoesNotExist('domain')
        self.assertTableDoesNotExist('user_domain_metadata')

        self.upgrade(7)
        self.assertTableExists('credential')
        self.assertTableColumns('credential', ['id', 'user_id', 'project_id',
                                               'blob', 'type', 'extra'])
        self.assertTableExists('domain')
        self.assertTableColumns('domain', ['id', 'name', 'extra'])
        self.assertTableExists('user_domain_metadata')
        self.assertTableColumns('user_domain_metadata',
                                ['user_id', 'domain_id', 'data'])

    def populate_user_table(self):
        for user in default_fixtures.USERS:
            extra = copy.deepcopy(user)
            extra.pop('id')
            extra.pop('name')
            self.engine.execute("insert into user values ('%s', '%s', '%s')"
                                % (user['id'],
                                   user['name'],
                                   json.dumps(extra)))

    def populate_tenant_table(self):
        for tenant in default_fixtures.TENANTS:
            extra = copy.deepcopy(tenant)
            extra.pop('id')
            extra.pop('name')
            self.engine.execute("insert into tenant values ('%s', '%s', '%s')"
                                % (tenant['id'],
                                   tenant['name'],
                                   json.dumps(extra)))

    def select_table(self, name):
        table = sqlalchemy.Table(name,
                                 self.metadata,
                                 autoload=True)
        s = sqlalchemy.select([table])
        return s

    def assertTableExists(self, table_name):
        """Asserts that a given table exists can be selected by name."""
        try:
            self.select_table(table_name)
        except sqlalchemy.exc.NoSuchTableError:
            raise AssertionError('Table "%s" does not exist' % table_name)

    def assertTableDoesNotExist(self, table_name):
        """Asserts that a given table exists cannot be selected by name."""
        try:
            self.assertTableExists(table_name)
        except AssertionError:
            pass
        else:
            raise AssertionError('Table "%s" already exists' % table_name)

    def upgrade(self, *args, **kwargs):
        self._migrate(*args, **kwargs)

    def downgrade(self, *args, **kwargs):
        self._migrate(*args, downgrade=True, **kwargs)

    def _migrate(self, version, repository=None, downgrade=False):
        repository = repository or self.repo_path
        err = ''
        version = versioning_api._migrate_version(self.schema,
                                                  version,
                                                  not downgrade,
                                                  err)
        changeset = self.schema.changeset(version)
        for ver, change in changeset:
            self.schema.runchange(ver, change, changeset.step)
        self.assertEqual(self.schema.version, version)
