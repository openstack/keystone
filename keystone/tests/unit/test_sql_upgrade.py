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

1. Modify the file ``keystone/tests/unit/config_files/backend_sql.conf`` to use
   the connection for your live database.
2. Set up a blank, live database
3. Run the tests using::

    tox -e py27 -- keystone.tests.unit.test_sql_upgrade

WARNING::

    Your database will be wiped.

    Do not do this against a database with valuable data as
    all data will be lost.
"""

import copy
import json
import uuid

from migrate.versioning import api as versioning_api
from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import migration
from oslo_db.sqlalchemy import session as db_session
from sqlalchemy.engine import reflection
import sqlalchemy.exc
from sqlalchemy import schema

from keystone.common import sql
from keystone.common.sql import migrate_repo
from keystone.common.sql import migration_helpers
from keystone.contrib import federation
from keystone.contrib import revoke
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id

# NOTE(morganfainberg): This should be updated when each DB migration collapse
# is done to mirror the expected structure of the DB in the format of
# { <DB_TABLE_NAME>: [<COLUMN>, <COLUMN>, ...], ... }
INITIAL_TABLE_STRUCTURE = {
    'credential': [
        'id', 'user_id', 'project_id', 'blob', 'type', 'extra',
    ],
    'domain': [
        'id', 'name', 'enabled', 'extra',
    ],
    'endpoint': [
        'id', 'legacy_endpoint_id', 'interface', 'region', 'service_id', 'url',
        'enabled', 'extra',
    ],
    'group': [
        'id', 'domain_id', 'name', 'description', 'extra',
    ],
    'policy': [
        'id', 'type', 'blob', 'extra',
    ],
    'project': [
        'id', 'name', 'extra', 'description', 'enabled', 'domain_id',
    ],
    'role': [
        'id', 'name', 'extra',
    ],
    'service': [
        'id', 'type', 'extra', 'enabled',
    ],
    'token': [
        'id', 'expires', 'extra', 'valid', 'trust_id', 'user_id',
    ],
    'trust': [
        'id', 'trustor_user_id', 'trustee_user_id', 'project_id',
        'impersonation', 'deleted_at', 'expires_at', 'remaining_uses', 'extra',
    ],
    'trust_role': [
        'trust_id', 'role_id',
    ],
    'user': [
        'id', 'name', 'extra', 'password', 'enabled', 'domain_id',
        'default_project_id',
    ],
    'user_group_membership': [
        'user_id', 'group_id',
    ],
    'region': [
        'id', 'description', 'parent_region_id', 'extra',
    ],
    'assignment': [
        'type', 'actor_id', 'target_id', 'role_id', 'inherited',
    ],
}


INITIAL_EXTENSION_TABLE_STRUCTURE = {
    'revocation_event': [
        'id', 'domain_id', 'project_id', 'user_id', 'role_id',
        'trust_id', 'consumer_id', 'access_token_id',
        'issued_before', 'expires_at', 'revoked_at', 'audit_id',
        'audit_chain_id',
    ],
}

EXTENSIONS = {'federation': federation,
              'revoke': revoke}


class SqlMigrateBase(unit.SQLDriverOverrides, unit.TestCase):
    def initialize_sql(self):
        self.metadata = sqlalchemy.MetaData()
        self.metadata.bind = self.engine

    def config_files(self):
        config_files = super(SqlMigrateBase, self).config_files()
        config_files.append(unit.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def repo_package(self):
        return sql

    def setUp(self):
        super(SqlMigrateBase, self).setUp()
        database.initialize_sql_session()
        conn_str = CONF.database.connection
        if (conn_str != unit.IN_MEM_DB_CONN_STRING and
                conn_str.startswith('sqlite') and
                conn_str[10:] == unit.DEFAULT_TEST_DB_FILE):
            # Override the default with a DB that is specific to the migration
            # tests only if the DB Connection string is the same as the global
            # default. This is required so that no conflicts occur due to the
            # global default DB already being under migrate control. This is
            # only needed if the DB is not-in-memory
            db_file = unit.dirs.tmp('keystone_migrate_test.db')
            self.config_fixture.config(
                group='database',
                connection='sqlite:///%s' % db_file)

        # create and share a single sqlalchemy engine for testing
        self.engine = sql.get_engine()
        self.Session = db_session.get_maker(self.engine, autocommit=False)
        self.addCleanup(sqlalchemy.orm.session.Session.close_all)

        self.initialize_sql()
        self.repo_path = migration_helpers.find_migrate_repo(
            self.repo_package())
        self.schema = versioning_api.ControlledSchema.create(
            self.engine,
            self.repo_path, self.initial_db_version)

        # auto-detect the highest available schema version in the migrate_repo
        self.max_version = self.schema.repository.version().version

        self.addCleanup(sql.cleanup)

        # drop tables and FKs.
        self.addCleanup(self._cleanupDB)

    def _cleanupDB(self):
        meta = sqlalchemy.MetaData()
        meta.bind = self.engine
        meta.reflect(self.engine)

        with self.engine.begin() as conn:
            inspector = reflection.Inspector.from_engine(self.engine)
            metadata = schema.MetaData()
            tbs = []
            all_fks = []

            for table_name in inspector.get_table_names():
                fks = []
                for fk in inspector.get_foreign_keys(table_name):
                    if not fk['name']:
                        continue
                    fks.append(
                        schema.ForeignKeyConstraint((), (), name=fk['name']))
                table = schema.Table(table_name, metadata, *fks)
                tbs.append(table)
                all_fks.extend(fks)

            for fkc in all_fks:
                if self.engine.name != 'sqlite':
                    conn.execute(schema.DropConstraint(fkc))

            for table in tbs:
                conn.execute(schema.DropTable(table))

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
        # Check if the columns are equal, but allow for a different order,
        # which might occur after an upgrade followed by a downgrade
        self.assertItemsEqual(expected_cols, actual_cols,
                              '%s table' % table_name)

    @property
    def initial_db_version(self):
        return getattr(self, '_initial_db_version', 0)


class SqlUpgradeTests(SqlMigrateBase):

    _initial_db_version = migrate_repo.DB_INIT_VERSION

    def test_blank_db_to_start(self):
        self.assertTableDoesNotExist('user')

    def test_start_version_db_init_version(self):
        version = migration.db_version(sql.get_engine(), self.repo_path,
                                       migrate_repo.DB_INIT_VERSION)
        self.assertEqual(
            migrate_repo.DB_INIT_VERSION,
            version,
            'DB is not at version %s' % migrate_repo.DB_INIT_VERSION)

    def test_upgrade_add_initial_tables(self):
        self.upgrade(migrate_repo.DB_INIT_VERSION + 1)
        self.check_initial_table_structure()

    def check_initial_table_structure(self):
        for table in INITIAL_TABLE_STRUCTURE:
            self.assertTableColumns(table, INITIAL_TABLE_STRUCTURE[table])

        # Ensure the default domain was properly created.
        default_domain = migration_helpers.get_default_domain()

        meta = sqlalchemy.MetaData()
        meta.bind = self.engine

        domain_table = sqlalchemy.Table('domain', meta, autoload=True)

        session = self.Session()
        q = session.query(domain_table)
        refs = q.all()

        self.assertEqual(1, len(refs))
        for k in default_domain.keys():
            self.assertEqual(default_domain[k], getattr(refs[0], k))

    def insert_dict(self, session, table_name, d, table=None):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        if table is None:
            this_table = sqlalchemy.Table(table_name, self.metadata,
                                          autoload=True)
        else:
            this_table = table
        insert = this_table.insert().values(**d)
        session.execute(insert)
        session.commit()

    def test_id_mapping(self):
        self.upgrade(50)
        self.assertTableDoesNotExist('id_mapping')
        self.upgrade(51)
        self.assertTableExists('id_mapping')

    def test_region_url_upgrade(self):
        self.upgrade(52)
        self.assertTableColumns('region',
                                ['id', 'description', 'parent_region_id',
                                 'extra', 'url'])

    def test_endpoint_region_upgrade_columns(self):
        self.upgrade(53)
        self.assertTableColumns('endpoint',
                                ['id', 'legacy_endpoint_id', 'interface',
                                 'service_id', 'url', 'extra', 'enabled',
                                 'region_id'])
        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(255, region_table.c.id.type.length)
        self.assertEqual(255, region_table.c.parent_region_id.type.length)
        endpoint_table = sqlalchemy.Table('endpoint',
                                          self.metadata,
                                          autoload=True)
        self.assertEqual(255, endpoint_table.c.region_id.type.length)

    def test_endpoint_region_migration(self):
        self.upgrade(52)
        session = self.Session()
        _small_region_name = '0' * 30
        _long_region_name = '0' * 255
        _clashing_region_name = '0' * 70

        def add_service():
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex
            }

            self.insert_dict(session, 'service', service)

            return service_id

        def add_endpoint(service_id, region):
            endpoint_id = uuid.uuid4().hex

            endpoint = {
                'id': endpoint_id,
                'interface': uuid.uuid4().hex[:8],
                'service_id': service_id,
                'url': uuid.uuid4().hex,
                'region': region
            }
            self.insert_dict(session, 'endpoint', endpoint)

            return endpoint_id

        _service_id_ = add_service()
        add_endpoint(_service_id_, region=_long_region_name)
        add_endpoint(_service_id_, region=_long_region_name)
        add_endpoint(_service_id_, region=_clashing_region_name)
        add_endpoint(_service_id_, region=_small_region_name)
        add_endpoint(_service_id_, region=None)

        # upgrade to 53
        session.close()
        self.upgrade(53)
        session = self.Session()
        self.metadata.clear()

        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(1, session.query(region_table).
                         filter_by(id=_long_region_name).count())
        self.assertEqual(1, session.query(region_table).
                         filter_by(id=_clashing_region_name).count())
        self.assertEqual(1, session.query(region_table).
                         filter_by(id=_small_region_name).count())

        endpoint_table = sqlalchemy.Table('endpoint',
                                          self.metadata,
                                          autoload=True)
        self.assertEqual(5, session.query(endpoint_table).count())
        self.assertEqual(2, session.query(endpoint_table).
                         filter_by(region_id=_long_region_name).count())
        self.assertEqual(1, session.query(endpoint_table).
                         filter_by(region_id=_clashing_region_name).count())
        self.assertEqual(1, session.query(endpoint_table).
                         filter_by(region_id=_small_region_name).count())

    def test_add_actor_id_index(self):
        self.upgrade(53)
        self.upgrade(54)
        table = sqlalchemy.Table('assignment', self.metadata, autoload=True)
        index_data = [(idx.name, list(idx.columns.keys()))
                      for idx in table.indexes]
        self.assertIn(('ix_actor_id', ['actor_id']), index_data)

    def test_token_user_id_and_trust_id_index_upgrade(self):
        self.upgrade(54)
        self.upgrade(55)
        table = sqlalchemy.Table('token', self.metadata, autoload=True)
        index_data = [(idx.name, list(idx.columns.keys()))
                      for idx in table.indexes]
        self.assertIn(('ix_token_user_id', ['user_id']), index_data)
        self.assertIn(('ix_token_trust_id', ['trust_id']), index_data)

    def test_project_parent_id_upgrade(self):
        self.upgrade(61)
        self.assertTableColumns('project',
                                ['id', 'name', 'extra', 'description',
                                 'enabled', 'domain_id', 'parent_id'])

    def test_drop_assignment_role_fk(self):
        self.upgrade(61)
        self.assertTrue(self.does_fk_exist('assignment', 'role_id'))
        self.upgrade(62)
        if self.engine.name != 'sqlite':
            # sqlite does not support FK deletions (or enforcement)
            self.assertFalse(self.does_fk_exist('assignment', 'role_id'))

    def test_insert_assignment_inherited_pk(self):
        ASSIGNMENT_TABLE_NAME = 'assignment'
        INHERITED_COLUMN_NAME = 'inherited'
        ROLE_TABLE_NAME = 'role'

        self.upgrade(72)

        # Check that the 'inherited' column is not part of the PK
        self.assertFalse(self.does_pk_exist(ASSIGNMENT_TABLE_NAME,
                                            INHERITED_COLUMN_NAME))

        session = self.Session()

        role = {'id': uuid.uuid4().hex,
                'name': uuid.uuid4().hex}
        self.insert_dict(session, ROLE_TABLE_NAME, role)

        # Create both inherited and noninherited role assignments
        inherited = {'type': 'UserProject',
                     'actor_id': uuid.uuid4().hex,
                     'target_id': uuid.uuid4().hex,
                     'role_id': role['id'],
                     'inherited': True}

        noninherited = inherited.copy()
        noninherited['inherited'] = False

        # Create another inherited role assignment as a spoiler
        spoiler = inherited.copy()
        spoiler['actor_id'] = uuid.uuid4().hex

        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, inherited)
        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, spoiler)

        # Since 'inherited' is not part of the PK, we can't insert noninherited
        self.assertRaises(db_exception.DBDuplicateEntry,
                          self.insert_dict,
                          session,
                          ASSIGNMENT_TABLE_NAME,
                          noninherited)

        session.close()

        self.upgrade(73)

        session = self.Session()
        self.metadata.clear()

        # Check that the 'inherited' column is now part of the PK
        self.assertTrue(self.does_pk_exist(ASSIGNMENT_TABLE_NAME,
                                           INHERITED_COLUMN_NAME))

        # The noninherited role assignment can now be inserted
        self.insert_dict(session, ASSIGNMENT_TABLE_NAME, noninherited)

        assignment_table = sqlalchemy.Table(ASSIGNMENT_TABLE_NAME,
                                            self.metadata,
                                            autoload=True)

        assignments = session.query(assignment_table).all()
        for assignment in (inherited, spoiler, noninherited):
            self.assertIn((assignment['type'], assignment['actor_id'],
                           assignment['target_id'], assignment['role_id'],
                           assignment['inherited']),
                          assignments)

    def does_pk_exist(self, table, pk_column):
        """Checks whether a column is primary key on a table."""

        inspector = reflection.Inspector.from_engine(self.engine)
        pk_columns = inspector.get_pk_constraint(table)['constrained_columns']

        return pk_column in pk_columns

    def does_fk_exist(self, table, fk_column):
        inspector = reflection.Inspector.from_engine(self.engine)
        for fk in inspector.get_foreign_keys(table):
            if fk_column in fk['constrained_columns']:
                return True
        return False

    def test_drop_region_url_upgrade(self):
        self.upgrade(63)
        self.assertTableColumns('region',
                                ['id', 'description', 'parent_region_id',
                                 'extra'])

    def test_domain_fk(self):
        self.upgrade(63)
        self.assertTrue(self.does_fk_exist('group', 'domain_id'))
        self.assertTrue(self.does_fk_exist('user', 'domain_id'))
        self.upgrade(64)
        if self.engine.name != 'sqlite':
            # sqlite does not support FK deletions (or enforcement)
            self.assertFalse(self.does_fk_exist('group', 'domain_id'))
            self.assertFalse(self.does_fk_exist('user', 'domain_id'))

    def test_add_domain_config(self):
        whitelisted_table = 'whitelisted_config'
        sensitive_table = 'sensitive_config'
        self.upgrade(64)
        self.assertTableDoesNotExist(whitelisted_table)
        self.assertTableDoesNotExist(sensitive_table)
        self.upgrade(65)
        self.assertTableColumns(whitelisted_table,
                                ['domain_id', 'group', 'option', 'value'])
        self.assertTableColumns(sensitive_table,
                                ['domain_id', 'group', 'option', 'value'])

    def test_fixup_service_name_value_upgrade(self):
        """Update service name data from `extra` to empty string."""
        def add_service(**extra_data):
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex,
                'extra': json.dumps(extra_data),
            }

            self.insert_dict(session, 'service', service)

            return service_id

        self.upgrade(65)
        session = self.Session()

        # Services with extra values having a random attribute and
        # different combinations of name
        random_attr_name = uuid.uuid4().hex
        random_attr_value = uuid.uuid4().hex
        random_attr_str = "%s='%s'" % (random_attr_name, random_attr_value)
        random_attr_no_name = {random_attr_name: random_attr_value}
        random_attr_no_name_str = "%s='%s'" % (random_attr_name,
                                               random_attr_value)
        random_attr_name_value = {random_attr_name: random_attr_value,
                                  'name': 'myname'}
        random_attr_name_value_str = 'name=myname,%s' % random_attr_str
        random_attr_name_empty = {random_attr_name: random_attr_value,
                                  'name': ''}
        random_attr_name_empty_str = 'name=,%s' % random_attr_str
        random_attr_name_none = {random_attr_name: random_attr_value,
                                 'name': None}
        random_attr_name_none_str = 'name=None,%s' % random_attr_str

        services = [
            (add_service(**random_attr_no_name),
             random_attr_name_empty, random_attr_no_name_str),
            (add_service(**random_attr_name_value),
             random_attr_name_value, random_attr_name_value_str),
            (add_service(**random_attr_name_empty),
             random_attr_name_empty, random_attr_name_empty_str),
            (add_service(**random_attr_name_none),
             random_attr_name_empty, random_attr_name_none_str),
        ]

        # NOTE(viktors): Add a service with empty extra field
        self.insert_dict(session, 'service',
                         {'id': uuid.uuid4().hex, 'type': uuid.uuid4().hex})

        session.close()
        self.upgrade(66)
        session = self.Session()

        # Verify that the services have the expected values.
        self.metadata.clear()
        service_table = sqlalchemy.Table('service', self.metadata,
                                         autoload=True)

        def fetch_service_extra(service_id):
            cols = [service_table.c.extra]
            f = service_table.c.id == service_id
            s = sqlalchemy.select(cols).where(f)
            service = session.execute(s).fetchone()
            return json.loads(service.extra)

        for service_id, exp_extra, msg in services:
            extra = fetch_service_extra(service_id)
            self.assertDictEqual(exp_extra, extra, msg)

    def _does_index_exist(self, table_name, index_name):
        meta = sqlalchemy.MetaData(bind=self.engine)
        table = sqlalchemy.Table('assignment', meta, autoload=True)
        return index_name in [idx.name for idx in table.indexes]

    def test_drop_assignment_role_id_index_mysql(self):
        self.upgrade(66)
        if self.engine.name == "mysql":
            self.assertTrue(self._does_index_exist('assignment',
                                                   'assignment_role_id_fkey'))
        self.upgrade(67)
        if self.engine.name == "mysql":
            self.assertFalse(self._does_index_exist('assignment',
                                                    'assignment_role_id_fkey'))

    def test_project_is_domain_upgrade(self):
        self.upgrade(74)
        self.assertTableColumns('project',
                                ['id', 'name', 'extra', 'description',
                                 'enabled', 'domain_id', 'parent_id',
                                 'is_domain'])

    def test_add_config_registration(self):
        config_registration = 'config_register'
        self.upgrade(74)
        self.assertTableDoesNotExist(config_registration)
        self.upgrade(75)
        self.assertTableColumns(config_registration, ['type', 'domain_id'])

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
        self.assertEqual([], names,
                         "Non-InnoDB tables exist")

        connection.close()


class VersionTests(SqlMigrateBase):

    _initial_db_version = migrate_repo.DB_INIT_VERSION

    def test_core_initial(self):
        """Get the version before migrated, it's the initial DB version."""
        version = migration_helpers.get_db_version()
        self.assertEqual(migrate_repo.DB_INIT_VERSION, version)

    def test_core_max(self):
        """When get the version after upgrading, it's the new version."""
        self.upgrade(self.max_version)
        version = migration_helpers.get_db_version()
        self.assertEqual(self.max_version, version)

    def test_assert_not_schema_downgrade(self):
        self.upgrade(self.max_version)
        self.assertRaises(
            db_exception.DbMigrationError,
            migration_helpers._sync_common_repo,
            self.max_version - 1)

    def test_extension_not_controlled(self):
        """When get the version before controlling, raises DbMigrationError."""
        self.assertRaises(db_exception.DbMigrationError,
                          migration_helpers.get_db_version,
                          extension='federation')

    def test_extension_initial(self):
        """When get the initial version of an extension, it's 0."""
        for name, extension in EXTENSIONS.items():
            abs_path = migration_helpers.find_migrate_repo(extension)
            migration.db_version_control(sql.get_engine(), abs_path)
            version = migration_helpers.get_db_version(extension=name)
            self.assertEqual(0, version,
                             'Migrate version for %s is not 0' % name)

    def test_extension_migrated(self):
        """When get the version after migrating an extension, it's not 0."""
        for name, extension in EXTENSIONS.items():
            abs_path = migration_helpers.find_migrate_repo(extension)
            migration.db_version_control(sql.get_engine(), abs_path)
            migration.db_sync(sql.get_engine(), abs_path)
            version = migration_helpers.get_db_version(extension=name)
            self.assertTrue(
                version > 0,
                "Version for %s didn't change after migrated?" % name)
            # Verify downgrades cannot occur
            self.assertRaises(
                db_exception.DbMigrationError,
                migration_helpers._sync_extension_repo,
                extension=name,
                version=0)

    def test_extension_federation_upgraded_values(self):
        abs_path = migration_helpers.find_migrate_repo(federation)
        migration.db_version_control(sql.get_engine(), abs_path)
        migration.db_sync(sql.get_engine(), abs_path, version=6)
        idp_table = sqlalchemy.Table("identity_provider",
                                     self.metadata,
                                     autoload=True)
        idps = [{'id': uuid.uuid4().hex,
                 'enabled': True,
                 'description': uuid.uuid4().hex,
                 'remote_id': uuid.uuid4().hex},
                {'id': uuid.uuid4().hex,
                 'enabled': True,
                 'description': uuid.uuid4().hex,
                 'remote_id': uuid.uuid4().hex}]
        for idp in idps:
            ins = idp_table.insert().values({'id': idp['id'],
                                             'enabled': idp['enabled'],
                                             'description': idp['description'],
                                             'remote_id': idp['remote_id']})
            self.engine.execute(ins)
        migration.db_sync(sql.get_engine(), abs_path)
        idp_remote_ids_table = sqlalchemy.Table("idp_remote_ids",
                                                self.metadata,
                                                autoload=True)
        for idp in idps:
            s = idp_remote_ids_table.select().where(
                idp_remote_ids_table.c.idp_id == idp['id'])
            remote = self.engine.execute(s).fetchone()
            self.assertEqual(idp['remote_id'],
                             remote['remote_id'],
                             'remote_ids must be preserved during the '
                             'migration from identity_provider table to '
                             'idp_remote_ids table')

    def test_unexpected_extension(self):
        """The version for an extension that doesn't exist raises ImportError.

        """

        extension_name = uuid.uuid4().hex
        self.assertRaises(ImportError,
                          migration_helpers.get_db_version,
                          extension=extension_name)

    def test_unversioned_extension(self):
        """The version for extensions without migrations raise an exception.

        """

        self.assertRaises(exception.MigrationNotProvided,
                          migration_helpers.get_db_version,
                          extension='admin_crud')

    def test_initial_with_extension_version_None(self):
        """When performing a default migration, also migrate extensions."""
        migration_helpers.sync_database_to_version(extension=None,
                                                   version=None)
        for table in INITIAL_EXTENSION_TABLE_STRUCTURE:
            self.assertTableColumns(table,
                                    INITIAL_EXTENSION_TABLE_STRUCTURE[table])

    def test_initial_with_extension_version_max(self):
        """When migrating to max version, do not migrate extensions."""
        migration_helpers.sync_database_to_version(extension=None,
                                                   version=self.max_version)
        for table in INITIAL_EXTENSION_TABLE_STRUCTURE:
            self.assertTableDoesNotExist(table)
