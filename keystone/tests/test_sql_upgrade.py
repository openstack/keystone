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

1. Modify the file ``keystone/tests/backend_sql.conf`` to use the connection
   for your live database
2. Set up a blank, live database
3. Run the tests using::

    tox keystone.tests.test_sql_upgrade

WARNING::

    Your database will be wiped.

    Do not do this against a database with valuable data as all data will be
    lost.
"""

import copy
import json
import uuid

from migrate.versioning import api as versioning_api
from oslo.db import exception as db_exception
from oslo.db.sqlalchemy import migration
from oslo.db.sqlalchemy import session as db_session
import six
from sqlalchemy.engine import reflection
import sqlalchemy.exc
from sqlalchemy import schema

from keystone.assignment.backends import sql as assignment_sql
from keystone.common import sql
from keystone.common.sql import migrate_repo
from keystone.common.sql import migration_helpers
from keystone import config
from keystone.contrib import federation
from keystone.contrib import revoke
from keystone import exception
from keystone import tests
from keystone.tests import default_fixtures
from keystone.tests.ksfixtures import database


CONF = config.CONF
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
        'extra',
    ],
    'group': [
        'id', 'domain_id', 'name', 'description', 'extra',
    ],
    'group_domain_metadata': [
        'group_id', 'domain_id', 'data',
    ],
    'group_project_metadata': [
        'group_id', 'project_id', 'data',
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
        'id', 'type', 'extra',
    ],
    'token': [
        'id', 'expires', 'extra', 'valid', 'trust_id', 'user_id',
    ],
    'trust': [
        'id', 'trustor_user_id', 'trustee_user_id', 'project_id',
        'impersonation', 'deleted_at', 'expires_at', 'extra',
    ],
    'trust_role': [
        'trust_id', 'role_id',
    ],
    'user': [
        'id', 'name', 'extra', 'password', 'enabled', 'domain_id',
        'default_project_id',
    ],
    'user_domain_metadata': [
        'user_id', 'domain_id', 'data',
    ],
    'user_group_membership': [
        'user_id', 'group_id',
    ],
    'user_project_metadata': [
        'user_id', 'project_id', 'data',
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


class SqlMigrateBase(tests.SQLDriverOverrides, tests.TestCase):
    def initialize_sql(self):
        self.metadata = sqlalchemy.MetaData()
        self.metadata.bind = self.engine

    def config_files(self):
        config_files = super(SqlMigrateBase, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def repo_package(self):
        return sql

    def setUp(self):
        super(SqlMigrateBase, self).setUp()
        database.initialize_sql_session()
        conn_str = CONF.database.connection
        if (conn_str != tests.IN_MEM_DB_CONN_STRING and
                conn_str.startswith('sqlite') and
                conn_str[10:] == tests.DEFAULT_TEST_DB_FILE):
            # Override the default with a DB that is specific to the migration
            # tests only if the DB Connection string is the same as the global
            # default. This is required so that no conflicts occur due to the
            # global default DB already being under migrate control. This is
            # only needed if the DB is not-in-memory
            db_file = tests.dirs.tmp('keystone_migrate_test.db')
            self.config_fixture.config(
                group='database',
                connection='sqlite:///%s' % db_file)

        # create and share a single sqlalchemy engine for testing
        self.engine = sql.get_engine()
        self.Session = db_session.get_maker(self.engine, autocommit=False)

        self.initialize_sql()
        self.repo_path = migration_helpers.find_migrate_repo(
            self.repo_package())
        self.schema = versioning_api.ControlledSchema.create(
            self.engine,
            self.repo_path, self.initial_db_version)

        # auto-detect the highest available schema version in the migrate_repo
        self.max_version = self.schema.repository.version().version

    def tearDown(self):
        sqlalchemy.orm.session.Session.close_all()
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
                conn.execute(schema.DropConstraint(fkc))

            for table in tbs:
                conn.execute(schema.DropTable(table))

        sql.cleanup()
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
        # Check if the columns are equal, but allow for a different order,
        # which might occur after an upgrade followed by a downgrade
        self.assertEqual(expected_cols.sort(), actual_cols.sort(),
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
            version,
            migrate_repo.DB_INIT_VERSION,
            'DB is not at version %s' % migrate_repo.DB_INIT_VERSION)

    def test_two_steps_forward_one_step_back(self):
        """You should be able to cleanly undo and re-apply all upgrades.

        Upgrades are run in the following order::

            Starting with the initial version defined at
            keystone.common.migrate_repo.DB_INIT_VERSION

            INIT +1 -> INIT +2 -> INIT +1 -> INIT +2 -> INIT +3 -> INIT +2 ...
            ^---------------------^          ^---------------------^

        Downgrade to the DB_INIT_VERSION does not occur based on the
        requirement that the base version be DB_INIT_VERSION + 1 before
        migration can occur. Downgrade below DB_INIT_VERSION + 1 is no longer
        supported.

        DB_INIT_VERSION is the number preceding the release schema version from
        two releases prior. Example, Juno releases with the DB_INIT_VERSION
        being 35 where Havana (Havana was two releases before Juno) release
        schema version is 36.

        The migrate utility requires the db must be initialized under version
        control with the revision directly before the first version to be
        applied.

        """
        for x in range(migrate_repo.DB_INIT_VERSION + 1,
                       self.max_version + 1):
            self.upgrade(x)
            downgrade_ver = x - 1
            # Don't actually downgrade to the init version. This will raise
            # a not-implemented error.
            if downgrade_ver != migrate_repo.DB_INIT_VERSION:
                self.downgrade(x - 1)
            self.upgrade(x)

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

    def test_downgrade_to_db_init_version(self):
        self.upgrade(self.max_version)

        if self.engine.name == 'mysql':
            self._mysql_check_all_tables_innodb()

        self.downgrade(migrate_repo.DB_INIT_VERSION + 1)
        self.check_initial_table_structure()

        meta = sqlalchemy.MetaData()
        meta.bind = self.engine
        meta.reflect(self.engine)

        initial_table_set = set(INITIAL_TABLE_STRUCTURE.keys())
        table_set = set(meta.tables.keys())
        # explicitly remove the migrate_version table, this is not controlled
        # by the migration scripts and should be exempt from this check.
        table_set.remove('migrate_version')

        self.assertSetEqual(initial_table_set, table_set)
        # Downgrade to before Havana's release schema version (036) is not
        # supported. A NotImplementedError should be raised when attempting to
        # downgrade.
        self.assertRaises(NotImplementedError, self.downgrade,
                          migrate_repo.DB_INIT_VERSION)

    def insert_dict(self, session, table_name, d, table=None):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        if table is None:
            this_table = sqlalchemy.Table(table_name, self.metadata,
                                          autoload=True)
        else:
            this_table = table
        insert = this_table.insert()
        insert.execute(d)
        session.commit()

    def test_region_migration(self):
        self.assertTableDoesNotExist('region')
        self.upgrade(37)
        self.assertTableExists('region')
        self.downgrade(36)
        self.assertTableDoesNotExist('region')

    def test_assignment_table_migration(self):

        def create_base_data(session):
            domain_table = sqlalchemy.Table('domain', self.metadata,
                                            autoload=True)
            user_table = sqlalchemy.Table('user', self.metadata, autoload=True)
            group_table = sqlalchemy.Table('group', self.metadata,
                                           autoload=True)
            role_table = sqlalchemy.Table('role', self.metadata, autoload=True)
            project_table = sqlalchemy.Table(
                'project', self.metadata, autoload=True)

            base_data = {}
            # Create a Domain
            base_data['domain'] = {'id': uuid.uuid4().hex,
                                   'name': uuid.uuid4().hex,
                                   'enabled': True}
            session.execute(domain_table.insert().values(base_data['domain']))

            # Create another Domain
            base_data['domain2'] = {'id': uuid.uuid4().hex,
                                    'name': uuid.uuid4().hex,
                                    'enabled': True}
            session.execute(domain_table.insert().values(base_data['domain2']))

            # Create a Project
            base_data['project'] = {'id': uuid.uuid4().hex,
                                    'name': uuid.uuid4().hex,
                                    'domain_id': base_data['domain']['id'],
                                    'extra': "{}"}
            session.execute(
                project_table.insert().values(base_data['project']))

            # Create another Project
            base_data['project2'] = {'id': uuid.uuid4().hex,
                                     'name': uuid.uuid4().hex,
                                     'domain_id': base_data['domain']['id'],
                                     'extra': "{}"}
            session.execute(
                project_table.insert().values(base_data['project2']))

            # Create a User
            base_data['user'] = {'id': uuid.uuid4().hex,
                                 'name': uuid.uuid4().hex,
                                 'domain_id': base_data['domain']['id'],
                                 'password': uuid.uuid4().hex,
                                 'enabled': True,
                                 'extra': "{}"}
            session.execute(user_table.insert().values(base_data['user']))

            # Create a Group
            base_data['group'] = {'id': uuid.uuid4().hex,
                                  'name': uuid.uuid4().hex,
                                  'domain_id': base_data['domain']['id'],
                                  'extra': "{}"}
            session.execute(group_table.insert().values(base_data['group']))

            # Create roles
            base_data['roles'] = []
            for _ in range(9):
                role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
                session.execute(role_table.insert().values(role))
                base_data['roles'].append(role)

            return base_data

        def populate_grants(session, base_data):

            user_project_table = sqlalchemy.Table(
                'user_project_metadata', self.metadata, autoload=True)
            user_domain_table = sqlalchemy.Table(
                'user_domain_metadata', self.metadata, autoload=True)
            group_project_table = sqlalchemy.Table(
                'group_project_metadata', self.metadata, autoload=True)
            group_domain_table = sqlalchemy.Table(
                'group_domain_metadata', self.metadata, autoload=True)

            # Grant a role to user on project
            grant = {'user_id': base_data['user']['id'],
                     'project_id': base_data['project']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][0]['id']}]})}
            session.execute(user_project_table.insert().values(grant))

            # Grant two roles to user on project2
            grant = {'user_id': base_data['user']['id'],
                     'project_id': base_data['project2']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][1]['id']},
                                    {'id': base_data['roles'][2]['id']}]})}
            session.execute(user_project_table.insert().values(grant))

            # Grant role to group on project
            grant = {'group_id': base_data['group']['id'],
                     'project_id': base_data['project']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][3]['id']}]})}
            session.execute(group_project_table.insert().values(grant))

            # Grant two roles to group on project2
            grant = {'group_id': base_data['group']['id'],
                     'project_id': base_data['project2']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][4]['id']},
                                    {'id': base_data['roles'][5]['id']}]})}
            session.execute(group_project_table.insert().values(grant))

            # Grant two roles to group on domain, one inherited, one not
            grant = {'group_id': base_data['group']['id'],
                     'domain_id': base_data['domain']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][6]['id']},
                                    {'id': base_data['roles'][7]['id'],
                                     'inherited_to': 'projects'}]})}
            session.execute(group_domain_table.insert().values(grant))

            # Grant inherited role to user on domain
            grant = {'user_id': base_data['user']['id'],
                     'domain_id': base_data['domain']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][8]['id'],
                                     'inherited_to': 'projects'}]})}
            session.execute(user_domain_table.insert().values(grant))

            # Grant two non-inherited roles to user on domain2, using roles
            # that are also assigned to other actors/targets
            grant = {'user_id': base_data['user']['id'],
                     'domain_id': base_data['domain2']['id'],
                     'data': json.dumps(
                         {'roles': [{'id': base_data['roles'][6]['id']},
                                    {'id': base_data['roles'][7]['id']}]})}
            session.execute(user_domain_table.insert().values(grant))

            session.commit()

        def check_grants(session, base_data):
            user_project_table = sqlalchemy.Table(
                'user_project_metadata', self.metadata, autoload=True)
            user_domain_table = sqlalchemy.Table(
                'user_domain_metadata', self.metadata, autoload=True)
            group_project_table = sqlalchemy.Table(
                'group_project_metadata', self.metadata, autoload=True)
            group_domain_table = sqlalchemy.Table(
                'group_domain_metadata', self.metadata, autoload=True)

            s = sqlalchemy.select([user_project_table.c.data]).where(
                (user_project_table.c.user_id == base_data['user']['id']) &
                (user_project_table.c.project_id ==
                 base_data['project']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(1, len(data['roles']))
            self.assertIn({'id': base_data['roles'][0]['id']}, data['roles'])

            s = sqlalchemy.select([user_project_table.c.data]).where(
                (user_project_table.c.user_id == base_data['user']['id']) &
                (user_project_table.c.project_id ==
                 base_data['project2']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(2, len(data['roles']))
            self.assertIn({'id': base_data['roles'][1]['id']}, data['roles'])
            self.assertIn({'id': base_data['roles'][2]['id']}, data['roles'])

            s = sqlalchemy.select([group_project_table.c.data]).where(
                (group_project_table.c.group_id == base_data['group']['id']) &
                (group_project_table.c.project_id ==
                 base_data['project']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(1, len(data['roles']))
            self.assertIn({'id': base_data['roles'][3]['id']}, data['roles'])

            s = sqlalchemy.select([group_project_table.c.data]).where(
                (group_project_table.c.group_id == base_data['group']['id']) &
                (group_project_table.c.project_id ==
                 base_data['project2']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(2, len(data['roles']))
            self.assertIn({'id': base_data['roles'][4]['id']}, data['roles'])
            self.assertIn({'id': base_data['roles'][5]['id']}, data['roles'])

            s = sqlalchemy.select([group_domain_table.c.data]).where(
                (group_domain_table.c.group_id == base_data['group']['id']) &
                (group_domain_table.c.domain_id == base_data['domain']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(2, len(data['roles']))
            self.assertIn({'id': base_data['roles'][6]['id']}, data['roles'])
            self.assertIn({'id': base_data['roles'][7]['id'],
                           'inherited_to': 'projects'}, data['roles'])

            s = sqlalchemy.select([user_domain_table.c.data]).where(
                (user_domain_table.c.user_id == base_data['user']['id']) &
                (user_domain_table.c.domain_id == base_data['domain']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(1, len(data['roles']))
            self.assertIn({'id': base_data['roles'][8]['id'],
                           'inherited_to': 'projects'}, data['roles'])

            s = sqlalchemy.select([user_domain_table.c.data]).where(
                (user_domain_table.c.user_id == base_data['user']['id']) &
                (user_domain_table.c.domain_id == base_data['domain2']['id']))
            r = session.execute(s)
            data = json.loads(r.fetchone()['data'])
            self.assertEqual(2, len(data['roles']))
            self.assertIn({'id': base_data['roles'][6]['id']}, data['roles'])
            self.assertIn({'id': base_data['roles'][7]['id']}, data['roles'])

        def check_assignments(session, base_data):

            def check_assignment_type(refs, type):
                for ref in refs:
                    self.assertEqual(type, ref.type)

            assignment_table = sqlalchemy.Table(
                'assignment', self.metadata, autoload=True)

            refs = session.query(assignment_table).all()
            self.assertEqual(11, len(refs))

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['user']['id'])
            q = q.filter_by(target_id=base_data['project']['id'])
            refs = q.all()
            self.assertEqual(1, len(refs))
            self.assertEqual(base_data['roles'][0]['id'], refs[0].role_id)
            self.assertFalse(refs[0].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.USER_PROJECT)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['user']['id'])
            q = q.filter_by(target_id=base_data['project2']['id'])
            refs = q.all()
            self.assertEqual(2, len(refs))
            role_ids = [base_data['roles'][1]['id'],
                        base_data['roles'][2]['id']]
            self.assertIn(refs[0].role_id, role_ids)
            self.assertIn(refs[1].role_id, role_ids)
            self.assertFalse(refs[0].inherited)
            self.assertFalse(refs[1].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.USER_PROJECT)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['group']['id'])
            q = q.filter_by(target_id=base_data['project']['id'])
            refs = q.all()
            self.assertEqual(1, len(refs))
            self.assertEqual(base_data['roles'][3]['id'], refs[0].role_id)
            self.assertFalse(refs[0].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.GROUP_PROJECT)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['group']['id'])
            q = q.filter_by(target_id=base_data['project2']['id'])
            refs = q.all()
            self.assertEqual(2, len(refs))
            role_ids = [base_data['roles'][4]['id'],
                        base_data['roles'][5]['id']]
            self.assertIn(refs[0].role_id, role_ids)
            self.assertIn(refs[1].role_id, role_ids)
            self.assertFalse(refs[0].inherited)
            self.assertFalse(refs[1].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.GROUP_PROJECT)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['group']['id'])
            q = q.filter_by(target_id=base_data['domain']['id'])
            refs = q.all()
            self.assertEqual(2, len(refs))
            role_ids = [base_data['roles'][6]['id'],
                        base_data['roles'][7]['id']]
            self.assertIn(refs[0].role_id, role_ids)
            self.assertIn(refs[1].role_id, role_ids)
            if refs[0].role_id == base_data['roles'][7]['id']:
                self.assertTrue(refs[0].inherited)
                self.assertFalse(refs[1].inherited)
            else:
                self.assertTrue(refs[1].inherited)
                self.assertFalse(refs[0].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.GROUP_DOMAIN)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['user']['id'])
            q = q.filter_by(target_id=base_data['domain']['id'])
            refs = q.all()
            self.assertEqual(1, len(refs))
            self.assertEqual(base_data['roles'][8]['id'], refs[0].role_id)
            self.assertTrue(refs[0].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.USER_DOMAIN)

            q = session.query(assignment_table)
            q = q.filter_by(actor_id=base_data['user']['id'])
            q = q.filter_by(target_id=base_data['domain2']['id'])
            refs = q.all()
            self.assertEqual(2, len(refs))
            role_ids = [base_data['roles'][6]['id'],
                        base_data['roles'][7]['id']]
            self.assertIn(refs[0].role_id, role_ids)
            self.assertIn(refs[1].role_id, role_ids)
            self.assertFalse(refs[0].inherited)
            self.assertFalse(refs[1].inherited)
            check_assignment_type(refs,
                                  assignment_sql.AssignmentType.USER_DOMAIN)

        self.upgrade(37)
        session = self.Session()
        self.assertTableDoesNotExist('assignment')
        base_data = create_base_data(session)
        populate_grants(session, base_data)
        check_grants(session, base_data)
        session.commit()
        session.close()
        self.upgrade(40)
        session = self.Session()
        self.assertTableExists('assignment')
        self.assertTableDoesNotExist('user_project_metadata')
        self.assertTableDoesNotExist('group_project_metadata')
        self.assertTableDoesNotExist('user_domain_metadata')
        self.assertTableDoesNotExist('group_domain_metadata')
        check_assignments(session, base_data)
        session.close()
        self.downgrade(37)
        session = self.Session()
        self.assertTableDoesNotExist('assignment')
        check_grants(session, base_data)
        session.close()

    def test_limited_trusts_upgrade(self):
        # make sure that the remaining_uses column is created
        self.upgrade(41)
        self.assertTableColumns('trust',
                                ['id', 'trustor_user_id',
                                 'trustee_user_id',
                                 'project_id', 'impersonation',
                                 'deleted_at',
                                 'expires_at', 'extra',
                                 'remaining_uses'])

    def test_limited_trusts_downgrade(self):
        # make sure that the remaining_uses column is removed
        self.upgrade(41)
        self.downgrade(40)
        self.assertTableColumns('trust',
                                ['id', 'trustor_user_id',
                                 'trustee_user_id',
                                 'project_id', 'impersonation',
                                 'deleted_at',
                                 'expires_at', 'extra'])

    def test_limited_trusts_downgrade_trusts_cleanup(self):
        # make sure that only trusts with unlimited uses are kept in the
        # downgrade
        self.upgrade(41)
        session = self.Session()
        limited_trust = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': True,
            'remaining_uses': 5
        }
        consumed_trust = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': True,
            'remaining_uses': 0
        }
        unlimited_trust = {
            'id': uuid.uuid4().hex,
            'trustor_user_id': uuid.uuid4().hex,
            'trustee_user_id': uuid.uuid4().hex,
            'project_id': uuid.uuid4().hex,
            'impersonation': True,
            'remaining_uses': None
        }
        self.insert_dict(session, 'trust', limited_trust)
        self.insert_dict(session, 'trust', consumed_trust)
        self.insert_dict(session, 'trust', unlimited_trust)
        trust_table = sqlalchemy.Table(
            'trust', self.metadata, autoload=True)
        # we should have 3 trusts in base
        self.assertEqual(3, session.query(trust_table).count())

        session.close()
        self.downgrade(40)
        session = self.Session()
        trust_table = sqlalchemy.Table(
            'trust', self.metadata, autoload=True)
        # Now only one trust remains ...
        self.assertEqual(1, session.query(trust_table.columns.id).count())
        # ... and this trust is the one that was not limited in uses
        self.assertEqual(
            unlimited_trust['id'],
            session.query(trust_table.columns.id).one()[0])

    def test_upgrade_service_enabled_cols(self):
        """Migration 44 added `enabled` column to `service` table."""

        self.upgrade(44)

        # Verify that there's an 'enabled' field.
        exp_cols = ['id', 'type', 'extra', 'enabled']
        self.assertTableColumns('service', exp_cols)

    def test_downgrade_service_enabled_cols(self):
        """Check columns when downgrade to migration 43.

        The downgrade from migration 44 removes the `enabled` column from the
        `service` table.

        """

        self.upgrade(44)
        self.downgrade(43)

        exp_cols = ['id', 'type', 'extra']
        self.assertTableColumns('service', exp_cols)

    def test_upgrade_service_enabled_data(self):
        """Migration 44 has to migrate data from `extra` to `enabled`."""

        def add_service(**extra_data):
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex,
                'extra': json.dumps(extra_data),
            }

            self.insert_dict(session, 'service', service)

            return service_id

        self.upgrade(43)
        session = self.Session()

        # Different services with expected enabled and extra values, and a
        # description.
        random_attr_name = uuid.uuid4().hex
        random_attr_value = uuid.uuid4().hex
        random_attr = {random_attr_name: random_attr_value}
        random_attr_str = "%s='%s'" % (random_attr_name, random_attr_value)
        random_attr_enabled_false = {random_attr_name: random_attr_value,
                                     'enabled': False}
        random_attr_enabled_false_str = 'enabled=False,%s' % random_attr_str

        services = [
            # Some values for True.
            (add_service(), (True, {}), 'no enabled'),
            (add_service(enabled=True), (True, {}), 'enabled=True'),
            (add_service(enabled='true'), (True, {}), "enabled='true'"),
            (add_service(**random_attr),
             (True, random_attr), random_attr_str),
            (add_service(enabled=None), (True, {}), 'enabled=None'),

            # Some values for False.
            (add_service(enabled=False), (False, {}), 'enabled=False'),
            (add_service(enabled='false'), (False, {}), "enabled='false'"),
            (add_service(enabled='0'), (False, {}), "enabled='0'"),
            (add_service(**random_attr_enabled_false),
             (False, random_attr), random_attr_enabled_false_str),
        ]

        session.close()
        self.upgrade(44)
        session = self.Session()

        # Verify that the services have the expected values.

        self.metadata.clear()
        service_table = sqlalchemy.Table('service', self.metadata,
                                         autoload=True)

        def fetch_service(service_id):
            cols = [service_table.c.enabled, service_table.c.extra]
            f = service_table.c.id == service_id
            s = sqlalchemy.select(cols).where(f)
            ep = session.execute(s).fetchone()
            return ep.enabled, json.loads(ep.extra)

        for service_id, exp, msg in services:
            exp_enabled, exp_extra = exp

            enabled, extra = fetch_service(service_id)

            self.assertEqual(exp_enabled, enabled, msg)
            self.assertEqual(exp_extra, extra, msg)

    def test_downgrade_service_enabled_data(self):
        """Downgrade from migration 44 migrates data.

        Downgrade from migration 44 migrates data from `enabled` to
        `extra`. Any disabled services have 'enabled': False put into 'extra'.

        """

        def add_service(enabled=True, **extra_data):
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex,
                'extra': json.dumps(extra_data),
                'enabled': enabled
            }

            self.insert_dict(session, 'service', service)

            return service_id

        self.upgrade(44)
        session = self.Session()

        # Insert some services using the new format.

        # We'll need a service entry since it's the foreign key for services.
        service_id = add_service(True)

        new_service = (lambda enabled, **extra_data:
                       add_service(enabled, **extra_data))

        # Different services with expected extra values, and a
        # description.
        services = [
            # True tests
            (new_service(True), {}, 'enabled'),
            (new_service(True, something='whatever'),
             {'something': 'whatever'},
             "something='whatever'"),

            # False tests
            (new_service(False), {'enabled': False}, 'enabled=False'),
            (new_service(False, something='whatever'),
             {'enabled': False, 'something': 'whatever'},
             "enabled=False, something='whatever'"),
        ]

        session.close()
        self.downgrade(43)
        session = self.Session()

        # Verify that the services have the expected values.

        self.metadata.clear()
        service_table = sqlalchemy.Table('service', self.metadata,
                                         autoload=True)

        def fetch_service(service_id):
            cols = [service_table.c.extra]
            f = service_table.c.id == service_id
            s = sqlalchemy.select(cols).where(f)
            ep = session.execute(s).fetchone()
            return json.loads(ep.extra)

        for service_id, exp_extra, msg in services:
            extra = fetch_service(service_id)
            self.assertEqual(exp_extra, extra, msg)

    def test_upgrade_endpoint_enabled_cols(self):
        """Migration 42 added `enabled` column to `endpoint` table."""

        self.upgrade(42)

        # Verify that there's an 'enabled' field.
        exp_cols = ['id', 'legacy_endpoint_id', 'interface', 'region',
                    'service_id', 'url', 'extra', 'enabled']
        self.assertTableColumns('endpoint', exp_cols)

    def test_downgrade_endpoint_enabled_cols(self):
        """Check columns when downgrade from migration 41.

        The downgrade from migration 42 removes the `enabled` column from the
        `endpoint` table.

        """

        self.upgrade(42)
        self.downgrade(41)

        exp_cols = ['id', 'legacy_endpoint_id', 'interface', 'region',
                    'service_id', 'url', 'extra']
        self.assertTableColumns('endpoint', exp_cols)

    def test_upgrade_endpoint_enabled_data(self):
        """Migration 42 has to migrate data from `extra` to `enabled`."""

        def add_service():
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex
            }

            self.insert_dict(session, 'service', service)

            return service_id

        def add_endpoint(service_id, **extra_data):
            endpoint_id = uuid.uuid4().hex

            endpoint = {
                'id': endpoint_id,
                'interface': uuid.uuid4().hex[:8],
                'service_id': service_id,
                'url': uuid.uuid4().hex,
                'extra': json.dumps(extra_data)
            }
            self.insert_dict(session, 'endpoint', endpoint)

            return endpoint_id

        self.upgrade(41)
        session = self.Session()

        # Insert some endpoints using the old format where `enabled` is in
        # `extra` JSON.

        # We'll need a service entry since it's the foreign key for endpoints.
        service_id = add_service()

        new_ep = lambda **extra_data: add_endpoint(service_id, **extra_data)

        # Different endpoints with expected enabled and extra values, and a
        # description.
        random_attr_name = uuid.uuid4().hex
        random_attr_value = uuid.uuid4().hex
        random_attr = {random_attr_name: random_attr_value}
        random_attr_str = "%s='%s'" % (random_attr_name, random_attr_value)
        random_attr_enabled_false = {random_attr_name: random_attr_value,
                                     'enabled': False}
        random_attr_enabled_false_str = 'enabled=False,%s' % random_attr_str

        endpoints = [
            # Some values for True.
            (new_ep(), (True, {}), 'no enabled'),
            (new_ep(enabled=True), (True, {}), 'enabled=True'),
            (new_ep(enabled='true'), (True, {}), "enabled='true'"),
            (new_ep(**random_attr),
             (True, random_attr), random_attr_str),
            (new_ep(enabled=None), (True, {}), 'enabled=None'),

            # Some values for False.
            (new_ep(enabled=False), (False, {}), 'enabled=False'),
            (new_ep(enabled='false'), (False, {}), "enabled='false'"),
            (new_ep(enabled='0'), (False, {}), "enabled='0'"),
            (new_ep(**random_attr_enabled_false),
             (False, random_attr), random_attr_enabled_false_str),
        ]

        session.close()
        self.upgrade(42)
        session = self.Session()

        # Verify that the endpoints have the expected values.

        self.metadata.clear()
        endpoint_table = sqlalchemy.Table('endpoint', self.metadata,
                                          autoload=True)

        def fetch_endpoint(endpoint_id):
            cols = [endpoint_table.c.enabled, endpoint_table.c.extra]
            f = endpoint_table.c.id == endpoint_id
            s = sqlalchemy.select(cols).where(f)
            ep = session.execute(s).fetchone()
            return ep.enabled, json.loads(ep.extra)

        for endpoint_id, exp, msg in endpoints:
            exp_enabled, exp_extra = exp

            enabled, extra = fetch_endpoint(endpoint_id)

            # NOTE(henry-nash): Different databases may return enabled as a
            # real boolean of 0/1 - so we use assertEqual not assertIs here.
            self.assertEqual(exp_enabled, enabled, msg)
            self.assertEqual(exp_extra, extra, msg)

    def test_downgrade_endpoint_enabled_data(self):
        """Downgrade from migration 42 migrates data.

        Downgrade from migration 42 migrates data from `enabled` to
        `extra`. Any disabled endpoints have 'enabled': False put into 'extra'.

        """

        def add_service():
            service_id = uuid.uuid4().hex

            service = {
                'id': service_id,
                'type': uuid.uuid4().hex
            }

            self.insert_dict(session, 'service', service)

            return service_id

        def add_endpoint(service_id, enabled, **extra_data):
            endpoint_id = uuid.uuid4().hex

            endpoint = {
                'id': endpoint_id,
                'interface': uuid.uuid4().hex[:8],
                'service_id': service_id,
                'url': uuid.uuid4().hex,
                'extra': json.dumps(extra_data),
                'enabled': enabled
            }
            self.insert_dict(session, 'endpoint', endpoint)

            return endpoint_id

        self.upgrade(42)
        session = self.Session()

        # Insert some endpoints using the new format.

        # We'll need a service entry since it's the foreign key for endpoints.
        service_id = add_service()

        new_ep = (lambda enabled, **extra_data:
                  add_endpoint(service_id, enabled, **extra_data))

        # Different endpoints with expected extra values, and a
        # description.
        endpoints = [
            # True tests
            (new_ep(True), {}, 'enabled'),
            (new_ep(True, something='whatever'), {'something': 'whatever'},
             "something='whatever'"),

            # False tests
            (new_ep(False), {'enabled': False}, 'enabled=False'),
            (new_ep(False, something='whatever'),
             {'enabled': False, 'something': 'whatever'},
             "enabled=False, something='whatever'"),
        ]

        session.close()
        self.downgrade(41)
        session = self.Session()

        # Verify that the endpoints have the expected values.

        self.metadata.clear()
        endpoint_table = sqlalchemy.Table('endpoint', self.metadata,
                                          autoload=True)

        def fetch_endpoint(endpoint_id):
            cols = [endpoint_table.c.extra]
            f = endpoint_table.c.id == endpoint_id
            s = sqlalchemy.select(cols).where(f)
            ep = session.execute(s).fetchone()
            return json.loads(ep.extra)

        for endpoint_id, exp_extra, msg in endpoints:
            extra = fetch_endpoint(endpoint_id)
            self.assertEqual(exp_extra, extra, msg)

    def test_upgrade_region_non_unique_description(self):
        """Test upgrade to migration 43.

        This migration should occur with no unique constraint on the region
        description column.

        Create two regions with the same description.

        """

        def add_region():
            region_uuid = uuid.uuid4().hex

            region = {
                'id': region_uuid,
                'description': ''
            }

            self.insert_dict(session, 'region', region)
            return region_uuid

        self.upgrade(43)
        session = self.Session()
        # Write one region to the database
        add_region()
        # Write another region to the database with the same description
        add_region()

    def test_upgrade_region_unique_description(self):
        """Test upgrade to migration 43.

        This test models a migration where there is a unique constraint on the
        description column.

        Create two regions with the same description.

        """

        def add_region(table):
            region_uuid = uuid.uuid4().hex

            region = {
                'id': region_uuid,
                'description': ''
            }

            self.insert_dict(session, 'region', region, table=table)
            return region_uuid

        def get_metadata():
            meta = sqlalchemy.MetaData()
            meta.bind = self.engine
            return meta

        # Migrate to version 42
        self.upgrade(42)
        session = self.Session()
        region_table = sqlalchemy.Table('region',
                                        get_metadata(),
                                        autoload=True)
        # create the unique constraint and load the new version of the
        # reflection cache
        idx = sqlalchemy.Index('description', region_table.c.description,
                               unique=True)
        idx.create(self.engine)

        region_unique_table = sqlalchemy.Table('region',
                                               get_metadata(),
                                               autoload=True)
        add_region(region_unique_table)
        self.assertEqual(1, session.query(region_unique_table).count())
        # verify the unique constraint is enforced
        self.assertRaises(
            # FIXME (I159): Since oslo.db wraps all the database exceptions
            # into more specific exception objects, we should catch both of
            # sqlalchemy and oslo.db exceptions. If an old oslo.db version
            # is installed, IntegrityError is raised. If >=0.4.0 version of
            # oslo.db is installed, DBError is raised.
            # When the global requirements is updated with
            # the version fixes exceptions wrapping, IntegrityError must be
            # removed from the tuple.

            # NOTE(henry-nash): The above re-creation of the (now erased from
            # history) unique constraint doesn't appear to work well with the
            # Postgresql SQA driver, leading to it throwing a ValueError, so
            # we also catch that here.
            (sqlalchemy.exc.IntegrityError, db_exception.DBError, ValueError),
            add_region,
            table=region_unique_table)

        # migrate to 43, unique constraint should be dropped
        session.close()
        self.upgrade(43)
        session = self.Session()

        # reload the region table from the schema
        region_nonunique = sqlalchemy.Table('region',
                                            get_metadata(),
                                            autoload=True)
        self.assertEqual(1, session.query(region_nonunique).count())

        # Write a second region to the database with the same description
        add_region(region_nonunique)
        self.assertEqual(2, session.query(region_nonunique).count())

    def test_id_mapping(self):
        self.upgrade(50)
        self.assertTableDoesNotExist('id_mapping')
        self.upgrade(51)
        self.assertTableExists('id_mapping')
        self.downgrade(50)
        self.assertTableDoesNotExist('id_mapping')

    def test_region_url_upgrade(self):
        self.upgrade(52)
        self.assertTableColumns('region',
                                ['id', 'description', 'parent_region_id',
                                 'extra', 'url'])

    def test_region_url_downgrade(self):
        self.upgrade(52)
        self.downgrade(51)
        self.assertTableColumns('region',
                                ['id', 'description', 'parent_region_id',
                                 'extra'])

    def test_region_url_cleanup(self):
        # make sure that the url field is dropped in the downgrade
        self.upgrade(52)
        session = self.Session()
        beta = {
            'id': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'parent_region_id': uuid.uuid4().hex,
            'url': uuid.uuid4().hex
        }
        acme = {
            'id': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'parent_region_id': uuid.uuid4().hex,
            'url': None
        }
        self.insert_dict(session, 'region', beta)
        self.insert_dict(session, 'region', acme)
        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(2, session.query(region_table).count())
        session.close()
        self.downgrade(51)
        session = self.Session()
        self.metadata.clear()
        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(2, session.query(region_table).count())
        region = session.query(region_table)[0]
        self.assertRaises(AttributeError, getattr, region, 'url')

    def test_endpoint_region_upgrade_columns(self):
        self.upgrade(53)
        self.assertTableColumns('endpoint',
                                ['id', 'legacy_endpoint_id', 'interface',
                                 'service_id', 'url', 'extra', 'enabled',
                                 'region_id'])
        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(region_table.c.id.type.length, 255)
        self.assertEqual(region_table.c.parent_region_id.type.length, 255)
        endpoint_table = sqlalchemy.Table('endpoint',
                                          self.metadata,
                                          autoload=True)
        self.assertEqual(endpoint_table.c.region_id.type.length, 255)

    def test_endpoint_region_downgrade_columns(self):
        self.upgrade(53)
        self.downgrade(52)
        self.assertTableColumns('endpoint',
                                ['id', 'legacy_endpoint_id', 'interface',
                                 'service_id', 'url', 'extra', 'enabled',
                                 'region'])
        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(region_table.c.id.type.length, 64)
        self.assertEqual(region_table.c.parent_region_id.type.length, 64)
        endpoint_table = sqlalchemy.Table('endpoint',
                                          self.metadata,
                                          autoload=True)
        self.assertEqual(endpoint_table.c.region.type.length, 255)

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

        # downgrade to 52
        session.close()
        self.downgrade(52)
        session = self.Session()
        self.metadata.clear()

        region_table = sqlalchemy.Table('region', self.metadata, autoload=True)
        self.assertEqual(1, session.query(region_table).count())
        self.assertEqual(1, session.query(region_table).
                         filter_by(id=_small_region_name).count())

        endpoint_table = sqlalchemy.Table('endpoint',
                                          self.metadata,
                                          autoload=True)
        self.assertEqual(5, session.query(endpoint_table).count())
        self.assertEqual(2, session.query(endpoint_table).
                         filter_by(region=_long_region_name).count())
        self.assertEqual(1, session.query(endpoint_table).
                         filter_by(region=_clashing_region_name).count())
        self.assertEqual(1, session.query(endpoint_table).
                         filter_by(region=_small_region_name).count())

    def test_add_actor_id_index(self):
        self.upgrade(53)
        self.upgrade(54)
        table = sqlalchemy.Table('assignment', self.metadata, autoload=True)
        index_data = [(idx.name, idx.columns.keys()) for idx in table.indexes]
        self.assertIn(('ix_actor_id', ['actor_id']), index_data)

    def test_token_user_id_and_trust_id_index_upgrade(self):
        self.upgrade(54)
        self.upgrade(55)
        table = sqlalchemy.Table('token', self.metadata, autoload=True)
        index_data = [(idx.name, idx.columns.keys()) for idx in table.indexes]
        self.assertIn(('ix_token_user_id', ['user_id']), index_data)
        self.assertIn(('ix_token_trust_id', ['trust_id']), index_data)

    def test_token_user_id_and_trust_id_index_downgrade(self):
        self.upgrade(55)
        self.downgrade(54)
        table = sqlalchemy.Table('token', self.metadata, autoload=True)
        index_data = [(idx.name, idx.columns.keys()) for idx in table.indexes]
        self.assertNotIn(('ix_token_user_id', ['user_id']), index_data)
        self.assertNotIn(('ix_token_trust_id', ['trust_id']), index_data)

    def test_remove_actor_id_index(self):
        self.upgrade(54)
        self.downgrade(53)
        table = sqlalchemy.Table('assignment', self.metadata, autoload=True)
        index_data = [(idx.name, idx.columns.keys()) for idx in table.indexes]
        self.assertNotIn(('ix_actor_id', ['actor_id']), index_data)

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

    def test_extension_not_controlled(self):
        """When get the version before controlling, raises DbMigrationError."""
        self.assertRaises(db_exception.DbMigrationError,
                          migration_helpers.get_db_version,
                          extension='federation')

    def test_extension_initial(self):
        """When get the initial version of an extension, it's 0."""
        for name, extension in six.iteritems(EXTENSIONS):
            abs_path = migration_helpers.find_migrate_repo(extension)
            migration.db_version_control(sql.get_engine(), abs_path)
            version = migration_helpers.get_db_version(extension=name)
            self.assertEqual(0, version,
                             'Migrate version for %s is not 0' % name)

    def test_extension_migrated(self):
        """When get the version after migrating an extension, it's not 0."""
        for name, extension in six.iteritems(EXTENSIONS):
            abs_path = migration_helpers.find_migrate_repo(extension)
            migration.db_version_control(sql.get_engine(), abs_path)
            migration.db_sync(sql.get_engine(), abs_path)
            version = migration_helpers.get_db_version(extension=name)
            self.assertTrue(
                version > 0,
                "Version for %s didn't change after migrated?" % name)

    def test_extension_downgraded(self):
        """When get the version after downgrading an extension, it is 0."""
        for name, extension in six.iteritems(EXTENSIONS):
            abs_path = migration_helpers.find_migrate_repo(extension)
            migration.db_version_control(sql.get_engine(), abs_path)
            migration.db_sync(sql.get_engine(), abs_path)
            version = migration_helpers.get_db_version(extension=name)
            self.assertTrue(
                version > 0,
                "Version for %s didn't change after migrated?" % name)
            migration.db_sync(sql.get_engine(), abs_path, version=0)
            version = migration_helpers.get_db_version(extension=name)
            self.assertEqual(0, version,
                             'Migrate version for %s is not 0' % name)

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
                          extension='access')

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
