# Copyright 2016 Intel Corporation
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


import os

import fixtures
from migrate.versioning import api as versioning_api
from migrate.versioning import repository
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
from oslo_db.sqlalchemy import test_migrations
from oslotest import base as test_base
import sqlalchemy
import testtools

from keystone.common.sql import contract_repo
from keystone.common.sql import data_migration_repo
from keystone.common.sql import expand_repo
from keystone.common.sql import migrate_repo
from keystone.common.sql import upgrades


class DBOperationNotAllowed(Exception):
    pass


class BannedDBSchemaOperations(fixtures.Fixture):
    """Ban some operations for migrations."""

    def __init__(self, banned_ops=None,
                 migration_repo=migrate_repo.__file__):
        super(BannedDBSchemaOperations, self).__init__()
        self._banned_ops = banned_ops or {}
        self._migration_repo = migration_repo

    @staticmethod
    def _explode(resource_op, repo):
        # Extract the repo name prior to the trailing '/__init__.py'
        repo_name = repo.split('/')[-2]
        raise DBOperationNotAllowed(
            'Operation %s() is not allowed in %s database migrations' % (
                resource_op, repo_name))

    def setUp(self):
        super(BannedDBSchemaOperations, self).setUp()
        explode_lambda = {
            'Table.create': lambda *a, **k: self._explode(
                'Table.create', self._migration_repo),
            'Table.alter': lambda *a, **k: self._explode(
                'Table.alter', self._migration_repo),
            'Table.drop': lambda *a, **k: self._explode(
                'Table.drop', self._migration_repo),
            'Table.insert': lambda *a, **k: self._explode(
                'Table.insert', self._migration_repo),
            'Table.update': lambda *a, **k: self._explode(
                'Table.update', self._migration_repo),
            'Table.delete': lambda *a, **k: self._explode(
                'Table.delete', self._migration_repo),
            'Column.create': lambda *a, **k: self._explode(
                'Column.create', self._migration_repo),
            'Column.alter': lambda *a, **k: self._explode(
                'Column.alter', self._migration_repo),
            'Column.drop': lambda *a, **k: self._explode(
                'Column.drop', self._migration_repo)
        }
        for resource in self._banned_ops:
            for op in self._banned_ops[resource]:
                resource_op = '%(resource)s.%(op)s' % {
                    'resource': resource, 'op': op}
                self.useFixture(fixtures.MonkeyPatch(
                    'sqlalchemy.%s' % resource_op,
                    explode_lambda[resource_op]))


class TestBannedDBSchemaOperations(testtools.TestCase):
    """Test the BannedDBSchemaOperations fixture."""

    def test_column(self):
        """Test column operations raise DBOperationNotAllowed."""
        column = sqlalchemy.Column()
        with BannedDBSchemaOperations(
                banned_ops={'Column': ['create', 'alter', 'drop']}):
            self.assertRaises(DBOperationNotAllowed, column.drop)
            self.assertRaises(DBOperationNotAllowed, column.alter)
            self.assertRaises(DBOperationNotAllowed, column.create)

    def test_table(self):
        """Test table operations raise DBOperationNotAllowed."""
        table = sqlalchemy.Table()
        with BannedDBSchemaOperations(
                banned_ops={'Table': ['create', 'alter', 'drop',
                                      'insert', 'update', 'delete']}):
            self.assertRaises(DBOperationNotAllowed, table.drop)
            self.assertRaises(DBOperationNotAllowed, table.alter)
            self.assertRaises(DBOperationNotAllowed, table.create)
            self.assertRaises(DBOperationNotAllowed, table.insert)
            self.assertRaises(DBOperationNotAllowed, table.update)
            self.assertRaises(DBOperationNotAllowed, table.delete)


class KeystoneMigrationsCheckers(test_migrations.WalkVersionsMixin):
    """Walk over and test all sqlalchemy-migrate migrations."""

    # NOTE(xek): We start requiring things be additive in Newton, so
    # ignore all migrations before the first version in Newton.
    migrate_file = migrate_repo.__file__
    first_version = 101
    # NOTE(henry-nash): We don't ban data modification in the legacy repo,
    # since there are already migrations that do this for Newton (and these
    # do not cause us issues, or are already worked around).
    banned_ops = {'Table': ['alter', 'drop'],
                  'Column': ['alter', 'drop']}
    exceptions = [
        # NOTE(xek): Reviewers: DO NOT ALLOW THINGS TO BE ADDED HERE UNLESS
        # JUSTIFICATION CAN BE PROVIDED AS TO WHY THIS WILL NOT CAUSE
        # PROBLEMS FOR ROLLING UPGRADES.

        # Migration 102 drops the domain table in the Newton release. All
        # code that referenced the domain table was removed in the Mitaka
        # release, hence this migration will not cause problems when
        # running a mixture of Mitaka and Newton versions of keystone.
        102,

        # Migration 106 simply allows the password column to be nullable.
        # This change would not impact a rolling upgrade.
        106
    ]

    @property
    def INIT_VERSION(self):
        return upgrades.get_init_version(
            abs_path=os.path.abspath(os.path.dirname(self.migrate_file)))

    @property
    def REPOSITORY(self):
        return repository.Repository(
            os.path.abspath(os.path.dirname(self.migrate_file))
        )

    @property
    def migration_api(self):
        temp = __import__('oslo_db.sqlalchemy.migration', globals(),
                          locals(), ['versioning_api'], 0)
        return temp.versioning_api

    @property
    def migrate_engine(self):
        return self.engine

    def migrate_fully(self, repo_name):
        abs_path = os.path.abspath(os.path.dirname(repo_name))
        init_version = upgrades.get_init_version(abs_path=abs_path)
        schema = versioning_api.ControlledSchema.create(
            self.migrate_engine, abs_path, init_version)
        max_version = schema.repository.version().version
        upgrade = True
        err = ''
        version = versioning_api._migrate_version(
            schema, max_version, upgrade, err)
        schema.upgrade(version)

    def migrate_up(self, version, with_data=False):
        """Check that migrations don't cause downtime.

        Schema migrations can be done online, allowing for rolling upgrades.
        """
        # NOTE(xek):
        # self.exceptions contains a list of migrations where we allow the
        # banned operations. Only Migrations which don't cause
        # incompatibilities are allowed, for example dropping an index or
        # constraint.
        #
        # Please follow the guidelines outlined at:
        # https://docs.openstack.org/keystone/latest/contributor/database-migrations.html

        if version >= self.first_version and version not in self.exceptions:
            banned_ops = self.banned_ops
        else:
            banned_ops = None
        with BannedDBSchemaOperations(banned_ops, self.migrate_file):
            super(KeystoneMigrationsCheckers,
                  self).migrate_up(version, with_data)

    snake_walk = False
    downgrade = False

    def test_walk_versions(self):
        self.walk_versions(self.snake_walk, self.downgrade)


class TestKeystoneMigrationsMySQL(
        KeystoneMigrationsCheckers,
        db_fixtures.OpportunisticDBTestMixin,
        test_base.BaseTestCase):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture

    def setUp(self):
        super(TestKeystoneMigrationsMySQL, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()


class TestKeystoneMigrationsPostgreSQL(
        KeystoneMigrationsCheckers,
        db_fixtures.OpportunisticDBTestMixin,
        test_base.BaseTestCase):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture

    def setUp(self):
        super(TestKeystoneMigrationsPostgreSQL, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()


class TestKeystoneMigrationsSQLite(
        KeystoneMigrationsCheckers,
        db_fixtures.OpportunisticDBTestMixin,
        test_base.BaseTestCase):

    def setUp(self):
        super(TestKeystoneMigrationsSQLite, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()


class TestKeystoneExpandSchemaMigrations(
        KeystoneMigrationsCheckers):

    migrate_file = expand_repo.__file__
    first_version = 1
    # TODO(henry-nash): we should include Table update here as well, but this
    # causes the update of the migration version to appear as a banned
    # operation!
    banned_ops = {'Table': ['alter', 'drop', 'insert', 'delete'],
                  'Column': ['alter', 'drop']}
    exceptions = [
        # NOTE(xek, henry-nash): Reviewers: DO NOT ALLOW THINGS TO BE ADDED
        # HERE UNLESS JUSTIFICATION CAN BE PROVIDED AS TO WHY THIS WILL NOT
        # CAUSE PROBLEMS FOR ROLLING UPGRADES.

        # Migration 002 changes the column type, from datetime to timestamp in
        # the contract phase. Adding exception here to pass expand banned
        # tests, otherwise fails.
        2,
        # NOTE(lbragstad): The expand 003 migration alters the credential table
        # to make `blob` nullable. This allows the triggers added in 003 to
        # catch writes when the `blob` attribute isn't populated. We do this so
        # that the triggers aren't aware of the encryption implementation.
        3,
        # Migration 004 changes the password created_at column type, from
        # timestamp to datetime and updates the initial value in the contract
        # phase. Adding an exception here to pass expand banned tests,
        # otherwise fails.
        4
    ]

    def setUp(self):
        super(TestKeystoneExpandSchemaMigrations, self).setUp()


class TestKeystoneExpandSchemaMigrationsMySQL(
        db_fixtures.OpportunisticDBTestMixin,
        test_base.BaseTestCase,
        TestKeystoneExpandSchemaMigrations):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture

    def setUp(self):
        super(TestKeystoneExpandSchemaMigrationsMySQL, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()
        self.migrate_fully(migrate_repo.__file__)


class TestKeystoneExpandSchemaMigrationsPostgreSQL(
        db_fixtures.OpportunisticDBTestMixin,
        test_base.BaseTestCase,
        TestKeystoneExpandSchemaMigrations):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture

    def setUp(self):
        super(TestKeystoneExpandSchemaMigrationsPostgreSQL, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()
        self.migrate_fully(migrate_repo.__file__)


class TestKeystoneDataMigrations(
        KeystoneMigrationsCheckers):

    migrate_file = data_migration_repo.__file__
    first_version = 1
    banned_ops = {'Table': ['create', 'alter', 'drop'],
                  'Column': ['create', 'alter', 'drop']}
    exceptions = [
        # NOTE(xek, henry-nash): Reviewers: DO NOT ALLOW THINGS TO BE ADDED
        # HERE UNLESS JUSTIFICATION CAN BE PROVIDED AS TO WHY THIS WILL NOT
        # CAUSE PROBLEMS FOR ROLLING UPGRADES.

        # Migration 002 changes the column type, from datetime to timestamp in
        # the contract phase. Adding exception here to pass banned data
        # migration tests. Fails otherwise.
        2,
        # Migration 004 changes the password created_at column type, from
        # timestamp to datetime and updates the initial value in the contract
        # phase. Adding an exception here to pass data migrations banned tests,
        # otherwise fails.
        4
    ]

    def setUp(self):
        super(TestKeystoneDataMigrations, self).setUp()
        self.migrate_fully(migrate_repo.__file__)
        self.migrate_fully(expand_repo.__file__)


class TestKeystoneDataMigrationsMySQL(
        TestKeystoneDataMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class TestKeystoneDataMigrationsPostgreSQL(
        TestKeystoneDataMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class TestKeystoneDataMigrationsSQLite(
        TestKeystoneDataMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    pass


class TestKeystoneContractSchemaMigrations(
        KeystoneMigrationsCheckers):

    migrate_file = contract_repo.__file__
    first_version = 1
    # TODO(henry-nash): we should include Table update here as well, but this
    # causes the update of the migration version to appear as a banned
    # operation!
    banned_ops = {'Table': ['create', 'insert', 'delete'],
                  'Column': ['create']}
    exceptions = [
        # NOTE(xek, henry-nash): Reviewers: DO NOT ALLOW THINGS TO BE ADDED
        # HERE UNLESS JUSTIFICATION CAN BE PROVIDED AS TO WHY THIS WILL NOT
        # CAUSE PROBLEMS FOR ROLLING UPGRADES.

        # Migration 002 changes the column type, from datetime to timestamp.
        # To do this, the column is first dropped and recreated. This should
        # not have any negative impact on a rolling upgrade deployment.
        2,
        # Migration 004 changes the password created_at column type, from
        # timestamp to datetime and updates the created_at value. This is
        # likely not going to impact a rolling upgrade as the contract repo is
        # executed once the code has been updated; thus the created_at column
        # would be populated for any password changes. That being said, there
        # could be a performance issue for existing large password tables, as
        # the migration is not batched. However, it's a compromise and not
        # likely going to be a problem for operators.
        4,
        # Migration 013 updates a foreign key constraint at the federated_user
        # table. It is a composite key pointing to the procotol.id and
        # protocol.idp_id columns. Since we can't create a new foreign key
        # before dropping the old one and the operations happens in the same
        # upgrade phase, adding an exception here to pass the contract
        # banned tests.
        13
    ]

    def setUp(self):
        super(TestKeystoneContractSchemaMigrations, self).setUp()
        self.migrate_fully(migrate_repo.__file__)
        self.migrate_fully(expand_repo.__file__)
        self.migrate_fully(data_migration_repo.__file__)


class TestKeystoneContractSchemaMigrationsMySQL(
        TestKeystoneContractSchemaMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class TestKeystoneContractSchemaMigrationsPostgreSQL(
        TestKeystoneContractSchemaMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture


class TestKeystoneContractSchemaMigrationsSQLite(
        TestKeystoneContractSchemaMigrations,
        db_fixtures.OpportunisticDBTestMixin):
    # In Sqlite an alter will appear as a create, so if we check for creates
    # we will get false positives.
    def setUp(self):
        super(TestKeystoneContractSchemaMigrationsSQLite, self).setUp()
        self.banned_ops['Table'].remove('create')
