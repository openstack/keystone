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
from migrate.versioning import repository
from oslo_db.sqlalchemy import test_base
from oslo_db.sqlalchemy import test_migrations
import sqlalchemy
import testtools

from keystone.common.sql import migrate_repo
from keystone.common.sql import migration_helpers


class DBOperationNotAllowed(Exception):
    pass


class BannedDBSchemaOperations(fixtures.Fixture):
    """Ban some operations for migrations."""

    def __init__(self, banned_resources=None):
        super(BannedDBSchemaOperations, self).__init__()
        self._banned_resources = banned_resources or []

    @staticmethod
    def _explode(resource, op):
        raise DBOperationNotAllowed(
            'Operation %s.%s() is not allowed in a database migration' % (
                resource, op))

    def setUp(self):
        super(BannedDBSchemaOperations, self).setUp()
        for resource in self._banned_resources:
            self.useFixture(fixtures.MonkeyPatch(
                'sqlalchemy.%s.drop' % resource,
                lambda *a, **k: self._explode(resource, 'drop')))
            self.useFixture(fixtures.MonkeyPatch(
                'sqlalchemy.%s.alter' % resource,
                lambda *a, **k: self._explode(resource, 'alter')))


class TestBannedDBSchemaOperations(testtools.TestCase):
    """Test the BannedDBSchemaOperations fixture."""

    def test_column(self):
        """Test column drops and alters raise DBOperationNotAllowed."""
        column = sqlalchemy.Column()
        with BannedDBSchemaOperations(banned_resources=['Column']):
            self.assertRaises(DBOperationNotAllowed, column.drop)
            self.assertRaises(DBOperationNotAllowed, column.alter)

    def test_table(self):
        """Test table drops and alters raise DBOperationNotAllowed."""
        table = sqlalchemy.Table()
        with BannedDBSchemaOperations(banned_resources=['Table']):
            self.assertRaises(DBOperationNotAllowed, table.drop)
            self.assertRaises(DBOperationNotAllowed, table.alter)


class KeystoneMigrationsCheckers(test_migrations.WalkVersionsMixin):
    """Walk over and test all sqlalchemy-migrate migrations."""

    @property
    def INIT_VERSION(self):
        return migration_helpers.get_init_version()

    @property
    def REPOSITORY(self):
        migrate_file = migrate_repo.__file__
        return repository.Repository(
            os.path.abspath(os.path.dirname(migrate_file))
        )

    @property
    def migration_api(self):
        temp = __import__('oslo_db.sqlalchemy.migration', globals(),
                          locals(), ['versioning_api'], 0)
        return temp.versioning_api

    @property
    def migrate_engine(self):
        return self.engine

    def migrate_up(self, version, with_data=False):
        """Check that migrations don't cause downtime.

        Schema migrations can be done online, allowing for rolling upgrades.
        """
        # NOTE(xek):
        # This is a list of migrations where we allow dropping and altering
        # things. The rules for adding exceptions are very specific:
        #
        # 1) Migrations which don't cause incompatibilities are allowed,
        #    for example dropping an index or constraint.
        #
        # 2) Migrations removing structures not used in the previous version
        #    are allowed (we keep compatibility between releases), ex.:
        #
        #    a) feature is deprecated according to the deprecation policies
        #       (release 1),
        #
        #    b) code supporting the feature is removed the following release
        #       (release 2),
        #
        #    c) table can be dropped a release after the code has been removed
        #       (i.e. in release 3).
        #
        # 3) Any other changes which don't pass this test are disallowed.
        #
        # Please follow the guidelines outlined at:
        # http://docs.openstack.org/developer/keystone/developing.html#online-migration

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

        # NOTE(xek): We start requiring things be additive in Newton, so
        # ignore all migrations before that point.
        NEWTON_START = 101

        if version >= NEWTON_START and version not in exceptions:
            banned = ['Table', 'Column']
        else:
            banned = None
        with BannedDBSchemaOperations(banned):
            super(KeystoneMigrationsCheckers,
                  self).migrate_up(version, with_data)

    snake_walk = False
    downgrade = False

    def test_walk_versions(self):
        self.walk_versions(self.snake_walk, self.downgrade)


class TestKeystoneMigrationsMySQL(
        KeystoneMigrationsCheckers, test_base.MySQLOpportunisticTestCase):
    pass


class TestKeystoneMigrationsPostgreSQL(
        KeystoneMigrationsCheckers, test_base.PostgreSQLOpportunisticTestCase):
    pass


class TestKeystoneMigrationsSQLite(
        KeystoneMigrationsCheckers, test_base.DbTestCase):
    pass
