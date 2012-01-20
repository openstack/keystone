# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 OpenStack, LLC
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Tests for database migrations. The test case runs a series of test cases to
ensure that migrations work properly both upgrading and downgrading, and that
no data loss occurs if possible.
"""

import os
import unittest2 as unittest
import urlparse

from migrate.versioning.repository import Repository
from sqlalchemy import *
from sqlalchemy.pool import NullPool

import keystone.backends.sqlalchemy.migration as migration_api
from keystone.logic.types import fault


class TestMigrations(unittest.TestCase):

    """Test sqlalchemy-migrate migrations"""

    TEST_DATABASES = {'sqlite': 'sqlite:///migration.db'}

    REPOSITORY_PATH = os.path.abspath(os.path.join(os.path.abspath(__file__),
                                os.pardir, os.pardir, os.pardir, 'backends',
                                'sqlalchemy', 'migrate_repo'))
    REPOSITORY = Repository(REPOSITORY_PATH)

    def __init__(self, *args, **kwargs):
        super(TestMigrations, self).__init__(*args, **kwargs)

    def setUp(self):
        # Load test databases
        self.engines = {}
        for key, value in TestMigrations.TEST_DATABASES.items():
            self.engines[key] = create_engine(value, poolclass=NullPool)

        # We start each test case with a completely blank slate.
        self._reset_databases()

    def tearDown(self):
        # We destroy the test data store between each test case,
        # and recreate it, which ensures that we have no side-effects
        # from the tests
        self._reset_databases()

    def _reset_databases(self):
        for key, engine in self.engines.items():
            conn_string = TestMigrations.TEST_DATABASES[key]
            conn_pieces = urlparse.urlparse(conn_string)
            if conn_string.startswith('sqlite'):
                # We can just delete the SQLite database, which is
                # the easiest and cleanest solution
                db_path = conn_pieces.path.strip('/')
                if os.path.exists(db_path):
                    os.unlink(db_path)
                # No need to recreate the SQLite DB. SQLite will
                # create it for us if it's not there...
            elif conn_string.startswith('mysql'):
                # We can execute the MySQL client to destroy and re-create
                # the MYSQL database, which is easier and less error-prone
                # than using SQLAlchemy to do this via MetaData...trust me.
                database = conn_pieces.path.strip('/')
                loc_pieces = conn_pieces.netloc.split('@')
                host = loc_pieces[1]
                auth_pieces = loc_pieces[0].split(':')
                user = auth_pieces[0]
                password = ""
                if len(auth_pieces) > 1:
                    if auth_pieces[1].strip():
                        password = "-p%s" % auth_pieces[1]
                sql = ("drop database if exists %(database)s; "
                       "create database %(database)s;") % locals()
                cmd = ("mysql -u%(user)s %(password)s -h%(host)s "
                       "-e\"%(sql)s\"") % locals()
                exitcode, out, err = execute(cmd)
                self.assertEqual(0, exitcode)

    def test_walk_versions(self):
        """
        Walks all version scripts for each tested database, ensuring
        that there are no errors in the version scripts for each engine
        """
        for key, engine in self.engines.items():
            self._walk_versions(TestMigrations.TEST_DATABASES[key])

    def _walk_versions(self, sql_connection):
        # Determine latest version script from the repo, then
        # upgrade from 1 through to the latest, with no data
        # in the databases. This just checks that the schema itself
        # upgrades successfully.

        # Assert we are not under version control...
        self.assertRaises(fault.DatabaseMigrationError,
                          migration_api.db_version,
                          sql_connection)
        # Place the database under version control
        print migration_api.version_control(sql_connection)

        cur_version = migration_api.db_version(sql_connection)
        self.assertEqual(0, cur_version)

        for version in xrange(1, TestMigrations.REPOSITORY.latest + 1):
            migration_api.upgrade(sql_connection, version)
            cur_version = migration_api.db_version(sql_connection)
            self.assertEqual(cur_version, version)

        # Now walk it back down to 0 from the latest, testing
        # the downgrade paths.
        for version in reversed(
            xrange(0, TestMigrations.REPOSITORY.latest)):
            migration_api.downgrade(sql_connection, version)
            cur_version = migration_api.db_version(sql_connection)
            self.assertEqual(cur_version, version)


if __name__ == '__main__':
    unittest.main()
