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
from oslo.config import cfg

from keystone.contrib.kds.db import api as db_api
from keystone.contrib.kds.db.sqlalchemy import migration
from keystone.openstack.common.db import exception as db_exception
from keystone import tests
from keystone.tests.contrib.kds import paths

CONF = cfg.CONF


class SqliteDb(fixtures.Fixture):
    """Connect to Keystone's sqlite database.

    KDS is not designed with the intention that it should run within the same
    database as keystone however there is nothing preventing that. There seems
    to be issues regarding the conflicting CONF objects between keystone and
    KDS that prevent the connection to separate databases for testing.
    Therefore this fixture must simply bridge the gap back to the testing
    database for keystone and setup the KDS tables.
    """

    def setUp(self):
        super(SqliteDb, self).setUp()

        sqlite_db = os.path.abspath(paths.tmp_path('test.db'))

        CONF.set_override('connection_debug', '51', 'database')
        CONF.set_override('connection', 'sqlite:///%s' % sqlite_db, 'database')

        db_api.reset()

        tests.setup_database()

        try:
            migration.db_sync()
        except db_exception.DbMigrationError:
            migration.db_version_control(0)
            migration.db_sync()
