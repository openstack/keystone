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

from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
from oslotest import base as test_base

from keystone.common import sql
from keystone.identity.backends import sql as sql_backend
from keystone.tests.unit.identity.backends import test_base as id_test_base
from keystone.tests.unit.ksfixtures import database


class TestIdentityDriver(db_fixtures.OpportunisticDBTestMixin,
                         test_base.BaseTestCase,
                         id_test_base.IdentityDriverTests):

    expected_is_domain_aware = True
    expected_default_assignment_driver = 'sql'
    expected_is_sql = True
    expected_generates_uuids = True

    def setUp(self):
        super(TestIdentityDriver, self).setUp()
        self.engine = enginefacade.writer.get_engine()
        self.sessionmaker = enginefacade.writer.get_sessionmaker()

        # Set keystone's connection URL to be the test engine's url. Close
        # sqlite FK to avoid conflicting with sql upgrade test.
        database.initialize_sql_session(self.engine.url,
                                        enforce_sqlite_fks=False)

        # Override keystone's context manager to be oslo.db's global context
        # manager.
        sql.core._TESTING_USE_GLOBAL_CONTEXT_MANAGER = True
        self.addCleanup(setattr,
                        sql.core, '_TESTING_USE_GLOBAL_CONTEXT_MANAGER', False)
        self.addCleanup(sql.cleanup)

        database._load_sqlalchemy_models()
        sql.ModelBase.metadata.create_all(bind=self.engine)

        self.driver = sql_backend.Identity()


class MySQLOpportunisticIdentityDriverTestCase(TestIdentityDriver):
    FIXTURE = db_fixtures.MySQLOpportunisticFixture


class PostgreSQLOpportunisticIdentityDriverTestCase(TestIdentityDriver):
    FIXTURE = db_fixtures.PostgresqlOpportunisticFixture
