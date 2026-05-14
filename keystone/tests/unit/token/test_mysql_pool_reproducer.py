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

"""Regression reproducer for Keystone DB pool exhaustion on token validation.

This intentionally runs against oslo.db's opportunistic MySQL fixture rather
than sqlite.  The failure seen in DevStack/CI was a MySQL QueuePool exhaustion
while validating a project-scoped token and loading the token's project via the
SQL resource backend.
"""

import gc
import traceback

from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures as db_fixtures
import sqlalchemy
import webtest

from keystone.common import provider_api
from keystone.common import sql
from keystone.common.sql import core as sql_core
import keystone.conf
from keystone.identity.mapping_backends import mapping as identity_mapping
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class MySQLTokenValidationPoolExhaustion(
    db_fixtures.OpportunisticDBTestMixin,
    unit.SQLDriverOverrides,
    unit.TestCase,
):
    """Exercise token validation with a deliberately tiny MySQL pool.

    A single-connection pool makes leaked or retained checked-out connections
    deterministic: the first validation may pass, but any subsequent DB access
    on the same worker will hit QueuePool timeout if the validation path fails
    to return its connection.
    """

    FIXTURE = db_fixtures.MySQLOpportunisticFixture

    def config_overrides(self):
        super().config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.config_fixture.config(group='token', caching=False)
        self.config_fixture.config(group='token', cache_on_issue=False)

    def setUp(self):
        super().setUp()

        # Get the temporary MySQL database URL provisioned by oslo.db.
        mysql_engine = enginefacade.writer.get_engine()

        # Use Keystone's normal local transaction context, but point it at the
        # opportunistic MySQL database with a very small QueuePool.  Do not use
        # sqlite here: sqlite uses different pool classes and won't reproduce
        # the MySQL QueuePool behaviour seen in DevStack.
        sql.cleanup()
        self.addCleanup(sql.cleanup)
        sql_core._get_main_context_manager().configure(
            connection=mysql_engine.url.render_as_string(hide_password=False),
            max_pool_size=1,
            max_overflow=0,
            pool_timeout=1,
        )

        database._load_sqlalchemy_models()
        with sql.session_for_write() as session:
            self.engine = session.get_bind()
        sql.ModelBase.metadata.create_all(bind=self.engine)
        self.addCleanup(sql.ModelBase.metadata.drop_all, bind=self.engine)

        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.user_foo['enabled'] = True

        self._checked_out = {}
        pool = self._pool()
        sqlalchemy.event.listen(pool, 'checkout', self._record_checkout)
        sqlalchemy.event.listen(pool, 'checkin', self._record_checkin)
        self.addCleanup(
            sqlalchemy.event.remove, pool, 'checkout', self._record_checkout
        )
        self.addCleanup(
            sqlalchemy.event.remove, pool, 'checkin', self._record_checkin
        )

    def _pool(self):
        return sql_core._get_main_context_manager().writer.get_engine().pool

    def _record_checkout(self, dbapi_connection, connection_record, proxy):
        self._checked_out[connection_record] = ''.join(
            traceback.format_stack(limit=25)
        )

    def _record_checkin(self, dbapi_connection, connection_record):
        self._checked_out.pop(connection_record, None)

    def assertNoConnectionsCheckedOut(self):
        pool = self._pool()
        stacks = '\n\n'.join(self._checked_out.values())
        self.assertEqual(
            0,
            pool.checkedout(),
            f'Keystone left DB connections checked out: {pool.status()}\n{stacks}',
        )

    def test_id_mapping_list_leaks_mysql_connection(self):
        local_entity = {
            'domain_id': default_fixtures.DEFAULT_DOMAIN_ID,
            'local_id': 'local-user',
            'entity_type': identity_mapping.EntityType.USER,
        }
        PROVIDERS.id_mapping_api.create_id_mapping(local_entity)
        self.assertNoConnectionsCheckedOut()

        mappings = PROVIDERS.id_mapping_api.get_domain_mapping_list(
            default_fixtures.DEFAULT_DOMAIN_ID
        )
        list(mappings)

        self.assertGreater(
            self._pool().checkedout(),
            0,
            'Expected ID mapping list to leak a checked-out DB connection '
            'on the buggy code path.',
        )
        del mappings
        gc.collect()

    def test_project_scoped_token_validation_returns_mysql_connections(self):
        token = PROVIDERS.token_provider_api.issue_token(
            self.user_foo['id'],
            ['password'],
            project_id=self.project_bar['id'],
        )
        self.assertNoConnectionsCheckedOut()

        for _i in range(100):
            PROVIDERS.token_provider_api.validate_token(token.id)
            self.assertNoConnectionsCheckedOut()

        # Prove the pool is still usable after repeated token validation.  On
        # the affected failure mode this call is where a worker would raise:
        #   QueuePool limit of size 1 overflow 0 reached
        PROVIDERS.resource_api.get_project(self.project_bar['id'])
        self.assertNoConnectionsCheckedOut()


class MySQLWSGITokenValidationPoolExhaustion(
    db_fixtures.OpportunisticDBTestMixin, test_v3.RestfulTestCase
):
    """Run the real Keystone WSGI app against opportunistic MySQL.

    This is closer to the DevStack/CI failure than direct provider calls.  It
    drives the public WSGI app through WebTest and exercises the same HTTP
    sequence an OpenStack client/service uses around ``/v3/auth/tokens``.
    """

    FIXTURE = db_fixtures.MySQLOpportunisticFixture

    def config_overrides(self):
        super().config_overrides()
        self.config_fixture.config(group='token', provider='fernet')
        self.config_fixture.config(group='token', caching=False)
        self.config_fixture.config(group='token', cache_on_issue=False)

    def setUp(self):
        # Do not call test_v3.RestfulTestCase.setUp(): it installs the sqlite
        # database fixture.  Instead, install the opportunistic MySQL fixture,
        # run Keystone's base TestCase setup, then create the WSGI app.
        db_fixtures.OpportunisticDBTestMixin._setup_fixtures(self)
        unit.TestCase.setUp(self)

        self.auth_plugin_config_override()
        self._configure_keystone_mysql_pool()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.public_app = webtest.TestApp(self.loadapp(name='public'))
        self.addCleanup(delattr, self, 'public_app')

        self._checked_out = {}
        pool = self._pool()
        sqlalchemy.event.listen(pool, 'checkout', self._record_checkout)
        sqlalchemy.event.listen(pool, 'checkin', self._record_checkin)
        self.addCleanup(
            sqlalchemy.event.remove, pool, 'checkout', self._record_checkout
        )
        self.addCleanup(
            sqlalchemy.event.remove, pool, 'checkin', self._record_checkin
        )

    def _configure_keystone_mysql_pool(self):
        mysql_engine = enginefacade.writer.get_engine()
        sql.cleanup()
        self.addCleanup(sql.cleanup)
        sql_core._get_main_context_manager().configure(
            connection=mysql_engine.url.render_as_string(hide_password=False),
            max_pool_size=1,
            max_overflow=0,
            pool_timeout=1,
        )
        database._load_sqlalchemy_models()
        with sql.session_for_write() as session:
            self.engine = session.get_bind()
        sql.ModelBase.metadata.create_all(bind=self.engine)
        # Let the opportunistic MySQL fixture drop the whole temporary
        # database.  If this regression test detects a checked-out connection,
        # metadata.drop_all() can block during cleanup and hide the useful
        # assertion failure.

    def _pool(self):
        return sql_core._get_main_context_manager().writer.get_engine().pool

    def _record_checkout(self, dbapi_connection, connection_record, proxy):
        self._checked_out[connection_record] = ''.join(
            traceback.format_stack(limit=25)
        )

    def _record_checkin(self, dbapi_connection, connection_record):
        self._checked_out.pop(connection_record, None)

    def assertNoConnectionsCheckedOut(self):
        pool = self._pool()
        checkedout = pool.checkedout()
        if checkedout:
            stacks = '\n\n'.join(self._checked_out.values())
            # If this assertion fires on the buggy code, release the cached
            # service-provider value that can hold the leaked SQLAlchemy query
            # alive. This lets oslo.db tear down the temporary MySQL database
            # cleanly and report the useful assertion instead of hanging in
            # cleanup.
            PROVIDERS.federation_api.get_enabled_service_providers.invalidate(
                PROVIDERS.federation_api
            )
            gc.collect()
            self.fail(
                'Keystone WSGI request left DB connections checked out: '
                f'{pool.status()}\nOutstanding checkout stacks:\n{stacks}'
            )

    def _create_project_scoped_token_over_wsgi(self):
        auth_data = self.build_authentication_request(
            user_id=self.user_id,
            password=self.user['password'],
            project_id=self.project_id,
        )
        response = self.post('/auth/tokens', body=auth_data)
        self.assertNoConnectionsCheckedOut()
        return response.headers['X-Subject-Token']

    def _validate_token_over_wsgi(self, subject_token, auth_token):
        response = self.admin_request(
            path='/v3/auth/tokens',
            headers={
                'X-Auth-Token': auth_token,
                'X-Subject-Token': subject_token,
            },
            method='GET',
        )
        self.assertNoConnectionsCheckedOut()
        return response

    def test_wsgi_token_rendering_leaks_mysql_connection(self):
        self.get_admin_token()

        stacks = '\n\n'.join(self._checked_out.values())
        self.assertGreater(
            self._pool().checkedout(),
            0,
            'Expected WSGI token rendering to leak a checked-out DB '
            'connection on the buggy code path.',
        )
        self.assertIn('get_enabled_service_providers', stacks)

        # Release the cached service-provider value that holds the lazy
        # SQLAlchemy query alive so oslo.db can tear down the temporary MySQL
        # database cleanly after this bug reproducer passes.
        PROVIDERS.federation_api.get_enabled_service_providers.invalidate(
            PROVIDERS.federation_api
        )
        gc.collect()
