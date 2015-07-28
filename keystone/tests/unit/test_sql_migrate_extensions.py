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

1. Modify the file `keystone/tests/unit/config_files/backend_sql.conf` to use
   the connection for your live database.
2. Set up a blank, live database.
3. Run the tests using::

    tox -e py27 -- keystone.tests.unit.test_sql_migrate_extensions

WARNING::

   Your database will be wiped.

   Do not do this against a Database with valuable data as
   all data will be lost.
"""

import sqlalchemy
import uuid

from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import utils

from keystone.contrib import endpoint_filter
from keystone.contrib import endpoint_policy
from keystone.contrib import example
from keystone.contrib import federation
from keystone.contrib import oauth1
from keystone.contrib import revoke
from keystone.tests.unit import test_sql_upgrade


class SqlUpgradeExampleExtension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return example

    def test_upgrade(self):
        self.assertTableDoesNotExist('example')
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('example', ['id', 'type', 'extra'])


class SqlUpgradeOAuth1Extension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return oauth1

    def upgrade(self, version):
        super(SqlUpgradeOAuth1Extension, self).upgrade(
            version, repository=self.repo_path)

    def _assert_v1_3_tables(self):
        self.assertTableColumns('consumer',
                                ['id',
                                 'description',
                                 'secret',
                                 'extra'])
        self.assertTableColumns('request_token',
                                ['id',
                                 'request_secret',
                                 'verifier',
                                 'authorizing_user_id',
                                 'requested_project_id',
                                 'requested_roles',
                                 'consumer_id',
                                 'expires_at'])
        self.assertTableColumns('access_token',
                                ['id',
                                 'access_secret',
                                 'authorizing_user_id',
                                 'project_id',
                                 'requested_roles',
                                 'consumer_id',
                                 'expires_at'])

    def _assert_v4_later_tables(self):
        self.assertTableColumns('consumer',
                                ['id',
                                 'description',
                                 'secret',
                                 'extra'])
        self.assertTableColumns('request_token',
                                ['id',
                                 'request_secret',
                                 'verifier',
                                 'authorizing_user_id',
                                 'requested_project_id',
                                 'role_ids',
                                 'consumer_id',
                                 'expires_at'])
        self.assertTableColumns('access_token',
                                ['id',
                                 'access_secret',
                                 'authorizing_user_id',
                                 'project_id',
                                 'role_ids',
                                 'consumer_id',
                                 'expires_at'])

    def test_upgrade(self):
        self.assertTableDoesNotExist('consumer')
        self.assertTableDoesNotExist('request_token')
        self.assertTableDoesNotExist('access_token')
        self.upgrade(1)
        self._assert_v1_3_tables()

        # NOTE(blk-u): Migrations 2-3 don't modify the tables in a way that we
        # can easily test for.

        self.upgrade(4)
        self._assert_v4_later_tables()

        self.upgrade(5)
        self._assert_v4_later_tables()


class EndpointFilterExtension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return endpoint_filter

    def upgrade(self, version):
        super(EndpointFilterExtension, self).upgrade(
            version, repository=self.repo_path)

    def _assert_v1_tables(self):
        self.assertTableColumns('project_endpoint',
                                ['endpoint_id', 'project_id'])
        self.assertTableDoesNotExist('endpoint_group')
        self.assertTableDoesNotExist('project_endpoint_group')

    def _assert_v2_tables(self):
        self.assertTableColumns('project_endpoint',
                                ['endpoint_id', 'project_id'])
        self.assertTableColumns('endpoint_group',
                                ['id', 'name', 'description', 'filters'])
        self.assertTableColumns('project_endpoint_group',
                                ['endpoint_group_id', 'project_id'])

    def test_upgrade(self):
        self.assertTableDoesNotExist('project_endpoint')
        self.upgrade(1)
        self._assert_v1_tables()
        self.assertTableColumns('project_endpoint',
                                ['endpoint_id', 'project_id'])
        self.upgrade(2)
        self._assert_v2_tables()


class EndpointPolicyExtension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return endpoint_policy

    def test_upgrade(self):
        self.assertTableDoesNotExist('policy_association')
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('policy_association',
                                ['id', 'policy_id', 'endpoint_id',
                                 'service_id', 'region_id'])


class FederationExtension(test_sql_upgrade.SqlMigrateBase):
    """Test class for ensuring the Federation SQL."""

    def setUp(self):
        super(FederationExtension, self).setUp()
        self.identity_provider = 'identity_provider'
        self.federation_protocol = 'federation_protocol'
        self.service_provider = 'service_provider'
        self.mapping = 'mapping'
        self.remote_id_table = 'idp_remote_ids'

    def repo_package(self):
        return federation

    def insert_dict(self, session, table_name, d):
        """Naively inserts key-value pairs into a table, given a dictionary."""
        table = sqlalchemy.Table(table_name, self.metadata, autoload=True)
        insert = table.insert().values(**d)
        session.execute(insert)
        session.commit()

    def test_upgrade(self):
        self.assertTableDoesNotExist(self.identity_provider)
        self.assertTableDoesNotExist(self.federation_protocol)
        self.assertTableDoesNotExist(self.mapping)

        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns(self.identity_provider,
                                ['id',
                                 'enabled',
                                 'description'])

        self.assertTableColumns(self.federation_protocol,
                                ['id',
                                 'idp_id',
                                 'mapping_id'])

        self.upgrade(2, repository=self.repo_path)
        self.assertTableColumns(self.mapping,
                                ['id', 'rules'])

        federation_protocol = utils.get_table(
            self.engine,
            'federation_protocol')
        with self.engine.begin() as conn:
            conn.execute(federation_protocol.insert(), id=0, idp_id=1)
            self.upgrade(3, repository=self.repo_path)
            federation_protocol = utils.get_table(
                self.engine,
                'federation_protocol')
            self.assertFalse(federation_protocol.c.mapping_id.nullable)

    def test_service_provider_attributes_cannot_be_null(self):
        self.upgrade(6, repository=self.repo_path)
        self.assertTableColumns(self.service_provider,
                                ['id', 'description', 'enabled', 'auth_url',
                                 'sp_url'])

        session = self.Session()
        sp1 = {'id': uuid.uuid4().hex,
               'auth_url': None,
               'sp_url': uuid.uuid4().hex,
               'description': uuid.uuid4().hex,
               'enabled': True}
        sp2 = {'id': uuid.uuid4().hex,
               'auth_url': uuid.uuid4().hex,
               'sp_url': None,
               'description': uuid.uuid4().hex,
               'enabled': True}
        sp3 = {'id': uuid.uuid4().hex,
               'auth_url': None,
               'sp_url': None,
               'description': uuid.uuid4().hex,
               'enabled': True}

        # Insert with 'auth_url' or 'sp_url' set to null must fail
        self.assertRaises(db_exception.DBError,
                          self.insert_dict,
                          session,
                          self.service_provider,
                          sp1)
        self.assertRaises(db_exception.DBError,
                          self.insert_dict,
                          session,
                          self.service_provider,
                          sp2)
        self.assertRaises(db_exception.DBError,
                          self.insert_dict,
                          session,
                          self.service_provider,
                          sp3)

        session.close()

    def test_fixup_service_provider_attributes(self):
        session = self.Session()
        sp1 = {'id': uuid.uuid4().hex,
               'auth_url': None,
               'sp_url': uuid.uuid4().hex,
               'description': uuid.uuid4().hex,
               'enabled': True}
        sp2 = {'id': uuid.uuid4().hex,
               'auth_url': uuid.uuid4().hex,
               'sp_url': None,
               'description': uuid.uuid4().hex,
               'enabled': True}
        sp3 = {'id': uuid.uuid4().hex,
               'auth_url': None,
               'sp_url': None,
               'description': uuid.uuid4().hex,
               'enabled': True}
        self.upgrade(5, repository=self.repo_path)
        self.assertTableColumns(self.service_provider,
                                ['id', 'description', 'enabled', 'auth_url',
                                 'sp_url'])

        # Before the migration, the table should accept null values
        self.insert_dict(session, self.service_provider, sp1)
        self.insert_dict(session, self.service_provider, sp2)
        self.insert_dict(session, self.service_provider, sp3)

        # Check if null values are updated to empty string when migrating
        session.close()
        self.upgrade(6, repository=self.repo_path)
        sp_table = sqlalchemy.Table(self.service_provider,
                                    self.metadata,
                                    autoload=True)
        session = self.Session()
        self.metadata.clear()

        sp = session.query(sp_table).filter(sp_table.c.id == sp1['id'])[0]
        self.assertEqual('', sp.auth_url)

        sp = session.query(sp_table).filter(sp_table.c.id == sp2['id'])[0]
        self.assertEqual('', sp.sp_url)

        sp = session.query(sp_table).filter(sp_table.c.id == sp3['id'])[0]
        self.assertEqual('', sp.auth_url)
        self.assertEqual('', sp.sp_url)

    def test_propagate_remote_id_to_separate_column(self):
        """Make sure empty remote_id is not propagated.
        Test scenario:
        - Upgrade database to version 6 where identity_provider table has a
          remote_id column
        - Add 3 identity provider objects, where idp1 and idp2 have valid
          remote_id parameter set, and idp3 has it empty (None).
        - Upgrade database to version 7 and expect migration scripts to
          properly move data rom identity_provider.remote_id column into
          separate table idp_remote_ids.
        - In the idp_remote_ids table expect to find entries for idp1 and idp2
          and not find anything for idp3 (identitified by idp's id)

        """
        session = self.Session()
        idp1 = {'id': uuid.uuid4().hex,
                'remote_id': uuid.uuid4().hex,
                'description': uuid.uuid4().hex,
                'enabled': True}
        idp2 = {'id': uuid.uuid4().hex,
                'remote_id': uuid.uuid4().hex,
                'description': uuid.uuid4().hex,
                'enabled': True}
        idp3 = {'id': uuid.uuid4().hex,
                'remote_id': None,
                'description': uuid.uuid4().hex,
                'enabled': True}
        self.upgrade(6, repository=self.repo_path)
        self.assertTableColumns(self.identity_provider,
                                ['id', 'description', 'enabled', 'remote_id'])

        self.insert_dict(session, self.identity_provider, idp1)
        self.insert_dict(session, self.identity_provider, idp2)
        self.insert_dict(session, self.identity_provider, idp3)

        session.close()
        self.upgrade(7, repository=self.repo_path)

        self.assertTableColumns(self.identity_provider,
                                ['id', 'description', 'enabled'])
        remote_id_table = sqlalchemy.Table(self.remote_id_table,
                                           self.metadata,
                                           autoload=True)

        session = self.Session()
        self.metadata.clear()

        idp = session.query(remote_id_table).filter(
            remote_id_table.c.idp_id == idp1['id'])[0]
        self.assertEqual(idp1['remote_id'], idp.remote_id)

        idp = session.query(remote_id_table).filter(
            remote_id_table.c.idp_id == idp2['id'])[0]
        self.assertEqual(idp2['remote_id'], idp.remote_id)

        idp = session.query(remote_id_table).filter(
            remote_id_table.c.idp_id == idp3['id'])
        # NOTE(marek-denis): As idp3 had empty 'remote_id' attribute we expect
        # not to find it in the 'remote_id_table' table, hence count should be
        # 0.real
        self.assertEqual(0, idp.count())

    def test_add_relay_state_column(self):
        self.upgrade(8, repository=self.repo_path)
        self.assertTableColumns(self.service_provider,
                                ['id', 'description', 'enabled', 'auth_url',
                                 'relay_state_prefix', 'sp_url'])


class RevokeExtension(test_sql_upgrade.SqlMigrateBase):

    _REVOKE_COLUMN_NAMES = ['id', 'domain_id', 'project_id', 'user_id',
                            'role_id', 'trust_id', 'consumer_id',
                            'access_token_id', 'issued_before', 'expires_at',
                            'revoked_at']

    def repo_package(self):
        return revoke

    def test_upgrade(self):
        self.assertTableDoesNotExist('revocation_event')
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('revocation_event',
                                self._REVOKE_COLUMN_NAMES)
