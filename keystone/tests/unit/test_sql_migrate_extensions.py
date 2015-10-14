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

from keystone.contrib import endpoint_filter
from keystone.contrib import endpoint_policy
from keystone.contrib import example
from keystone.contrib import federation
from keystone.contrib import oauth1
from keystone.contrib import revoke
from keystone import exception
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
        self.assertRaises(exception.MigrationMovedFailure,
                          self.upgrade, version=1,
                          repository=self.repo_path)


class FederationExtension(test_sql_upgrade.SqlMigrateBase):

    FEDERATION_MIGRATIONS = 8

    def repo_package(self):
        return federation

    def test_upgrade(self):
        for version in range(self.FEDERATION_MIGRATIONS):
            v = version + 1
            self.assertRaises(exception.MigrationMovedFailure,
                              self.upgrade, version=v,
                              repository=self.repo_path)


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
