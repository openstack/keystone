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
Test SQL migration extensions.

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
from keystone.contrib import federation
from keystone.contrib import oauth1
from keystone.contrib import revoke
from keystone import exception
from keystone.tests.unit import test_sql_upgrade


class SqlUpgradeOAuth1Extension(test_sql_upgrade.SqlMigrateBase):

    OAUTH1_MIGRATIONS = 5

    def repo_package(self):
        return oauth1

    def test_upgrade(self):
        for version in range(self.OAUTH1_MIGRATIONS):
            v = version + 1
            self.assertRaises(exception.MigrationMovedFailure,
                              self.upgrade, version=v,
                              repository=self.repo_path)


class EndpointFilterExtension(test_sql_upgrade.SqlMigrateBase):

    ENDPOINT_FILTER_MIGRATIONS = 2

    def repo_package(self):
        return endpoint_filter

    def test_upgrade(self):
        for version in range(self.ENDPOINT_FILTER_MIGRATIONS):
            v = version + 1
            self.assertRaises(exception.MigrationMovedFailure,
                              self.upgrade, version=v,
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

    REVOKE_MIGRATIONS = 2

    def repo_package(self):
        return revoke

    def test_upgrade(self):
        for version in range(self.REVOKE_MIGRATIONS):
            v = version + 1
            self.assertRaises(exception.MigrationMovedFailure,
                              self.upgrade, version=v,
                              repository=self.repo_path)
