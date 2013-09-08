# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
1. Modify the file `tests/backend_sql.conf` to use the connection for your
   live database
2. Set up a blank, live database.
3. run the tests using
    ./run_tests.sh -N  test_sql_upgrade
    WARNING::
        Your database will be wiped.
    Do not do this against a Database with valuable data as
    all data will be lost.
"""


from keystone.contrib import endpoint_filter
from keystone.contrib import example
from keystone.contrib import oauth1
from keystone.tests import test_sql_upgrade


class SqlUpgradeExampleExtension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return example

    def test_upgrade(self):
        self.assertTableDoesNotExist('example')
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('example', ['id', 'type', 'extra'])

    def test_downgrade(self):
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('example', ['id', 'type', 'extra'])
        self.downgrade(0, repository=self.repo_path)
        self.assertTableDoesNotExist('example')


class SqlUpgradeOAuth1Extension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return oauth1

    def test_upgrade(self):
        self.assertTableDoesNotExist('consumer')
        self.assertTableDoesNotExist('request_token')
        self.assertTableDoesNotExist('access_token')
        self.upgrade(1, repository=self.repo_path)
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

    def test_downgrade(self):
        self.upgrade(1, repository=self.repo_path)
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
        self.downgrade(0, repository=self.repo_path)
        self.assertTableDoesNotExist('consumer')
        self.assertTableDoesNotExist('request_token')
        self.assertTableDoesNotExist('access_token')


class EndpointFilterExtension(test_sql_upgrade.SqlMigrateBase):
    def repo_package(self):
        return endpoint_filter

    def test_upgrade(self):
        self.assertTableDoesNotExist('project_endpoint')
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('project_endpoint',
                                ['endpoint_id', 'project_id'])

    def test_downgrade(self):
        self.upgrade(1, repository=self.repo_path)
        self.assertTableColumns('project_endpoint',
                                ['endpoint_id', 'project_id'])
        self.downgrade(0, repository=self.repo_path)
        self.assertTableDoesNotExist('project_endpoint')
