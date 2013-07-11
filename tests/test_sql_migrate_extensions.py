# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone.contrib import example

import test_sql_upgrade


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
