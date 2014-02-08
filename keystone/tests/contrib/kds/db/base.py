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

from keystone.contrib.kds.db import api as db_api
from keystone.tests.contrib.kds import base
from keystone.tests.contrib.kds import fixture


class BaseTestCase(base.BaseTestCase):

    scenarios = [('sqlitedb', {'sql_fixture': fixture.SqliteDb}),
                 ('kvsdb', {'sql_fixture': fixture.KvsDb})]

    def setUp(self):
        super(BaseTestCase, self).setUp()

        self.useFixture(self.sql_fixture())

        self.DB = db_api.get_instance()
