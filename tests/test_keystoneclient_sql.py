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
from keystone import config
from keystone import test
from keystone.common.sql import util as sql_util

import test_keystoneclient


CONF = config.CONF


class KcMasterSqlTestCase(test_keystoneclient.KcMasterTestCase):
    def config(self):
        CONF(config_files=[test.etcdir('keystone.conf'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()
