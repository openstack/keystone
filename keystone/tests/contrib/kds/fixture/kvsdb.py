# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import fixtures
from oslo.config import cfg

from keystone.contrib.kds.db import api as db_api

CONF = cfg.CONF


class KvsDb(fixtures.Fixture):

    def setUp(self):
        super(KvsDb, self).setUp()

        CONF.set_override('backend', 'kvs', 'database')

        db_api.reset()
