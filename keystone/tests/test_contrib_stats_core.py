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

from keystone.contrib import stats

from keystone import config
from keystone import tests


CONF = config.CONF


class StatsContribCore(tests.TestCase):
    def setUp(self):
        super(StatsContribCore, self).setUp()
        self.stats_middleware = stats.StatsMiddleware(None)

    def test_admin_request(self):
        host_admin = "127.0.0.1:%s" % CONF.admin_port
        self.assertEqual("admin",
                         self.stats_middleware._resolve_api(host_admin))

    def test_public_request(self):
        host_public = "127.0.0.1:%s" % CONF.public_port
        self.assertEqual("public",
                         self.stats_middleware._resolve_api(host_public))

    def test_other_request(self):
        host_public = "127.0.0.1:%s" % CONF.public_port
        host_other = host_public + "1"
        self.assertEqual(host_other,
                         self.stats_middleware._resolve_api(host_other))
