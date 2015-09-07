# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg

from keystone.common import environment
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import appserver


CONF = cfg.CONF


class IPv6TestCase(unit.TestCase):

    def setUp(self):
        self.skip_if_no_ipv6()
        super(IPv6TestCase, self).setUp()
        self.load_backends()

    def test_ipv6_ok(self):
        """Make sure both public and admin API work with ipv6."""
        paste_conf = self._paste_config('keystone')

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, host="::1"):
            conn = environment.httplib.HTTPConnection(
                '::1', CONF.eventlet_server.admin_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, host="::1"):
            conn = environment.httplib.HTTPConnection(
                '::1', CONF.eventlet_server.public_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)
