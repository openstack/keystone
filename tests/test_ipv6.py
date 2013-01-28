# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import httplib
import os
import ssl

from keystone import config
from keystone import test


CONF = config.CONF


class IPv6TestCase(test.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skip_if_no_ipv6()

    def setUp(self):
        super(IPv6TestCase, self).setUp()
        self.load_backends()

    def test_ipv6_ok(self):
        """
        Make sure both public and admin API work with ipv6.
        """
        self.public_server = self.serveapp('keystone', name='main',
                                           host="::1", port=0)
        self.admin_server = self.serveapp('keystone', name='admin',
                                          host="::1", port=0)
        # Verify Admin
        conn = httplib.HTTPConnection('::1', CONF.admin_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
        # Verify Public
        conn = httplib.HTTPConnection('::1', CONF.public_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
