# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os
import ssl

from keystone.common import environment
from keystone import config
from keystone import tests


CONF = config.CONF

CERTDIR = tests.rootdir("examples/pki/certs")
KEYDIR = tests.rootdir("examples/pki/private")
CERT = os.path.join(CERTDIR, 'ssl_cert.pem')
KEY = os.path.join(KEYDIR, 'ssl_key.pem')
CA = os.path.join(CERTDIR, 'cacert.pem')
CLIENT = os.path.join(CERTDIR, 'middleware.pem')


class SSLTestCase(tests.TestCase):
    def setUp(self):
        super(SSLTestCase, self).setUp()
        self.load_backends()

    def test_1way_ssl_ok(self):
        """Make sure both public and admin API work with 1-way SSL."""
        self.public_server = self.serveapp('keystone', name='main',
                                           cert=CERT, key=KEY, ca=CA)
        self.admin_server = self.serveapp('keystone', name='admin',
                                          cert=CERT, key=KEY, ca=CA)
        # Verify Admin
        conn = environment.httplib.HTTPSConnection('127.0.0.1',
                                                   CONF.admin_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
        # Verify Public
        conn = environment.httplib.HTTPSConnection('127.0.0.1',
                                                   CONF.public_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)

    def test_2way_ssl_ok(self):
        """Make sure both public and admin API work with 2-way SSL.

        Requires client certificate.
        """
        self.public_server = self.serveapp(
            'keystone', name='main', cert=CERT,
            key=KEY, ca=CA, cert_required=True)
        self.admin_server = self.serveapp(
            'keystone', name='admin', cert=CERT,
            key=KEY, ca=CA, cert_required=True)
        # Verify Admin
        conn = environment.httplib.HTTPSConnection(
            '127.0.0.1', CONF.admin_port, CLIENT, CLIENT)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
        # Verify Public
        conn = environment.httplib.HTTPSConnection(
            '127.0.0.1', CONF.public_port, CLIENT, CLIENT)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)

    def test_1way_ssl_with_ipv6_ok(self):
        """Make sure both public and admin API work with 1-way ipv6 & SSL."""
        self.skip_if_no_ipv6()
        self.public_server = self.serveapp('keystone', name='main',
                                           cert=CERT, key=KEY, ca=CA,
                                           host="::1", port=0)
        self.admin_server = self.serveapp('keystone', name='admin',
                                          cert=CERT, key=KEY, ca=CA,
                                          host="::1", port=0)
        # Verify Admin
        conn = environment.httplib.HTTPSConnection('::1', CONF.admin_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
        # Verify Public
        conn = environment.httplib.HTTPSConnection('::1', CONF.public_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)

    def test_2way_ssl_with_ipv6_ok(self):
        """Make sure both public and admin API work with 2-way ipv6 & SSL.

        Requires client certificate.
        """
        self.skip_if_no_ipv6()
        self.public_server = self.serveapp(
            'keystone', name='main', cert=CERT,
            key=KEY, ca=CA, cert_required=True,
            host="::1", port=0)
        self.admin_server = self.serveapp(
            'keystone', name='admin', cert=CERT,
            key=KEY, ca=CA, cert_required=True,
            host="::1", port=0)
        # Verify Admin
        conn = environment.httplib.HTTPSConnection(
            '::1', CONF.admin_port, CLIENT, CLIENT)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)
        # Verify Public
        conn = environment.httplib.HTTPSConnection(
            '::1', CONF.public_port, CLIENT, CLIENT)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 300)

    def test_2way_ssl_fail(self):
        """Expect to fail when client does not present proper certificate."""
        self.public_server = self.serveapp(
            'keystone', name='main', cert=CERT,
            key=KEY, ca=CA, cert_required=True)
        self.admin_server = self.serveapp(
            'keystone', name='admin', cert=CERT,
            key=KEY, ca=CA, cert_required=True)
        # Verify Admin
        conn = environment.httplib.HTTPSConnection('127.0.0.1',
                                                   CONF.admin_port)
        try:
            conn.request('GET', '/')
            self.fail('Admin API shoulda failed with SSL handshake!')
        except ssl.SSLError:
            pass
        # Verify Public
        conn = environment.httplib.HTTPSConnection('127.0.0.1',
                                                   CONF.public_port)
        try:
            conn.request('GET', '/')
            self.fail('Public API shoulda failed with SSL handshake!')
        except ssl.SSLError:
            pass
