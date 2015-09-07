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

from oslo_config import cfg

from keystone.common import environment
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import appserver


CONF = cfg.CONF

CERTDIR = unit.dirs.root('examples', 'pki', 'certs')
KEYDIR = unit.dirs.root('examples', 'pki', 'private')
CERT = os.path.join(CERTDIR, 'ssl_cert.pem')
KEY = os.path.join(KEYDIR, 'ssl_key.pem')
CA = os.path.join(CERTDIR, 'cacert.pem')
CLIENT = os.path.join(CERTDIR, 'middleware.pem')


class SSLTestCase(unit.TestCase):
    def setUp(self):
        super(SSLTestCase, self).setUp()
        raise self.skipTest('SSL Version and Ciphers cannot be configured '
                            'with eventlet, some platforms have disabled '
                            'SSLv3. See bug 1381365.')
        # NOTE(morganfainberg): It has been determined that this
        # will not be fixed. These tests should be re-enabled for the full
        # functional test suite when run against an SSL terminated
        # endpoint. Some distributions/environments have patched OpenSSL to
        # not have SSLv3 at all due to POODLE and this causes differing
        # behavior depending on platform. See bug 1381365 for more information.

        # NOTE(jamespage):
        # Deal with more secure certificate chain verification
        # introduced in python 2.7.9 under PEP-0476
        # https://github.com/python/peps/blob/master/pep-0476.txt
        self.context = None
        if hasattr(ssl, '_create_unverified_context'):
            self.context = ssl._create_unverified_context()
        self.load_backends()

    def get_HTTPSConnection(self, *args):
        """Simple helper to configure HTTPSConnection objects."""
        if self.context:
            return environment.httplib.HTTPSConnection(
                *args,
                context=self.context
            )
        else:
            return environment.httplib.HTTPSConnection(*args)

    def test_1way_ssl_ok(self):
        """Make sure both public and admin API work with 1-way SSL."""
        paste_conf = self._paste_config('keystone')
        ssl_kwargs = dict(cert=CERT, key=KEY, ca=CA)

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.admin_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.public_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

    def test_2way_ssl_ok(self):
        """Make sure both public and admin API work with 2-way SSL.

        Requires client certificate.
        """
        paste_conf = self._paste_config('keystone')
        ssl_kwargs = dict(cert=CERT, key=KEY, ca=CA, cert_required=True)

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.admin_port, CLIENT, CLIENT)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.public_port, CLIENT, CLIENT)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

    def test_1way_ssl_with_ipv6_ok(self):
        """Make sure both public and admin API work with 1-way ipv6 & SSL."""
        self.skip_if_no_ipv6()

        paste_conf = self._paste_config('keystone')
        ssl_kwargs = dict(cert=CERT, key=KEY, ca=CA, host="::1")

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '::1', CONF.eventlet_server.admin_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '::1', CONF.eventlet_server.public_port)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

    def test_2way_ssl_with_ipv6_ok(self):
        """Make sure both public and admin API work with 2-way ipv6 & SSL.

        Requires client certificate.
        """
        self.skip_if_no_ipv6()

        paste_conf = self._paste_config('keystone')
        ssl_kwargs = dict(cert=CERT, key=KEY, ca=CA,
                          cert_required=True, host="::1")

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '::1', CONF.eventlet_server.admin_port, CLIENT, CLIENT)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '::1', CONF.eventlet_server.public_port, CLIENT, CLIENT)
            conn.request('GET', '/')
            resp = conn.getresponse()
            self.assertEqual(300, resp.status)

    def test_2way_ssl_fail(self):
        """Expect to fail when client does not present proper certificate."""
        paste_conf = self._paste_config('keystone')
        ssl_kwargs = dict(cert=CERT, key=KEY, ca=CA, cert_required=True)

        # Verify Admin
        with appserver.AppServer(paste_conf, appserver.ADMIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.admin_port)
            try:
                conn.request('GET', '/')
                self.fail('Admin API shoulda failed with SSL handshake!')
            except ssl.SSLError:
                pass

        # Verify Public
        with appserver.AppServer(paste_conf, appserver.MAIN, **ssl_kwargs):
            conn = self.get_HTTPSConnection(
                '127.0.0.1', CONF.eventlet_server.public_port)
            try:
                conn.request('GET', '/')
                self.fail('Public API shoulda failed with SSL handshake!')
            except ssl.SSLError:
                pass
