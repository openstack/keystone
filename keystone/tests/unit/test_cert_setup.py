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
import shutil
import subprocess

import mock
from six.moves import http_client
from testtools import matchers

from keystone.common import openssl
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import rest


SSLDIR = unit.dirs.tmp('ssl')
CONF = unit.CONF


CERTDIR = os.path.join(SSLDIR, 'certs')
KEYDIR = os.path.join(SSLDIR, 'private')


class CertSetupTestCase(rest.RestfulTestCase):

    def setUp(self):
        super(CertSetupTestCase, self).setUp()

        def cleanup_ssldir():
            try:
                shutil.rmtree(SSLDIR)
            except OSError:
                pass

        self.addCleanup(cleanup_ssldir)

    def config_overrides(self):
        super(CertSetupTestCase, self).config_overrides()
        ca_certs = os.path.join(CERTDIR, 'ca.pem')
        ca_key = os.path.join(CERTDIR, 'cakey.pem')

        self.config_fixture.config(
            group='signing',
            certfile=os.path.join(CERTDIR, 'signing_cert.pem'),
            ca_certs=ca_certs,
            ca_key=ca_key,
            keyfile=os.path.join(KEYDIR, 'signing_key.pem'))
        self.config_fixture.config(group='token', provider='fernet')
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

    def test_create_pki_certs(self, rebuild=False):
        pki = openssl.ConfigurePKI(None, None, rebuild=rebuild)
        pki.run()
        self.assertTrue(os.path.exists(CONF.signing.certfile))
        self.assertTrue(os.path.exists(CONF.signing.ca_certs))
        self.assertTrue(os.path.exists(CONF.signing.keyfile))

    def test_fetch_signing_cert(self, rebuild=False):
        pki = openssl.ConfigurePKI(None, None, rebuild=rebuild)
        pki.run()

        # NOTE(jamielennox): Use request directly because certificate
        # requests don't have some of the normal information
        signing_resp = self.request(self.public_app,
                                    '/v2.0/certificates/signing',
                                    method='GET',
                                    expected_status=http_client.OK)

        cacert_resp = self.request(self.public_app,
                                   '/v2.0/certificates/ca',
                                   method='GET',
                                   expected_status=http_client.OK)

        with open(CONF.signing.certfile) as f:
            self.assertEqual(f.read(), signing_resp.text)

        with open(CONF.signing.ca_certs) as f:
            self.assertEqual(f.read(), cacert_resp.text)

        # NOTE(jamielennox): This is weird behaviour that we need to enforce.
        # It doesn't matter what you ask for it's always going to give text
        # with a text/html content_type.

        for path in ['/v2.0/certificates/signing', '/v2.0/certificates/ca']:
            for accept in [None, 'text/html', 'application/json', 'text/xml']:
                headers = {'Accept': accept} if accept else {}
                resp = self.request(self.public_app, path, method='GET',
                                    expected_status=http_client.OK,
                                    headers=headers)

                self.assertEqual('text/html', resp.content_type)

    def test_fetch_signing_cert_when_rebuild(self):
        pki = openssl.ConfigurePKI(None, None)
        pki.run()
        self.test_fetch_signing_cert(rebuild=True)

    def test_failure(self):
        for path in ['/v2.0/certificates/signing', '/v2.0/certificates/ca']:
            self.request(self.public_app, path, method='GET',
                         expected_status=http_client.INTERNAL_SERVER_ERROR)

    def test_pki_certs_rebuild(self):
        self.test_create_pki_certs()
        with open(CONF.signing.certfile) as f:
            cert_file1 = f.read()

        self.test_create_pki_certs(rebuild=True)
        with open(CONF.signing.certfile) as f:
            cert_file2 = f.read()

        self.assertNotEqual(cert_file1, cert_file2)

    @mock.patch.object(os, 'remove')
    def test_rebuild_pki_certs_remove_error(self, mock_remove):
        self.test_create_pki_certs()
        with open(CONF.signing.certfile) as f:
            cert_file1 = f.read()

        mock_remove.side_effect = OSError()
        self.test_create_pki_certs(rebuild=True)
        with open(CONF.signing.certfile) as f:
            cert_file2 = f.read()

        self.assertEqual(cert_file1, cert_file2)

    def test_create_pki_certs_twice_without_rebuild(self):
        self.test_create_pki_certs()
        with open(CONF.signing.certfile) as f:
            cert_file1 = f.read()

        self.test_create_pki_certs()
        with open(CONF.signing.certfile) as f:
            cert_file2 = f.read()

        self.assertEqual(cert_file1, cert_file2)


class TestExecCommand(unit.TestCase):

    @mock.patch.object(subprocess.Popen, 'poll')
    def test_running_a_successful_command(self, mock_poll):
        mock_poll.return_value = 0

        ssl = openssl.ConfigurePKI('keystone_user', 'keystone_group')
        ssl.exec_command(['ls'])

    @mock.patch.object(subprocess, 'check_output')
    def test_running_an_invalid_command(self, mock_check_output):
        cmd = ['ls']

        output = 'this is the output string'

        error = subprocess.CalledProcessError(returncode=1,
                                              cmd=cmd,
                                              output=output)
        mock_check_output.side_effect = error

        ssl = openssl.ConfigurePKI('keystone_user', 'keystone_group')
        e = self.assertRaises(subprocess.CalledProcessError,
                              ssl.exec_command,
                              cmd)
        self.assertThat(e.output, matchers.Equals(output))
