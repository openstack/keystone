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

import os
import shutil

from keystone.common import openssl
from keystone import exception
from keystone import test
from keystone import token

ROOTDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSLDIR = "%s/tests/ssl/" % ROOTDIR
CONF = test.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


def rootdir(*p):
    return os.path.join(SSLDIR, *p)


CERTDIR = rootdir("certs")
KEYDIR = rootdir("private")


class CertSetupTestCase(test.TestCase):

    def setUp(self):
        super(CertSetupTestCase, self).setUp()
        CONF.signing.certfile = os.path.join(CERTDIR, 'signing_cert.pem')
        CONF.signing.ca_certs = os.path.join(CERTDIR, "ca.pem")
        CONF.signing.keyfile = os.path.join(KEYDIR, "signing_key.pem")

        self.load_backends()
        self.controller = token.controllers.Auth()

    def test_can_handle_missing_certs(self):
        self.opt_in_group('signing', token_format='PKI')
        self.opt_in_group('signing', certfile='invalid')
        user = {
            'id': 'fake1',
            'name': 'fake1',
            'password': 'fake1',
            'domain_id': DEFAULT_DOMAIN_ID
        }
        body_dict = {
            'passwordCredentials': {
                'userId': user['id'],
                'password': user['password'],
            },
        }
        self.identity_api.create_user(user['id'], user)
        self.assertRaises(exception.UnexpectedError,
                          self.controller.authenticate,
                          {}, body_dict)

    def test_create_certs(self):
        ssl = openssl.ConfigurePKI(None, None)
        ssl.run()
        self.assertTrue(os.path.exists(CONF.signing.certfile))
        self.assertTrue(os.path.exists(CONF.signing.ca_certs))
        self.assertTrue(os.path.exists(CONF.signing.keyfile))

    def tearDown(self):
        try:
            shutil.rmtree(rootdir(SSLDIR))
        except OSError:
            pass
        super(CertSetupTestCase, self).tearDown()
