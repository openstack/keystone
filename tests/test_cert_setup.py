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
import unittest2 as test
import shutil

from keystone import config
from keystone.common import openssl

ROOTDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSLDIR = "%s/tests/ssl/" % ROOTDIR
CONF = config.CONF


def rootdir(*p):
    return os.path.join(SSLDIR, *p)


CERTDIR = rootdir("certs")
KEYDIR = rootdir("private")

CONF.signing.certfile = os.path.join(CERTDIR, 'signing_cert.pem')
CONF.signing.ca_certs = os.path.join(CERTDIR, "ca.pem")
CONF.signing.keyfile = os.path.join(KEYDIR, "signing_key.pem")


class CertSetupTestCase(test.TestCase):

    def test_create_certs(self):
        ssl = openssl.ConfigurePKI()
        ssl.run()
        self.assertTrue(os.path.exists(CONF.signing.certfile))
        self.assertTrue(os.path.exists(CONF.signing.ca_certs))
        self.assertTrue(os.path.exists(CONF.signing.keyfile))

    def tearDown(self):
        shutil.rmtree(rootdir(SSLDIR))
