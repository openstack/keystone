# Copyright 2015 Intel Corporation
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

import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils

from keystone.contrib.ec2 import controllers
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database


class TestCredentialEc2(unit.TestCase):
    # TODO(davechen): more testcases for ec2 credential are expected here and
    # the file name would be renamed to "test_credential" to correspond with
    # "test_v3_credential.py".
    def setUp(self):
        super(TestCredentialEc2, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.user_id = self.user_foo['id']
        self.project_id = self.tenant_bar['id']
        self.blob = {'access': uuid.uuid4().hex,
                     'secret': uuid.uuid4().hex}
        self.controller = controllers.Ec2Controller()
        self.creds_ref = {'user_id': self.user_id,
                          'tenant_id': self.project_id,
                          'access': self.blob['access'],
                          'secret': self.blob['secret'],
                          'trust_id': None}

    def test_signature_validate_no_host_port(self):
        """Test signature validation with the access/secret provided."""
        access = self.blob['access']
        secret = self.blob['secret']
        signer = ec2_utils.Ec2Signer(secret)
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}
        request = {'host': 'foo',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        signature = signer.generate(request)

        sig_ref = {'access': access,
                   'signature': signature,
                   'host': 'foo',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}

        # Now validate the signature based on the dummy request
        self.assertTrue(self.controller.check_signature(self.creds_ref,
                                                        sig_ref))

    def test_signature_validate_with_host_port(self):
        """Test signature validation when host is bound with port.

        Host is bound with a port, generally, the port here is not the
        standard port for the protocol, like '80' for HTTP and port 443
        for HTTPS, the port is not omitted by the client library.
        """
        access = self.blob['access']
        secret = self.blob['secret']
        signer = ec2_utils.Ec2Signer(secret)
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}
        request = {'host': 'foo:8181',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        signature = signer.generate(request)

        sig_ref = {'access': access,
                   'signature': signature,
                   'host': 'foo:8181',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}

        # Now validate the signature based on the dummy request
        self.assertTrue(self.controller.check_signature(self.creds_ref,
                                                        sig_ref))

    def test_signature_validate_with_missed_host_port(self):
        """Test signature validation when host is bound with well-known port.

        Host is bound with a port, but the port is well-know port like '80'
        for HTTP and port 443 for HTTPS, sometimes, client library omit
        the port but then make the request with the port.
        see (How to create the string to sign): 'http://docs.aws.amazon.com/
        general/latest/gr/signature-version-2.html'.

        Since "credentials['host']" is not set by client library but is
        taken from "req.host", so caused the differences.
        """
        access = self.blob['access']
        secret = self.blob['secret']
        signer = ec2_utils.Ec2Signer(secret)
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}
        # Omit the port to generate the signature.
        cnt_req = {'host': 'foo',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        signature = signer.generate(cnt_req)

        sig_ref = {'access': access,
                   'signature': signature,
                   'host': 'foo:8080',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}

        # Now validate the signature based on the dummy request
        # Check the signature again after omitting the port.
        self.assertTrue(self.controller.check_signature(self.creds_ref,
                                                        sig_ref))

    def test_signature_validate_no_signature(self):
        """Signature is not presented in signature reference data."""
        access = self.blob['access']
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}

        sig_ref = {'access': access,
                   'signature': None,
                   'host': 'foo:8080',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}

        creds_ref = {'user_id': self.user_id,
                     'tenant_id': self.project_id,
                     'access': self.blob['access'],
                     'secret': self.blob['secret'],
                     'trust_id': None
                     }

        # Now validate the signature based on the dummy request
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          creds_ref, sig_ref)

    def test_signature_validate_invalid_signature(self):
        """Signature is not signed on the correct data."""
        access = self.blob['access']
        secret = self.blob['secret']
        signer = ec2_utils.Ec2Signer(secret)
        params = {'SignatureMethod': 'HmacSHA256',
                  'SignatureVersion': '2',
                  'AWSAccessKeyId': access}
        request = {'host': 'bar',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}
        signature = signer.generate(request)

        sig_ref = {'access': access,
                   'signature': signature,
                   'host': 'foo:8080',
                   'verb': 'GET',
                   'path': '/bar',
                   'params': params}

        creds_ref = {'user_id': self.user_id,
                     'tenant_id': self.project_id,
                     'access': self.blob['access'],
                     'secret': self.blob['secret'],
                     'trust_id': None
                     }

        # Now validate the signature based on the dummy request
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          creds_ref, sig_ref)

    def test_check_non_admin_user(self):
        """Checking if user is admin causes uncaught error.

        When checking if a user is an admin, keystone.exception.Unauthorized
        is raised but not caught if the user is not an admin.
        """
        # make a non-admin user
        context = {'is_admin': False, 'token_id': uuid.uuid4().hex}

        # check if user is admin
        # no exceptions should be raised
        self.controller._is_admin(context)
