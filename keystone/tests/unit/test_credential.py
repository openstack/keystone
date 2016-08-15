# Copyright 2015 UnitedStack, Inc
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
from six.moves import http_client

from keystone.common import context
from keystone.common import request
from keystone.common import utils
from keystone.contrib.ec2 import controllers
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import rest

CRED_TYPE_EC2 = controllers.CRED_TYPE_EC2


class V2CredentialEc2TestCase(rest.RestfulTestCase):
    def setUp(self):
        super(V2CredentialEc2TestCase, self).setUp()
        self.user_id = self.user_foo['id']
        self.project_id = self.tenant_bar['id']
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def _get_token_id(self, r):
        return r.result['access']['token']['id']

    def _get_ec2_cred(self):
        uri = self._get_ec2_cred_uri()
        r = self.public_request(method='POST', token=self.get_scoped_token(),
                                path=uri, body={'tenant_id': self.project_id})
        return r.result['credential']

    def _get_ec2_cred_uri(self):
        return '/v2.0/users/%s/credentials/OS-EC2' % self.user_id

    def test_ec2_cannot_get_non_ec2_credential(self):
        access_key = uuid.uuid4().hex
        cred_id = utils.hash_access_key(access_key)
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id,
            project_id=self.project_id)
        non_ec2_cred['id'] = cred_id
        self.credential_api.create_credential(cred_id, non_ec2_cred)

        # if access_key is not found, ec2 controller raises Unauthorized
        # exception
        path = '/'.join([self._get_ec2_cred_uri(), access_key])
        self.public_request(method='GET', token=self.get_scoped_token(),
                            path=path,
                            expected_status=http_client.UNAUTHORIZED)

    def assertValidErrorResponse(self, r):
        # FIXME(wwwjfy): it's copied from test_v3.py. The logic of this method
        # in test_v2.py and test_v3.py (both are inherited from rest.py) has no
        # difference, so they should be refactored into one place. Also, the
        # function signatures in both files don't match the one in the parent
        # class in rest.py.
        resp = r.result
        self.assertIsNotNone(resp.get('error'))
        self.assertIsNotNone(resp['error'].get('code'))
        self.assertIsNotNone(resp['error'].get('title'))
        self.assertIsNotNone(resp['error'].get('message'))
        self.assertEqual(int(resp['error']['code']), r.status_code)

    def test_ec2_list_credentials(self):
        self._get_ec2_cred()
        uri = self._get_ec2_cred_uri()
        r = self.public_request(method='GET', token=self.get_scoped_token(),
                                path=uri)
        cred_list = r.result['credentials']
        self.assertEqual(1, len(cred_list))

        # non-EC2 credentials won't be fetched
        non_ec2_cred = unit.new_credential_ref(
            user_id=self.user_id,
            project_id=self.project_id)
        non_ec2_cred['type'] = uuid.uuid4().hex
        self.credential_api.create_credential(non_ec2_cred['id'],
                                              non_ec2_cred)
        r = self.public_request(method='GET', token=self.get_scoped_token(),
                                path=uri)
        cred_list_2 = r.result['credentials']
        # still one element because non-EC2 credentials are not returned.
        self.assertEqual(1, len(cred_list_2))
        self.assertEqual(cred_list[0], cred_list_2[0])


class V2CredentialEc2Controller(unit.TestCase):
    def setUp(self):
        super(V2CredentialEc2Controller, self).setUp()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.user_id = self.user_foo['id']
        self.project_id = self.tenant_bar['id']
        self.controller = controllers.Ec2Controller()
        self.blob, tmp_ref = unit.new_ec2_credential(
            user_id=self.user_id,
            project_id=self.project_id)

        self.creds_ref = (controllers.Ec2Controller
                          ._convert_v3_to_ec2_credential(tmp_ref))

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

        # Now validate the signature based on the dummy request
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          self.creds_ref, sig_ref)

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

        # Now validate the signature based on the dummy request
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          self.creds_ref, sig_ref)

    def test_check_non_admin_user(self):
        """Checking if user is admin causes uncaught error.

        When checking if a user is an admin, keystone.exception.Unauthorized
        is raised but not caught if the user is not an admin.
        """
        # make a non-admin user
        req = request.Request.blank('/')
        req.context = context.RequestContext(is_admin=False)
        req.context_dict['is_admin'] = False
        req.context_dict['token_id'] = uuid.uuid4().hex

        # check if user is admin
        # no exceptions should be raised
        self.controller._is_admin(req)
