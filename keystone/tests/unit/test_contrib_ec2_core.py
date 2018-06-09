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

from keystoneclient.contrib.ec2 import utils as ec2_utils
from six.moves import http_client

from keystone.common import provider_api
from keystone.contrib.ec2 import controllers
from keystone.tests import unit
from keystone.tests.unit import test_v3


PROVIDERS = provider_api.ProviderAPIs


class EC2ContribCoreV3(test_v3.RestfulTestCase):
    def setUp(self):
        super(EC2ContribCoreV3, self).setUp()

        self.cred_blob, self.credential = unit.new_ec2_credential(
            self.user['id'], self.project_id)
        PROVIDERS.credential_api.create_credential(
            self.credential['id'], self.credential)

        self.controller = controllers.Ec2ControllerV3

    def test_valid_authentication_response_with_proper_secret(self):
        signer = ec2_utils.Ec2Signer(self.cred_blob['secret'])
        credentials = {
            'access': self.cred_blob['access'],
            'secret': self.cred_blob['secret'],
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'SignatureVersion': '2',
                'Action': 'Test',
                'Timestamp': '2007-01-31T23:59:59Z'
            },
        }
        credentials['signature'] = signer.generate(credentials)
        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http_client.OK)
        self.assertValidProjectScopedTokenResponse(resp, self.user)

    def test_authenticate_with_empty_body_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            body={},
            expected_status=http_client.BAD_REQUEST)

    def test_authenticate_without_json_request_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            body='not json',
            expected_status=http_client.BAD_REQUEST)

    def test_authenticate_without_request_body_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            expected_status=http_client.BAD_REQUEST)

    def test_authenticate_without_proper_secret_returns_unauthorized(self):
        signer = ec2_utils.Ec2Signer('totally not the secret')
        credentials = {
            'access': self.cred_blob['access'],
            'secret': 'totally not the secret',
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'SignatureVersion': '2',
                'Action': 'Test',
                'Timestamp': '2007-01-31T23:59:59Z'
            },
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http_client.UNAUTHORIZED)
