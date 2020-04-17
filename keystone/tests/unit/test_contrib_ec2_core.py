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

import datetime
import hashlib

import http.client
from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_utils import timeutils

from keystone.common import provider_api
from keystone.common import utils
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

    def test_valid_authentication_response_with_proper_secret(self):
        signer = ec2_utils.Ec2Signer(self.cred_blob['secret'])
        timestamp = utils.isotime(timeutils.utcnow())
        credentials = {
            'access': self.cred_blob['access'],
            'secret': self.cred_blob['secret'],
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'SignatureVersion': '2',
                'Action': 'Test',
                'Timestamp': timestamp
            },
        }
        credentials['signature'] = signer.generate(credentials)
        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.OK)
        self.assertValidProjectScopedTokenResponse(resp, self.user)

    def test_valid_authentication_response_with_signature_v4(self):
        signer = ec2_utils.Ec2Signer(self.cred_blob['secret'])
        timestamp = utils.isotime(timeutils.utcnow())
        hashed_payload = (
            'GET\n'
            '/\n'
            'Action=Test\n'
            'host:localhost\n'
            'x-amz-date:' + timestamp + '\n'
            '\n'
            'host;x-amz-date\n'
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        body_hash = hashlib.sha256(hashed_payload.encode()).hexdigest()
        amz_credential = (
            'AKIAIOSFODNN7EXAMPLE/%s/us-east-1/iam/aws4_request,' %
            timestamp[:8])

        credentials = {
            'access': self.cred_blob['access'],
            'secret': self.cred_blob['secret'],
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'Action': 'Test',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-SignedHeaders': 'host,x-amz-date,',
                'X-Amz-Credential': amz_credential
            },
            'headers': {
                'X-Amz-Date': timestamp
            },
            'body_hash': body_hash
        }
        credentials['signature'] = signer.generate(credentials)
        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.OK)
        self.assertValidProjectScopedTokenResponse(resp, self.user)

    def test_authenticate_with_empty_body_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            body={},
            expected_status=http.client.BAD_REQUEST)

    def test_authenticate_without_json_request_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            body='not json',
            expected_status=http.client.BAD_REQUEST)

    def test_authenticate_without_request_body_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            expected_status=http.client.BAD_REQUEST)

    def test_authenticate_without_proper_secret_returns_unauthorized(self):
        signer = ec2_utils.Ec2Signer('totally not the secret')
        timestamp = utils.isotime(timeutils.utcnow())
        credentials = {
            'access': self.cred_blob['access'],
            'secret': 'totally not the secret',
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'SignatureVersion': '2',
                'Action': 'Test',
                'Timestamp': timestamp
            },
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED)

    def test_authenticate_expired_request(self):
        self.config_fixture.config(
            group='credential',
            auth_ttl=5
        )
        signer = ec2_utils.Ec2Signer(self.cred_blob['secret'])
        past = timeutils.utcnow() - datetime.timedelta(minutes=10)
        timestamp = utils.isotime(past)
        credentials = {
            'access': self.cred_blob['access'],
            'secret': self.cred_blob['secret'],
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'SignatureVersion': '2',
                'Action': 'Test',
                'Timestamp': timestamp
            },
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED)

    def test_authenticate_expired_request_v4(self):
        self.config_fixture.config(
            group='credential',
            auth_ttl=5
        )
        signer = ec2_utils.Ec2Signer(self.cred_blob['secret'])
        past = timeutils.utcnow() - datetime.timedelta(minutes=10)
        timestamp = utils.isotime(past)
        hashed_payload = (
            'GET\n'
            '/\n'
            'Action=Test\n'
            'host:localhost\n'
            'x-amz-date:' + timestamp + '\n'
            '\n'
            'host;x-amz-date\n'
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        body_hash = hashlib.sha256(hashed_payload.encode()).hexdigest()
        amz_credential = (
            'AKIAIOSFODNN7EXAMPLE/%s/us-east-1/iam/aws4_request,' %
            timestamp[:8])

        credentials = {
            'access': self.cred_blob['access'],
            'secret': self.cred_blob['secret'],
            'host': 'localhost',
            'verb': 'GET',
            'path': '/',
            'params': {
                'Action': 'Test',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-SignedHeaders': 'host,x-amz-date,',
                'X-Amz-Credential': amz_credential
            },
            'headers': {
                'X-Amz-Date': timestamp
            },
            'body_hash': body_hash
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED)
