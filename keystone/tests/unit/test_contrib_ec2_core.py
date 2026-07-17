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

from keystone.common import authorization
from keystone.common import provider_api
from keystone.common import utils
from keystone.tests import unit
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs


class EC2ContribCoreV3(test_v3.RestfulTestCase):
    def setUp(self):
        super().setUp()

        self.cred_blob, self.credential = unit.new_ec2_credential(
            self.user['id'], self.project_id
        )
        PROVIDERS.credential_api.create_credential(
            self.credential['id'], self.credential
        )

    def test_http_get_method_not_allowed(self):
        resp = self.get(
            '/ec2tokens',
            expected_status=http.client.METHOD_NOT_ALLOWED,
            convert=False,
        )
        self.assertEqual(http.client.METHOD_NOT_ALLOWED, resp.status_code)

    def _test_valid_authentication_response_with_proper_secret(self, **kwargs):
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
                'Timestamp': timestamp,
            },
        }
        credentials['signature'] = signer.generate(credentials)
        # Authenticate as system admin by default unless overridden via kwargs
        token = None
        if 'noauth' in kwargs and kwargs['noauth']:
            token = None
        else:
            PROVIDERS.assignment_api.create_system_grant_for_user(
                self.user_id, self.role_id
            )
            token = self.get_system_scoped_token()

        expected_status = kwargs.get('expected_status', http.client.OK)
        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=expected_status,
            token=token,
            noauth=kwargs.get('noauth'),
        )
        if expected_status == http.client.OK:
            self.assertValidProjectScopedTokenResponse(resp, self.user)

    def test_valid_authentication_response_with_proper_secret(self):
        self._test_valid_authentication_response_with_proper_secret()

    def test_valid_authentication_response_with_proper_secret_noauth(self):
        # ec2 endpoint now enforces RBAC; unauthenticated should be denied
        self._test_valid_authentication_response_with_proper_secret(
            expected_status=http.client.UNAUTHORIZED, noauth=True
        )

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
            f'AKIAIOSFODNN7EXAMPLE/{timestamp[:8]}/us-east-1/iam/aws4_request,'
        )

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
                'X-Amz-Credential': amz_credential,
            },
            'headers': {'X-Amz-Date': timestamp},
            'body_hash': body_hash,
        }
        credentials['signature'] = signer.generate(credentials)
        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.OK,
        )
        self.assertValidProjectScopedTokenResponse(resp, self.user)

    def test_authenticate_with_empty_body_returns_bad_request(self):
        self.post(
            '/ec2tokens', body={}, expected_status=http.client.BAD_REQUEST
        )

    def test_authenticate_without_json_request_returns_bad_request(self):
        self.post(
            '/ec2tokens',
            body='not json',
            expected_status=http.client.BAD_REQUEST,
        )

    def test_authenticate_without_request_body_returns_bad_request(self):
        self.post('/ec2tokens', expected_status=http.client.BAD_REQUEST)

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
                'Timestamp': timestamp,
            },
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED,
        )

    def test_authenticate_expired_request(self):
        self.config_fixture.config(group='credential', auth_ttl=5)
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
                'Timestamp': timestamp,
            },
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED,
        )

    def test_authenticate_expired_request_v4(self):
        self.config_fixture.config(group='credential', auth_ttl=5)
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
            f'AKIAIOSFODNN7EXAMPLE/{timestamp[:8]}/us-east-1/iam/aws4_request,'
        )

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
                'X-Amz-Credential': amz_credential,
            },
            'headers': {'X-Amz-Date': timestamp},
            'body_hash': body_hash,
        }
        credentials['signature'] = signer.generate(credentials)
        self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.UNAUTHORIZED,
        )

    def test_valid_ec2_token_invalid_for_regular_endpoints(self, **kwargs):
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
                'Timestamp': timestamp,
            },
        }
        credentials['signature'] = signer.generate(credentials)
        # Authenticate as system admin by default unless overridden via kwargs
        token = None
        if 'noauth' in kwargs and kwargs['noauth']:
            token = None
        else:
            PROVIDERS.assignment_api.create_system_grant_for_user(
                self.user_id, self.role_id
            )
            token = self.get_system_scoped_token()

        resp = self.post(
            '/ec2tokens',
            body={'credentials': credentials},
            expected_status=http.client.OK,
            token=token,
            noauth=kwargs.get('noauth'),
        )
        self.assertValidProjectScopedTokenResponse(resp, self.user)

        # Extract the EC2 credential token from the response - the password
        # token used for POST /ec2tokens is NOT the EC2 token.
        ec2_token = resp.headers['X-Subject-Token']
        self.assertEqual(['ec2credential'], resp.json['token']['methods'])

        # The EC2 token should be rejected by regular endpoints (check subset
        # the user should normally be able to query).
        self.get(
            '/users', token=ec2_token, expected_status=http.client.FORBIDDEN
        )
        self.get(
            f"/users/{self.user_id}",
            token=ec2_token,
            expected_status=http.client.FORBIDDEN,
        )
        self.get(
            '/auth/projects',
            token=ec2_token,
            expected_status=http.client.FORBIDDEN,
        )

        # The EC2 token should be still validated.
        self.get(
            '/auth/tokens',
            headers={"X-Subject-Token": ec2_token},
            token=token,
            expected_status=http.client.OK,
        )
        # Test reauth is also working
        resp = self.post(
            '/auth/tokens',
            headers={"X-Subject-Token": ec2_token},
            body={
                "auth": {
                    "identity": {
                        "methods": ["token"],
                        "token": {"id": ec2_token},
                    }
                }
            },
            token=token,
            expected_status=http.client.CREATED,
        )
        ec2_token = resp.headers['X-Subject-Token']
        self.assertIn('ec2credential', resp.json['token']['methods'])
