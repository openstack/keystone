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

import base64
import hashlib
import hmac
import uuid

import http.client

from keystone.api import s3tokens
from keystone.common import provider_api
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs


class S3ContribCore(test_v3.RestfulTestCase):
    def setUp(self):
        super(S3ContribCore, self).setUp()

        self.load_backends()

        self.cred_blob, self.credential = unit.new_ec2_credential(
            self.user['id'], self.project_id)
        PROVIDERS.credential_api.create_credential(
            self.credential['id'], self.credential)

    def test_good_response(self):
        sts = 'string to sign'  # opaque string from swift3
        sig = hmac.new(self.cred_blob['secret'].encode('ascii'),
                       sts.encode('ascii'), hashlib.sha1).digest()
        resp = self.post(
            '/s3tokens',
            body={'credentials': {
                'access': self.cred_blob['access'],
                'signature': base64.b64encode(sig).strip(),
                'token': base64.b64encode(sts.encode('ascii')).strip(),
            }},
            expected_status=http.client.OK)
        self.assertValidProjectScopedTokenResponse(resp, self.user,
                                                   forbid_token_id=True)

    def test_bad_request(self):
        self.post(
            '/s3tokens',
            body={},
            expected_status=http.client.BAD_REQUEST)

        self.post(
            '/s3tokens',
            body="not json",
            expected_status=http.client.BAD_REQUEST)

        self.post(
            '/s3tokens',
            expected_status=http.client.BAD_REQUEST)

    def test_bad_response(self):
        self.post(
            '/s3tokens',
            body={'credentials': {
                'access': self.cred_blob['access'],
                'signature': base64.b64encode(b'totally not the sig').strip(),
                'token': base64.b64encode(b'string to sign').strip(),
            }},
            expected_status=http.client.UNAUTHORIZED)

    def test_good_signature_v1(self):
        creds_ref = {'secret':
                     u'b121dd41cdcc42fe9f70e572e84295aa'}
        credentials = {'token':
                       'UFVUCjFCMk0yWThBc2dUcGdBbVk3UGhDZmc9PQphcHB'
                       'saWNhdGlvbi9vY3RldC1zdHJlYW0KVHVlLCAxMSBEZWMgMjAxM'
                       'iAyMTo0MTo0MSBHTVQKL2NvbnRfczMvdXBsb2FkZWRfZnJ'
                       'vbV9zMy50eHQ=',
                       'signature': 'IL4QLcLVaYgylF9iHj6Wb8BGZsw='}

        self.assertIsNone(s3tokens.S3Resource._check_signature(
            creds_ref, credentials))

    def test_bad_signature_v1(self):
        creds_ref = {'secret':
                     u'b121dd41cdcc42fe9f70e572e84295aa'}
        credentials = {'token':
                       'UFVUCjFCMk0yWThBc2dUcGdBbVk3UGhDZmc9PQphcHB'
                       'saWNhdGlvbi9vY3RldC1zdHJlYW0KVHVlLCAxMSBEZWMgMjAxM'
                       'iAyMTo0MTo0MSBHTVQKL2NvbnRfczMvdXBsb2FkZWRfZnJ'
                       'vbV9zMy50eHQ=',
                       'signature': uuid.uuid4().hex}

        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

    def test_good_signature_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zMy9hd3M0X3JlcXVlc3QKZjIy'
                       'MTU1ODBlZWI5YTE2NzM1MWJkOTNlODZjM2I2ZjA0YTkyOGY1'
                       'YzU1MjBhMzkzNWE0NTM1NDBhMDk1NjRiNQ==',
                       'signature':
                       '730ba8f58df6ffeadd78f402e990b2910d60'
                       'bc5c2aec63619734f096a4dd77be'}

        self.assertIsNone(s3tokens.S3Resource._check_signature(
            creds_ref, credentials))

    def test_good_iam_signature_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9pYW0vYXdzNF9yZXF1ZXN0CmYy'
                       'MjE1NTgwZWViOWExNjczNTFiZDkzZTg2YzNiNmYwNGE5Mjhm'
                       'NWM1NTIwYTM5MzVhNDUzNTQwYTA5NTY0YjU=',
                       'signature':
                       'db4e15b3040f6afaa9d9d16002de2fc3425b'
                       'eea0c6ea8c1b2bb674f052030b7d'}

        self.assertIsNone(s3tokens.S3Resource._check_signature(
            creds_ref, credentials))

    def test_good_sts_signature_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zdHMvYXdzNF9yZXF1ZXN0CmYy'
                       'MjE1NTgwZWViOWExNjczNTFiZDkzZTg2YzNiNmYwNGE5Mjhm'
                       'NWM1NTIwYTM5MzVhNDUzNTQwYTA5NTY0YjU=',
                       'signature':
                       '3aa0b6f1414b92b2a32584068f83c6d09b7f'
                       'daa11d4ea58912bbf1d8616ef56d'}

        self.assertIsNone(s3tokens.S3Resource._check_signature(
            creds_ref, credentials))

    def test_bad_signature_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # the signature is wrong on an otherwise correctly formed token
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zMy9hd3M0X3JlcXVlc3QKZjIy'
                       'MTU1ODBlZWI5YTE2NzM1MWJkOTNlODZjM2I2ZjA0YTkyOGY1'
                       'YzU1MjBhMzkzNWE0NTM1NDBhMDk1NjRiNQ==',
                       'signature': uuid.uuid4().hex}

        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

    def test_bad_service_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # use 'bad' as the service scope instead of a recognised service
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9iYWQvYXdzNF9yZXF1ZXN0CmYy'
                       'MjE1NTgwZWViOWExNjczNTFiZDkzZTg2YzNiNmYwNGE5Mjhm'
                       'NWM1NTIwYTM5MzVhNDUzNTQwYTA5NTY0YjU=',
                       'signature':
                       '1a2dec50eb1bba97887d1103c2ead6a39911'
                       '98c4be2537cf14d40b64cceb888b'}

        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

    def test_bad_signing_key_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # signed with aws4_badrequest instead of aws4_request
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zMy9hd3M0X3JlcXVlc3QKZjIy'
                       'MTU1ODBlZWI5YTE2NzM1MWJkOTNlODZjM2I2ZjA0YTkyOGY1'
                       'YzU1MjBhMzkzNWE0NTM1NDBhMDk1NjRiNQ==',
                       'signature':
                       '52d02211a3767d00b2104ab28c9859003b0e'
                       '9c8735cd10de7975f3b1212cca41'}

        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

    def test_bad_short_scope_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # credential scope has too few parts, missing final /aws4_request
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zMwpmMjIxNTU4MGVlYjlhMTY3'
                       'MzUxYmQ5M2U4NmMzYjZmMDRhOTI4ZjVjNTUyMGEzOTM1YTQ1'
                       'MzU0MGEwOTU2NGI1',
                       'signature':
                       '28a075f1ee41e96c431153914998443ff0f5'
                       '5fe93d31b37181f13ff4865942a2'}

        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

    def test_bad_token_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # token has invalid format of first part
        credentials = {'token':
                       'QVdTNC1BQUEKWApYClg=',
                       'signature': ''}
        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)

        # token has invalid format of scope
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgpYCi8vczMvYXdzTl9yZXF1ZXN0Clg=',
                       'signature': ''}
        self.assertRaises(exception.Unauthorized,
                          s3tokens.S3Resource._check_signature,
                          creds_ref, credentials)
