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

import uuid

from keystone.contrib import s3
from keystone import exception
from keystone.tests import unit


class S3ContribCore(unit.TestCase):
    def setUp(self):
        super(S3ContribCore, self).setUp()

        self.load_backends()

        self.controller = s3.S3Controller()

    def test_good_signature_v1(self):
        creds_ref = {'secret':
                     u'b121dd41cdcc42fe9f70e572e84295aa'}
        credentials = {'token':
                       'UFVUCjFCMk0yWThBc2dUcGdBbVk3UGhDZmc9PQphcHB'
                       'saWNhdGlvbi9vY3RldC1zdHJlYW0KVHVlLCAxMSBEZWMgMjAxM'
                       'iAyMTo0MTo0MSBHTVQKL2NvbnRfczMvdXBsb2FkZWRfZnJ'
                       'vbV9zMy50eHQ=',
                       'signature': 'IL4QLcLVaYgylF9iHj6Wb8BGZsw='}

        self.assertIsNone(self.controller.check_signature(creds_ref,
                                                          credentials))

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
                          self.controller.check_signature,
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

        self.assertIsNone(self.controller.check_signature(creds_ref,
                                                          credentials))

    def test_bad_signature_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgoyMDE1MDgyNFQxMTIwNDFaCjIw'
                       'MTUwODI0L1JlZ2lvbk9uZS9zMy9hd3M0X3JlcXVlc3QKZjIy'
                       'MTU1ODBlZWI5YTE2NzM1MWJkOTNlODZjM2I2ZjA0YTkyOGY1'
                       'YzU1MjBhMzkzNWE0NTM1NDBhMDk1NjRiNQ==',
                       'signature': uuid.uuid4().hex}

        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          creds_ref, credentials)

    def test_bad_token_v4(self):
        creds_ref = {'secret':
                     u'e7a7a2240136494986991a6598d9fb9f'}
        # token has invalid format of first part
        credentials = {'token':
                       'QVdTNC1BQUEKWApYClg=',
                       'signature': ''}
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          creds_ref, credentials)

        # token has invalid format of scope
        credentials = {'token':
                       'QVdTNC1ITUFDLVNIQTI1NgpYCi8vczMvYXdzTl9yZXF1ZXN0Clg=',
                       'signature': ''}
        self.assertRaises(exception.Unauthorized,
                          self.controller.check_signature,
                          creds_ref, credentials)
