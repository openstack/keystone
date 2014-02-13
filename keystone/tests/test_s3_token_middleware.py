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

import testtools

from keystoneclient.middleware import s3_token as ksc_s3_token

from keystone.middleware import s3_token


class S3TokenMiddlewareTestBase(testtools.TestCase):
    def test_symbols(self):
        """Verify s3_token middleware symbols.

        Verify that the keystone version of s3_token middleware forwards the
        public symbols from the keystoneclient version of the s3_token
        middleware for backwards compatibility.

        """

        self.assertIs(ksc_s3_token.PROTOCOL_NAME, s3_token.PROTOCOL_NAME)
        self.assertIs(ksc_s3_token.split_path, s3_token.split_path)
        self.assertIs(ksc_s3_token.ServiceError, s3_token.ServiceError)
        self.assertIs(ksc_s3_token.filter_factory, s3_token.filter_factory)
        self.assertTrue(
            issubclass(s3_token.S3Token, ksc_s3_token.S3Token),
            's3_token.S3Token is not subclass of keystoneclient s3_token')
