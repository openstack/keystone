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

import os

import fixtures

from keystone.common import jwt_utils
from keystone.common import utils


class JWSKeyRepository(fixtures.Fixture):
    def __init__(self, config_fixture):
        super(JWSKeyRepository, self).__init__()
        self.config_fixture = config_fixture
        self.key_group = 'jwt_tokens'

    def setUp(self):
        super(JWSKeyRepository, self).setUp()

        # grab a couple of temporary directory file paths
        private_key_directory = self.useFixture(fixtures.TempDir()).path
        public_key_directory = self.useFixture(fixtures.TempDir()).path

        # set config to use temporary paths
        self.config_fixture.config(
            group=self.key_group,
            jws_private_key_repository=private_key_directory
        )
        self.config_fixture.config(
            group=self.key_group,
            jws_public_key_repository=public_key_directory
        )

        # create temporary repositories
        utils.create_directory(private_key_directory)
        utils.create_directory(public_key_directory)

        # create an asymmetric key pair for token signing and validation
        private_key_path = os.path.join(private_key_directory, 'private.pem')
        public_key_path = os.path.join(public_key_directory, 'public.pem')
        jwt_utils.create_jws_keypair(private_key_path, public_key_path)
