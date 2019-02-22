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
import uuid

from keystone.common import jwt_utils
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.token import provider
from keystone.token.providers import jws

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class TestJWSProvider(unit.TestCase):

    def setUp(self):
        super(TestJWSProvider, self).setUp()
        self.config_fixture.config(group='token', provider='jws')
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))
        self.provider = jws.Provider()

    def test_invalid_token_raises_token_not_found(self):
        token_id = uuid.uuid4().hex
        self.assertRaises(
            exception.TokenNotFound,
            self.provider.validate_token,
            token_id
        )

    def test_non_existent_private_key_raises_system_exception(self):
        private_key = os.path.join(
            CONF.jwt_tokens.jws_private_key_repository, 'private.pem'
        )
        os.remove(private_key)
        self.assertRaises(SystemExit, jws.Provider)

    def test_non_existent_public_key_repo_raises_system_exception(self):
        for f in os.listdir(CONF.jwt_tokens.jws_public_key_repository):
            path = os.path.join(CONF.jwt_tokens.jws_public_key_repository, f)
            os.remove(path)
        os.rmdir(CONF.jwt_tokens.jws_public_key_repository)
        self.assertRaises(SystemExit, jws.Provider)

    def test_empty_public_key_repo_raises_system_exception(self):
        for f in os.listdir(CONF.jwt_tokens.jws_public_key_repository):
            path = os.path.join(CONF.jwt_tokens.jws_public_key_repository, f)
            os.remove(path)
        self.assertRaises(SystemExit, jws.Provider)

    def test_unable_to_verify_token_with_missing_public_key(self):
        # create token, signing with private key
        token = token_model.TokenModel()
        token.methods = ['password']
        token.user_id = uuid.uuid4().hex
        token.audit_id = provider.random_urlsafe_str()
        token.expires_at = utils.isotime(
            provider.default_expire_time(), subsecond=True
        )
        token_id, issued_at = self.provider.generate_id_and_issued_at(token)

        # remove the public key for the token we just created
        current_pub_key = os.path.join(
            CONF.jwt_tokens.jws_public_key_repository, 'public.pem'
        )
        os.remove(current_pub_key)

        # create additional public keys
        for _ in range(2):
            private_key_path = os.path.join(
                CONF.jwt_tokens.jws_private_key_repository,
                uuid.uuid4().hex
            )
            pub_key_path = os.path.join(
                CONF.jwt_tokens.jws_public_key_repository,
                uuid.uuid4().hex
            )
            jwt_utils.create_jws_keypair(private_key_path, pub_key_path)

        # validate token and ensure it returns a 404
        self.assertRaises(
            exception.TokenNotFound,
            self.provider.validate_token,
            token_id
        )

    def test_verify_token_with_multiple_public_keys_present(self):
        token = token_model.TokenModel()
        token.methods = ['password']
        token.user_id = uuid.uuid4().hex
        token.audit_id = provider.random_urlsafe_str()
        token.expires_at = utils.isotime(
            provider.default_expire_time(), subsecond=True
        )
        token_id, issued_at = self.provider.generate_id_and_issued_at(token)

        for _ in range(2):
            private_key_path = os.path.join(
                CONF.jwt_tokens.jws_private_key_repository,
                uuid.uuid4().hex
            )
            pub_key_path = os.path.join(
                CONF.jwt_tokens.jws_public_key_repository,
                uuid.uuid4().hex
            )
            jwt_utils.create_jws_keypair(private_key_path, pub_key_path)

        # make sure we iterate through all public keys on disk and we can still
        # validate the token
        self.provider.validate_token(token_id)
