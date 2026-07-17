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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import fixtures

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
        super().setUp()
        self.config_fixture.config(group='token', provider='jws')
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))
        self.provider = jws.Provider()

    def test_invalid_token_raises_token_not_found(self):
        token_id = uuid.uuid4().hex
        self.assertRaises(
            exception.TokenNotFound, self.provider.validate_token, token_id
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
                CONF.jwt_tokens.jws_private_key_repository, uuid.uuid4().hex
            )
            pub_key_path = os.path.join(
                CONF.jwt_tokens.jws_public_key_repository, uuid.uuid4().hex
            )
            jwt_utils.create_jws_keypair(private_key_path, pub_key_path)

        # validate token and ensure it returns a 404
        self.assertRaises(
            exception.TokenNotFound, self.provider.validate_token, token_id
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
                CONF.jwt_tokens.jws_private_key_repository, uuid.uuid4().hex
            )
            pub_key_path = os.path.join(
                CONF.jwt_tokens.jws_public_key_repository, uuid.uuid4().hex
            )
            jwt_utils.create_jws_keypair(private_key_path, pub_key_path)

        # make sure we iterate through all public keys on disk and we can still
        # validate the token
        self.provider.validate_token(token_id)


class TestCreateJWSKeypair(unit.TestCase):
    """Tests for jwt_utils.create_jws_keypair key generation per algorithm."""

    _EXPECTED_KEY_TYPES = {
        'ES256': (ec.EllipticCurvePrivateKey, ec.SECP256R1),
        'ES384': (ec.EllipticCurvePrivateKey, ec.SECP384R1),
        'ES512': (ec.EllipticCurvePrivateKey, ec.SECP521R1),
        'EdDSA': (ed25519.Ed25519PrivateKey, None),
    }

    def _generate_and_load_keys(self, algorithm):
        tmp = self.useFixture(fixtures.TempDir()).path
        priv_path = os.path.join(tmp, 'private.pem')
        pub_path = os.path.join(tmp, 'public.pem')
        jwt_utils.create_jws_keypair(priv_path, pub_path, algorithm=algorithm)
        with open(priv_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    def test_es256_generates_p256_key(self):
        priv, pub = self._generate_and_load_keys('ES256')
        self.assertIsInstance(priv, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(priv.curve, ec.SECP256R1)

    def test_es384_generates_p384_key(self):
        priv, pub = self._generate_and_load_keys('ES384')
        self.assertIsInstance(priv, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(priv.curve, ec.SECP384R1)

    def test_es512_generates_p521_key(self):
        priv, pub = self._generate_and_load_keys('ES512')
        self.assertIsInstance(priv, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(priv.curve, ec.SECP521R1)

    def test_eddsa_generates_ed25519_key(self):
        priv, pub = self._generate_and_load_keys('EdDSA')
        self.assertIsInstance(priv, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(pub, ed25519.Ed25519PublicKey)

    def test_unsupported_algorithm_raises_value_error(self):
        tmp = self.useFixture(fixtures.TempDir()).path
        self.assertRaises(
            ValueError,
            jwt_utils.create_jws_keypair,
            os.path.join(tmp, 'priv.pem'),
            os.path.join(tmp, 'pub.pem'),
            algorithm='RS256',
        )


class TestJWSProviderAlgorithmSelection(unit.TestCase):
    """End-to-end sign/verify for every supported algorithm."""

    def _setup_provider(self, algorithm, accepted=None):
        self.config_fixture.config(group='token', provider='jws')
        self.config_fixture.config(group='jwt_tokens', jws_algorithm=algorithm)
        if accepted is None:
            accepted = [algorithm]
        self.config_fixture.config(
            group='jwt_tokens', jws_accepted_algorithms=accepted
        )
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))
        return jws.Provider()

    def _make_token(self, prov):
        token = token_model.TokenModel()
        token.methods = ['password']
        token.user_id = uuid.uuid4().hex
        token.audit_id = provider.random_urlsafe_str()
        token.expires_at = utils.isotime(
            provider.default_expire_time(), subsecond=True
        )
        return prov.generate_id_and_issued_at(token)

    def test_roundtrip_es256(self):
        prov = self._setup_provider('ES256')
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_roundtrip_es384(self):
        prov = self._setup_provider('ES384')
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_roundtrip_es512(self):
        prov = self._setup_provider('ES512')
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_roundtrip_eddsa(self):
        prov = self._setup_provider('EdDSA')
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_default_algorithm_is_es256(self):
        """Without explicit jws_algorithm, the default is ES256."""
        self.config_fixture.config(group='token', provider='jws')
        self.useFixture(ksfixtures.JWSKeyRepository(self.config_fixture))
        prov = jws.Provider()
        self.assertEqual('ES256', CONF.jwt_tokens.jws_algorithm)
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_multi_algorithm_validation(self):
        """Validate ES256 token when verifier accepts ES256 and ES384."""
        prov = self._setup_provider('ES256', accepted=['ES256', 'ES384'])
        token_id, _ = self._make_token(prov)
        prov.validate_token(token_id)

    def test_token_rejected_when_algorithm_not_accepted(self):
        """Reject ES256 token when verifier only accepts ES384."""
        prov_sign = self._setup_provider('ES256', accepted=['ES256'])
        token_id, _ = self._make_token(prov_sign)

        # Reconfigure to only accept ES384; keep same key repos so
        # the token is structurally valid but algorithmically rejected.
        self.config_fixture.config(
            group='jwt_tokens', jws_accepted_algorithms=['ES384']
        )
        prov_verify = jws.Provider()
        self.assertRaises(
            exception.TokenNotFound, prov_verify.validate_token, token_id
        )

    def test_algorithm_migration_scenario(self):
        """Simulate a migration from ES256 to EdDSA.

        1. Generate a token with ES256.
        2. Reconfigure to sign with EdDSA but accept both algorithms.
        3. The old ES256 token must still validate.
        4. A new EdDSA token must also validate.
        """
        # Step 1: issue token with ES256
        prov_old = self._setup_provider('ES256')
        token_id_old, _ = self._make_token(prov_old)

        # Save the ES256 public key so the new provider can still verify it
        old_pub_repo = CONF.jwt_tokens.jws_public_key_repository
        old_pub_keys = []
        for fname in os.listdir(old_pub_repo):
            path = os.path.join(old_pub_repo, fname)
            with open(path, 'rb') as f:
                old_pub_keys.append((fname, f.read()))

        # Step 2: stand up a new provider with EdDSA
        prov_new = self._setup_provider('EdDSA', accepted=['EdDSA', 'ES256'])

        # Copy old ES256 public keys into the new public key repository
        new_pub_repo = CONF.jwt_tokens.jws_public_key_repository
        for fname, data in old_pub_keys:
            dest = os.path.join(new_pub_repo, 'old_' + fname)
            with open(dest, 'wb') as f:
                f.write(data)

        # Step 3: old token (ES256) must still validate
        prov_new.validate_token(token_id_old)

        # Step 4: new token (EdDSA) must also validate
        token_id_new, _ = self._make_token(prov_new)
        prov_new.validate_token(token_id_new)
