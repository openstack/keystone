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

import fixtures
import hashlib
import uuid

from oslo_log import log

from keystone.common import fernet_utils
from keystone.credential.providers import fernet as credential_fernet
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database


class TestFernetCredentialProvider(unit.TestCase):
    def setUp(self):
        super(TestFernetCredentialProvider, self).setUp()
        self.provider = credential_fernet.Provider()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    def test_valid_data_encryption(self):
        blob = uuid.uuid4().hex
        encrypted_blob, primary_key_hash = self.provider.encrypt(blob)
        decrypted_blob = self.provider.decrypt(encrypted_blob)

        self.assertNotEqual(blob, encrypted_blob)
        self.assertEqual(blob, decrypted_blob)
        self.assertIsNotNone(primary_key_hash)


class TestFernetCredentialProviderWithNullKey(unit.TestCase):
    def setUp(self):
        super(TestFernetCredentialProviderWithNullKey, self).setUp()
        self.provider = credential_fernet.Provider()
        self.useFixture(database.Database())
        # Only do this to set the key_repository location in configuration. To
        # test the null key path, we need to make it so that the key repository
        # doesn't actually exist. If you're running the tests locally and have
        # bootstrapped a credential key repository in
        # `/etc/keystone/credential-keys` this will fail unless we override the
        # default.
        self.config_fixture.config(
            group='credential',
            key_repository=self.useFixture(fixtures.TempDir()).path
        )

    def test_encryption_with_null_key(self):
        null_key = fernet_utils.NULL_KEY
        # NOTE(lhinds) This is marked as #nosec since bandit will see SHA1
        # which is marked insecure. Keystone uses SHA1 in this case as part of
        # HMAC-SHA1 which is currently not insecure but will still get
        # caught when scanning with bandit.
        null_key_hash = hashlib.sha1(null_key).hexdigest()  # nosec

        blob = uuid.uuid4().hex
        encrypted_blob, primary_key_hash = self.provider.encrypt(blob)
        self.assertEqual(null_key_hash, primary_key_hash)
        self.assertNotEqual(blob, encrypted_blob)

        decrypted_blob = self.provider.decrypt(encrypted_blob)
        self.assertEqual(blob, decrypted_blob)

    def test_warning_is_logged_when_encrypting_with_null_key(self):
        blob = uuid.uuid4().hex
        logging_fixture = self.useFixture(fixtures.FakeLogger(level=log.DEBUG))
        expected_output = (
            'Encrypting credentials with the null key. Please properly '
            'encrypt credentials using `keystone-manage credential_setup`, '
            '`keystone-manage credential_migrate`, and `keystone-manage '
            'credential_rotate`'
        )
        encrypted_blob, primary_key_hash = self.provider.encrypt(blob)
        self.assertIn(expected_output, logging_fixture.output)
