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

import shutil
import uuid

import keystone.conf
from keystone.credential.providers import fernet
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database

CONF = keystone.conf.CONF


class TestFernetCredentialProvider(unit.TestCase):
    def setUp(self):
        super(TestFernetCredentialProvider, self).setUp()
        self.provider = fernet.Provider()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                fernet.MAX_ACTIVE_KEYS
            )
        )

    def config_overrides(self):
        super(TestFernetCredentialProvider, self).config_overrides()

    def test_valid_data_encryption(self):
        blob = uuid.uuid4().hex
        encrypted_blob = self.provider.encrypt(blob)
        decrypted_blob = self.provider.decrypt(encrypted_blob)

        self.assertNotEqual(blob, encrypted_blob)
        self.assertEqual(blob, decrypted_blob)

    def test_encrypt_with_invalid_key_raises_exception(self):
        shutil.rmtree(CONF.credential.key_repository)
        blob = uuid.uuid4().hex
        self.assertRaises(
            exception.CredentialEncryptionError,
            self.provider.encrypt,
            blob
        )

    def test_decrypt_with_invalid_key_raises_exception(self):
        blob = uuid.uuid4().hex
        encrypted_blob = self.provider.encrypt(blob)
        shutil.rmtree(CONF.credential.key_repository)
        self.assertRaises(
            exception.CredentialEncryptionError,
            self.provider.decrypt,
            encrypted_blob
        )
