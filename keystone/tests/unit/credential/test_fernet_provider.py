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

import keystone.conf
from keystone.credential.providers import fernet
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
        encrypted_blob, primary_key_hash = self.provider.encrypt(blob)
        decrypted_blob = self.provider.decrypt(encrypted_blob)

        self.assertNotEqual(blob, encrypted_blob)
        self.assertEqual(blob, decrypted_blob)
        self.assertIsNotNone(primary_key_hash)
