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

import random
import secrets
import string

from oslo_config import fixture as config_fixture

from keystone.common import password_hashing
import keystone.conf
from keystone.tests import unit

CONF = keystone.conf.CONF


class TestPasswordHashing(unit.BaseTestCase):
    OPTIONAL = object()
    ITERATIONS: int = 10

    def setUp(self):
        super().setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

    def test_scrypt(self):
        self.config_fixture.config(strict_password_check=True)
        self.config_fixture.config(
            group="identity", password_hash_algorithm="scrypt"
        )
        self.config_fixture.config(group="identity", max_password_length="96")
        # Few iterations to test different inputs
        for _ in range(self.ITERATIONS):
            password: str = "".join(  # type: ignore
                secrets.choice(string.printable)
                for i in range(random.randint(1, 72))
            )
            hashed = password_hashing.hash_password(password)
            self.assertTrue(password_hashing.check_password(password, hashed))

    def test_bcrypt(self):
        self.config_fixture.config(strict_password_check=True)
        self.config_fixture.config(
            group="identity", password_hash_algorithm="bcrypt"
        )
        self.config_fixture.config(group="identity", max_password_length="72")
        # Few iterations to test different inputs
        for _ in range(self.ITERATIONS):
            password: str = "".join(  # type: ignore
                secrets.choice(string.printable)
                for i in range(random.randint(1, 72))
            )
            hashed = password_hashing.hash_password(password)
            self.assertTrue(password_hashing.check_password(password, hashed))

    def test_bcrypt_sha256(self):
        self.config_fixture.config(strict_password_check=True)
        self.config_fixture.config(
            group="identity", password_hash_algorithm="bcrypt_sha256"
        )
        self.config_fixture.config(group="identity", max_password_length="96")
        # Few iterations to test different inputs
        for _ in range(self.ITERATIONS):
            password: str = "".join(  # type: ignore
                secrets.choice(string.printable)
                for i in range(random.randint(1, 96))
            )
            hashed = password_hashing.hash_password(password)
            self.assertTrue(password_hashing.check_password(password, hashed))

    def test_pbkdf2_sha512(self):
        self.config_fixture.config(strict_password_check=True)
        self.config_fixture.config(
            group="identity", password_hash_algorithm="pbkdf2_sha512"
        )
        self.config_fixture.config(group="identity", max_password_length="96")
        # Do few iterations to process different inputs
        for _ in range(self.ITERATIONS):
            password: str = "".join(  # type: ignore
                secrets.choice(string.printable)
                for i in range(random.randint(1, 96))
            )
            hashed = password_hashing.hash_password(password)
            self.assertTrue(password_hashing.check_password(password, hashed))
