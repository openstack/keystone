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


class TestGeneratePartialPasswordHash(unit.BaseTestCase):
    def setUp(self):
        super().setUp()

        self.h = password_hashing.generate_partial_password_hash

        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.config(
            group="security_compliance",
            invalid_password_hash_secret_key="secret_key",
        )

    def test_equal_input_generates_equal_hash(self):
        args1 = ("password", "salt")
        args2 = ("password", "salt")

        hashed1 = self.h(*args1)
        hashed2 = self.h(*args2)

        self.assertEqual(hashed1, hashed2)

    def test_different_inputs_generate_different_hashes(self):
        params = [
            {
                "msg": "Different passwords",
                "args1": ("password1", "salt"),
                "args2": ("password2", "salt"),
            },
            {
                "msg": "Different salts",
                "args1": ("password", "salt1"),
                "args2": ("password", "salt2"),
            },
            {
                "msg": "Same but mixed inputs",
                "args1": ("password", "salt"),
                "args2": ("salt", "password"),
            },
        ]

        # test variability of: a) full hash; b) partial hash
        max_chars_conf = [None, 5]
        for data in params:
            for max_chars in max_chars_conf:
                msg = data["msg"] + f" ({max_chars=})"
                self.config_fixture.config(
                    group="security_compliance",
                    invalid_password_hash_max_chars=max_chars,
                )
                with self.subTest(msg=msg):
                    hashed1 = self.h(*data["args1"])
                    hashed2 = self.h(*data["args2"])
                    self.assertNotEqual(hashed1, hashed2, msg=msg)

    def test_generates_full_hash_by_default(self):
        args1 = ("password", "salt")
        args2 = ("password", "salt")

        # when `max_chars` is not specified, a default value will be used,
        # which is expected to return full hash
        hashed1 = self.h(*args1)

        self.config_fixture.config(
            group="security_compliance",
            # 1000 is larger than any supported hash function key length +
            # base64 encoding, so it should cause full hash to be returned
            invalid_password_hash_max_chars=1000,
        )
        hashed2 = self.h(*args2)

        self.assertEqual(len(hashed1), len(hashed2))

    def test_invalid_function_raises_value_error(self):
        args = ("password", "salt")
        self.config_fixture.config(
            group="security_compliance",
            invalid_password_hash_function="invalid",
        )

        self.assertRaises(ValueError, self.h, *args)

    def test_large_passwords(self):
        # 48042 bytes or 48 kB
        args1 = ("p" * 1000 * 48 + "1", "salt")
        args2 = ("p" * 1000 * 48 + "2", "salt")

        # test variability of: a) full hash; b) partial hash
        max_chars_conf = [None, 5]
        for max_chars in max_chars_conf:
            msg = f"Large password ({max_chars=})"
            self.config_fixture.config(
                group="security_compliance",
                invalid_password_hash_max_chars=max_chars,
            )
            with self.subTest(msg=msg):
                hashed1 = self.h(*args1)
                hashed2 = self.h(*args2)
                self.assertNotEqual(hashed1, hashed2, msg=msg)

    def test_different_conf_generates_different_hashes(self):
        args = ("password", "salt")

        params = [
            {
                "msg": "Different secret_keys",
                "conf1": {"invalid_password_hash_secret_key": "secret_key1"},
                "conf2": {"invalid_password_hash_secret_key": "secret_key2"},
            },
            {
                "msg": "Different max chars",
                "conf1": {"invalid_password_hash_max_chars": 3},
                "conf2": {"invalid_password_hash_max_chars": 4},
            },
            {
                "msg": "Different hash functions",
                "conf1": {"invalid_password_hash_function": "sha3_512"},
                "conf2": {"invalid_password_hash_function": "sha512"},
            },
        ]

        for data in params:
            with self.subTest(msg=data["msg"]):
                self.config_fixture.config(
                    group="security_compliance", **data["conf1"]
                )
                hashed1 = self.h(*args)
                self.config_fixture.config(
                    group="security_compliance", **data["conf2"]
                )
                hashed2 = self.h(*args)
                self.assertNotEqual(hashed1, hashed2, msg=data["msg"])

    def test_conf_secret_key_is_required(self):
        self.config_fixture.config(
            group="security_compliance", invalid_password_hash_secret_key=None
        )

        args = ("password", "salt")

        self.assertRaises(RuntimeError, self.h, *args)

    def test_returns_not_more_than_max_chars(self):
        args = ("password", "salt")

        max_chars_conf = [1, 5, 1000]
        for max_chars in max_chars_conf:
            self.config_fixture.config(
                group="security_compliance",
                invalid_password_hash_max_chars=max_chars,
            )
            with self.subTest(msg=max_chars):
                hashed = self.h(*args)

                self.assertLessEqual(
                    len(hashed), max_chars, msg=f"{max_chars=}"
                )
