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

import binascii
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from keystone.common import password_hashers
from keystone import exception

DEFAULT_ROUNDS: int = 25000


class Sha512(password_hashers.PasswordHasher):
    """passlib transition class for PBKDF2 Sha512 password hashing"""

    name: str = "pbkdf2_sha512"
    ident: str = "$pbkdf2-sha512$"
    hash_algo = hashes.SHA512()

    @staticmethod
    def hash(
        password: bytes, salt_size: int = 16, rounds: int = DEFAULT_ROUNDS
    ) -> str:
        """Generate password hash string with ident and params.

        https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/#pbkdf2

        :param bytes password: Password to be hashed.
        :param int salt_size: Number of random bytes to use as salt.
        :param int rounds: PBKDF2 iteration count.

        :returns: String in format ``$pbkdf2-sha512$<rounds>$<salt>$<digest>``
        """
        salt: bytes = os.urandom(salt_size)

        # Prepare the kdf function with params
        kdf = PBKDF2HMAC(
            algorithm=Sha512.hash_algo, length=64, salt=salt, iterations=rounds
        )

        # derive - create a digest
        key: bytes = kdf.derive(password)

        # make a `str` digest compatible with passlib
        digest_str: str = (
            binascii.b2a_base64(key).rstrip(b"=\n").decode("ascii")
        )
        # make a `str` salt
        salt_str: str = (
            binascii.b2a_base64(salt).rstrip(b"=\n").decode("ascii")
        )

        return f"{Sha512.ident}{rounds}${salt_str}${digest_str}"

    @staticmethod
    def needs_rehash(
        hashed: str, rounds: int = DEFAULT_ROUNDS, **kwargs
    ) -> bool:
        """Return True if hashed used fewer rounds than ``rounds``.

        :param str hashed: Stored password hash.
        :param int rounds: Target iteration count (defaults to
            DEFAULT_ROUNDS; callers should pass the operator-configured value).
        :returns: True when the hash should be upgraded on next login.
        """
        parts = hashed[1:].split('$')
        if len(parts) == 4:
            _, rounds_str, _, _ = parts
            try:
                return int(rounds_str) < rounds
            except ValueError:
                pass
        return True

    @staticmethod
    def verify(password: bytes, hashed: str) -> bool:
        """Verify hashing password would be equal to the `hashed` value

        :param bytes password: Password to verify
        :param string hashed: Hashed password. Used to extract hashing
            parameters

        :returns: boolean whether hashing password with the same parameters
            would match hashed value
        """
        data: str = hashed
        # split hashed string to extract parameters
        parts: list[str] = data[1:].split("$")
        rounds: int

        if len(parts) == 4:
            _, rounds_str, salt_str, digest_str = parts
            # Convert salt and digest back to bytes as opposite to how passlib
            # serializes them
            salt: bytes = password_hashers.b64s_decode(
                salt_str.replace(".", "+").encode("ascii")
            )
            digest: bytes = password_hashers.b64s_decode(
                digest_str.replace(".", "+").encode("ascii")
            )
            rounds = int(rounds_str)
        else:
            raise exception.PasswordValidationError("malformed password hash")

        # Prepare the kdf function with params
        kdf = PBKDF2HMAC(
            algorithm=Sha512.hash_algo, length=64, salt=salt, iterations=rounds
        )

        # Verify the key.
        # NOTE(gtema): cryptography raises exception when key does not match
        try:
            kdf.verify(password, digest)
            return True
        except InvalidKey:
            return False
