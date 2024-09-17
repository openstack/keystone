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
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as Scrypt_kdf

from keystone.common import password_hashers
from keystone import exception


class Scrypt(password_hashers.PasswordHasher):
    """passlib transition class for implementing scrypt password hashing"""

    name: str = "scrypt"
    ident_values: set[str] = {"$scrypt$", "$7$"}

    @staticmethod
    def hash(
        password: bytes,
        salt_size: int = 16,
        n: int = 16,
        r: int = 8,
        p: int = 1,
        **kwargs,
    ) -> str:
        """Generate password hash string with ident and params

        https://docs.python.org/3/library/hashlib.html#hashlib.scrypt

        :param bytes password: Password to be hashed.
        :param int salt_size: Salt size.
        :param int n: CPU/Memory cost factor.
        :param int r: Block size.
        :param int p: Parallel count.

        :returns: String in format `$scrypt$ln=logN,r=R,p=P$salt$checksum`
        """
        salt: bytes = os.urandom(salt_size)
        # Prepare the kdf function
        kdf = Scrypt_kdf(salt=salt, length=32, n=2**n, r=r, p=p)
        # derive - build a digest
        digest = kdf.derive(password)
        # convert digest to string using stripped base64
        digest_str: str = (
            binascii.b2a_base64(digest).rstrip(b"=\n").decode("ascii")
        )
        # apply the same for the salt
        salt_str: str = (
            binascii.b2a_base64(salt).rstrip(b"=\n").decode("ascii")
        )
        return f"$scrypt$ln={n},r={r},p={p}${salt_str}${digest_str}"

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
        salt: bytes
        digest: bytes
        n: int
        p: int
        r: int

        if len(parts) == 4:
            ident, params, salt_str, digest_str = parts
            salt = password_hashers.b64s_decode(
                salt_str.replace(".", "+").encode("ascii")
            )
            digest = password_hashers.b64s_decode(
                digest_str.replace(".", "+").encode("ascii")
            )
        else:
            raise exception.PasswordValidationError("malformed password hash")

        for param in params.split(","):
            if param.startswith("ln="):
                n = 2 ** int(param[3:])
            elif param.startswith("p="):
                p = int(param[2:])
            elif param.startswith("r="):
                r = int(param[2:])

        # Prepare the kdf function
        kdf = Scrypt_kdf(salt=salt, length=32, n=n, r=r, p=p)
        # Cryptography raises exception on mismatch
        try:
            kdf.verify(password, digest)
            return True
        except InvalidKey:
            return False
