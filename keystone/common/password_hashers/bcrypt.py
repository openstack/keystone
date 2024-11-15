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

import base64
import hmac

import bcrypt

from keystone.common import password_hashers
from keystone import exception


class Bcrypt(password_hashers.PasswordHasher):
    """passlib transition class for implementing bcrypt password hashing"""

    name: str = "bcrypt"
    ident_values: set[str] = {"$2$", "$2a$", "$2b$", "$2x$", "$2y$"}

    @staticmethod
    def hash(password: bytes, rounds: int = 12, **kwargs) -> str:
        """Generate password hash string with ident and params

        https://pypi.org/project/bcrypt/

        :param bytes password: Password to be hashed.
        :param int round: Count of rounds.

        :returns: String in format `$2b${rounds}${salt}{digest}`
        """
        salt: bytes = bcrypt.gensalt(rounds)
        digest: bytes = bcrypt.hashpw(password, salt)
        return digest.decode("ascii")

    @staticmethod
    def verify(password: bytes, hashed: str) -> bool:
        """Verify hashing password would be equal to the `hashed` value

        :param bytes password: Password to verify
        :param string hashed: Hashed password. Used to extract hashing
            parameters

        :returns: boolean whether hashing password with the same parameters
            would match hashed value
        """
        return bcrypt.checkpw(password, hashed.encode("ascii"))


class Bcrypt_sha256(password_hashers.PasswordHasher):
    """passlib transition class for bcrypt_sha256 password hashing"""

    name: str = "bcrypt_sha256"
    ident_values: set[str] = {"$2a$", "$2b$"}
    prefix: str = "$bcrypt-sha256$"

    @staticmethod
    def hash(password: bytes, rounds: int = 12, **kwargs) -> str:
        """Generate password hash string with ident and params

        https://pypi.org/project/bcrypt/

        :param bytes password: Password to be hashed.
        :param int round: Count of rounds.

        :returns: String in format
            `$bcrypt-sha256$r={rounds},t={ident},v={version}${salt}${digest}`
        """
        # generate salt with ident and options
        salt_with_opts: bytes = bcrypt.gensalt(rounds)
        # get the pure salt
        salt: bytes = salt_with_opts[-22:]
        # make a `str` salt
        salt_str: str = salt.decode("ascii")

        # NOTE(gtema): passlib calculates sha256 hmac digest of the password
        # with the key set to salt
        # Calculate password hmac digest with salt as key
        hmac_digest: bytes = base64.b64encode(
            hmac.digest(salt, password, "sha256")
        )

        # calculate bcrypt hash
        hashed: str = bcrypt.hashpw(hmac_digest, salt_with_opts).decode(
            "ascii"
        )
        # get the digest part of the hash
        digest: str = hashed[-31:]

        # Construct `passlib` compatible format of the bcrypt-sha256 hash
        return f"{Bcrypt_sha256.prefix}v=2,t=2b,r={rounds}${salt_str}${digest}"

    @staticmethod
    def verify(password: bytes, hashed: str) -> bool:
        """Verify hashing password would be equal to the `hashed` value

        :param bytes password: Password to verify
        :param string hashed: Hashed password. Used to extract hashing
            parameters

        :returns: boolean whether hashing password with the same parameters
            would match hashed value
        """
        opts: dict = {}
        data: str = hashed
        # Strip the ident from the hashed value
        if hashed.startswith(Bcrypt_sha256.prefix):
            data = hashed[len(Bcrypt_sha256.prefix) :]
        # split hashed string to extract parameters
        parts: list[str] = data.split("$")
        salt: str
        digest: str

        if len(parts) == 3:
            params, salt, digest = parts
        else:
            raise exception.PasswordValidationError("malformed password hash")

        for param in params.split(","):
            if param.startswith("r="):
                # Extract rounds passlib applied
                opts["r"] = int(param[2:])
            if param.startswith("t="):
                # indent applied during hashing
                opts["t"] = param[2:]

        # Calculate password hmac digest with salt as key
        hmac_digest: bytes = base64.b64encode(
            hmac.digest(salt.encode("ascii"), password, "sha256")
        )

        # Normalize salt to whatever bcrypt expects it to be
        new_salt: str = f"${opts['t']}${opts['r']}${salt}"

        # verify_digest: str = bcrypt.hashpw(
        #     hmac_digest.encode("ascii"), new_salt.encode("ascii")
        # )[-31:].decode("ascii")

        # Invoke bcrypt checkpw with the re-calculated salt
        return bcrypt.checkpw(
            hmac_digest, f"{new_salt}{digest}".encode("ascii")
        )
