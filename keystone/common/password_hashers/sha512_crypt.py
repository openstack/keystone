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

import crypt

from keystone.common import password_hashers


class Sha512_crypt(password_hashers.PasswordHasher):
    """passlib transition class for sha512_crypt password hashing"""

    name: str = "sha512_crypt"
    ident: str = "$6$"

    @staticmethod
    def verify(password: bytes, hashed: str) -> bool:
        """Verify hashing password would be equal to the `hashed` value

        :param bytes password: Password to verify
        :param string hashed: Hashed password. Used to extract hashing
            parameters

        :returns: boolean whether hashing password with the same parameters
            would match hashed value
        """

        return (
            crypt.crypt(password.decode("utf8"), hashed[0 : hashed.rfind("$")])
            == hashed
        )
