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
#
import abc
import binascii
import typing as ty

# Methods as implemented in passlib to guarantee backwards compatibility.

_BASE64_STRIP = b"=\n"
_BASE64_PAD1 = b"="
_BASE64_PAD2 = b"=="


def b64s_decode(data: bytes):
    """decode from shortened base64 format which omits padding & whitespace

    uses default ``+/`` altchars.
    """
    off = len(data) & 3
    if off == 0:
        pass
    elif off == 2:
        data += _BASE64_PAD2
    elif off == 3:
        data += _BASE64_PAD1
    else:  # off == 1
        raise ValueError("invalid base64 input")
    return binascii.a2b_base64(data)


class PasswordHasher(abc.ABC):
    """Abstract password hasher class"""

    name: str
    ident: ty.Optional[str]
