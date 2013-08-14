# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64

from Crypto.Hash import HMAC
from Crypto import Random

from keystone.openstack.common.gettextutils import _  # noqa
from keystone.openstack.common import importutils


class CryptoutilsException(Exception):
    """Generic Exception for Crypto utilities."""

    message = _("An unknown error occurred in crypto utils.")


class CipherBlockLengthTooBig(CryptoutilsException):
    """The block size is too big."""

    def __init__(self, requested, permitted):
        msg = _("Block size of %(given)d is too big, max = %(maximum)d")
        message = msg % {'given': requested, 'maximum': permitted}
        super(CryptoutilsException, self).__init__(message)


class HKDFOutputLengthTooLong(CryptoutilsException):
    """The amount of Key Material asked is too much."""

    def __init__(self, requested, permitted):
        msg = _("Length of %(given)d is too long, max = %(maximum)d")
        message = msg % {'given': requested, 'maximum': permitted}
        super(CryptoutilsException, self).__init__(message)


class HKDF(object):
    """An HMAC-based Key Derivation Function implementation (RFC5869)

    This class creates an object that allows to use HKDF to derive keys.
    """

    def __init__(self, hashtype='SHA256'):
        self.hashfn = importutils.import_module('Crypto.Hash.' + hashtype)
        self.max_okm_length = 255 * self.hashfn.digest_size

    def extract(self, ikm, salt=None):
        """An extract function that can be used to derive a robust key given
        weak Input Key Material (IKM) which could be a password.
        Returns a pseudorandom key (of HashLen octets)

        :param ikm: input keying material (ex a password)
        :param salt: optional salt value (a non-secret random value)
        """
        if salt is None:
            salt = '\x00' * self.hashfn.digest_size

        return HMAC.new(salt, ikm, self.hashfn).digest()

    def expand(self, prk, info, length):
        """An expand function that will return arbitrary length output that can
        be used as keys.
        Returns a buffer usable as key material.

        :param prk: a pseudorandom key of at least HashLen octets
        :param info: optional string (can be a zero-length string)
        :param length: length of output keying material (<= 255 * HashLen)
        """
        if length > self.max_okm_length:
            raise HKDFOutputLengthTooLong(length, self.max_okm_length)

        N = (length + self.hashfn.digest_size - 1) / self.hashfn.digest_size

        okm = ""
        tmp = ""
        for block in range(1, N + 1):
            tmp = HMAC.new(prk, tmp + info + chr(block), self.hashfn).digest()
            okm += tmp

        return okm[:length]


MAX_CB_SIZE = 256


class SymmetricCrypto(object):
    """Symmetric Key Crypto object.

    This class creates a Symmetric Key Crypto object that can be used
    to encrypt, decrypt, or sign arbitrary data.

    :param enctype: Encryption Cipher name (default: AES)
    :param hashtype: Hash/HMAC type name (default: SHA256)
    """

    def __init__(self, enctype='AES', hashtype='SHA256'):
        self.cipher = importutils.import_module('Crypto.Cipher.' + enctype)
        self.hashfn = importutils.import_module('Crypto.Hash.' + hashtype)

    def new_key(self, size):
        return Random.new().read(size)

    def encrypt(self, key, msg, b64encode=True):
        """Encrypt the provided msg and returns the cyphertext optionally
        base64 encoded.

        Uses AES-128-CBC with a Random IV by default.

        The plaintext is padded to reach blocksize length.
        The last byte of the block is the length of the padding.
        The length of the padding does not include the length byte itself.

        :param key: The Encryption key.
        :param msg: the plain text.

        :returns encblock: a block of encrypted data.
        """
        iv = Random.new().read(self.cipher.block_size)
        cipher = self.cipher.new(key, self.cipher.MODE_CBC, iv)

        # CBC mode requires a fixed block size. Append padding and length of
        # padding.
        if self.cipher.block_size > MAX_CB_SIZE:
            raise CipherBlockLengthTooBig(self.cipher.block_size, MAX_CB_SIZE)
        r = len(msg) % self.cipher.block_size
        padlen = self.cipher.block_size - r - 1
        msg += '\x00' * padlen
        msg += chr(padlen)

        enc = iv + cipher.encrypt(msg)
        if b64encode:
            enc = base64.b64encode(enc)
        return enc

    def decrypt(self, key, msg, b64decode=True):
        """Decrypts the provided ciphertext, optionally base 64 encoded, and
        returns the plaintext message, after padding is removed.

        Uses AES-128-CBC with an IV by default.

        :param key: The Encryption key.
        :param msg: the ciphetext, the first block is the IV
        """
        if b64decode:
            msg = base64.b64decode(msg)
        iv = msg[:self.cipher.block_size]
        cipher = self.cipher.new(key, self.cipher.MODE_CBC, iv)

        padded = cipher.decrypt(msg[self.cipher.block_size:])
        l = ord(padded[-1]) + 1
        plain = padded[:-l]
        return plain

    def sign(self, key, msg, b64encode=True):
        """Signs a message string and returns a base64 encoded signature.

        Uses HMAC-SHA-256 by default.

        :param key: The Signing key.
        :param msg: the message to sign.
        """
        h = HMAC.new(key, msg, self.hashfn)
        out = h.digest()
        if b64encode:
            out = base64.b64encode(out)
        return out
