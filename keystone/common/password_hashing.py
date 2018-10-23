# Copyright 2017 Red Hat
# All Rights Reserved.
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

import itertools

from oslo_log import log
import passlib.hash

import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

SUPPORTED_HASHERS = frozenset([passlib.hash.bcrypt,
                               passlib.hash.scrypt,
                               passlib.hash.pbkdf2_sha512,
                               passlib.hash.sha512_crypt])

_HASHER_NAME_MAP = {hasher.name: hasher for hasher in SUPPORTED_HASHERS}


# NOTE(notmorgan): Build the list of prefixes. This comprehension builds
# a dictionary where the keys are the prefix (all hashedpasswords are
# '$<ident>$<metadata>$<hash>') so we can do a fast-lookup on the hasher to
# use. If has hasher has multiple ident options it is encoded in the
# .ident_values attribute whereas hashers that have a single option
# (sha512_crypt) only has the .ident attribute.
_HASHER_IDENT_MAP = {
    prefix: module for module, prefix in itertools.chain(
        *[zip([mod] * len(getattr(mod, 'ident_values', (mod.ident,))),
              getattr(mod, 'ident_values', (mod.ident,)))
          for mod in SUPPORTED_HASHERS])}


def _get_hasher_from_ident(hashed):
    try:
        return _HASHER_IDENT_MAP[hashed[0:hashed.index('$', 1) + 1]]
    except KeyError:
        raise ValueError(
            _('Unsupported password hashing algorithm ident: %s') %
            hashed[0:hashed.index('$', 1) + 1])


def verify_length_and_trunc_password(password):
    """Verify and truncate the provided password to the max_password_length."""
    max_length = CONF.identity.max_password_length
    try:
        if len(password) > max_length:
            if CONF.strict_password_check:
                raise exception.PasswordVerificationError(size=max_length)
            else:
                msg = "Truncating user password to %d characters."
                LOG.warning(msg, max_length)
                return password[:max_length]
        else:
            return password
    except TypeError:
        raise exception.ValidationError(attribute='string', target='password')


def check_password(password, hashed):
    """Check that a plaintext password matches hashed.

    hashpw returns the salt value concatenated with the actual hash value.
    It extracts the actual salt if this value is then passed as the salt.

    """
    if password is None or hashed is None:
        return False
    password_utf8 = verify_length_and_trunc_password(password).encode('utf-8')
    hasher = _get_hasher_from_ident(hashed)
    return hasher.verify(password_utf8, hashed)


def hash_user_password(user):
    """Hash a user dict's password without modifying the passed-in dict."""
    password = user.get('password')
    if password is None:
        return user

    return dict(user, password=hash_password(password))


def hash_password(password):
    """Hash a password. Harder."""
    params = {}
    password_utf8 = verify_length_and_trunc_password(password).encode('utf-8')
    conf_hasher = CONF.identity.password_hash_algorithm
    hasher = _HASHER_NAME_MAP.get(conf_hasher)

    if hasher is None:
        raise RuntimeError(
            _('Password Hash Algorithm %s not found') %
            CONF.identity.password_hash_algorithm)

    if CONF.identity.password_hash_rounds:
        params['rounds'] = CONF.identity.password_hash_rounds
    if hasher is passlib.hash.scrypt:
        if CONF.identity.scrypt_block_size:
            params['block_size'] = CONF.identity.scrypt_block_size
        if CONF.identity.scrypt_parallelism:
            params['parallelism'] = CONF.identity.scrypt_parallelism
        if CONF.identity.salt_bytesize:
            params['salt_size'] = CONF.identity.salt_bytesize
    if hasher is passlib.hash.pbkdf2_sha512:
        if CONF.identity.salt_bytesize:
            params['salt_size'] = CONF.identity.salt_bytesize

    return hasher.using(**params).hash(password_utf8)
