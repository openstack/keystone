# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
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

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib

import passlib.hash

from keystone import config
from keystone.common import logging


CONF = config.CONF
config.register_int('crypt_strength', default=40000)

LOG = logging.getLogger(__name__)

ISO_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_PASSWORD_LENGTH = 4096


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


class SmarterEncoder(json.JSONEncoder):
    """Help for JSON encoding dict-like objects."""
    def default(self, obj):
        if not isinstance(obj, dict) and hasattr(obj, 'iteritems'):
            return dict(obj.iteritems())
        return super(SmarterEncoder, self).default(obj)


class Ec2Signer(object):
    """Hacked up code from boto/connection.py"""

    def __init__(self, secret_key):
        secret_key = secret_key.encode()
        self.hmac = hmac.new(secret_key, digestmod=hashlib.sha1)
        if hashlib.sha256:
            self.hmac_256 = hmac.new(secret_key, digestmod=hashlib.sha256)

    def generate(self, credentials):
        """Generate auth string according to what SignatureVersion is given."""
        if credentials['params']['SignatureVersion'] == '0':
            return self._calc_signature_0(credentials['params'])
        if credentials['params']['SignatureVersion'] == '1':
            return self._calc_signature_1(credentials['params'])
        if credentials['params']['SignatureVersion'] == '2':
            return self._calc_signature_2(credentials['params'],
                                          credentials['verb'],
                                          credentials['host'],
                                          credentials['path'])
        raise Exception('Unknown Signature Version: %s' %
                        credentials['params']['SignatureVersion'])

    @staticmethod
    def _get_utf8_value(value):
        """Get the UTF8-encoded version of a value."""
        if not isinstance(value, str) and not isinstance(value, unicode):
            value = str(value)
        if isinstance(value, unicode):
            return value.encode('utf-8')
        else:
            return value

    def _calc_signature_0(self, params):
        """Generate AWS signature version 0 string."""
        s = params['Action'] + params['Timestamp']
        self.hmac.update(s)
        return base64.b64encode(self.hmac.digest())

    def _calc_signature_1(self, params):
        """Generate AWS signature version 1 string."""
        keys = params.keys()
        keys.sort(cmp=lambda x, y: cmp(x.lower(), y.lower()))
        for key in keys:
            self.hmac.update(key)
            val = self._get_utf8_value(params[key])
            self.hmac.update(val)
        return base64.b64encode(self.hmac.digest())

    def _calc_signature_2(self, params, verb, server_string, path):
        """Generate AWS signature version 2 string."""
        LOG.debug('using _calc_signature_2')
        string_to_sign = '%s\n%s\n%s\n' % (verb, server_string, path)
        if self.hmac_256:
            current_hmac = self.hmac_256
            params['SignatureMethod'] = 'HmacSHA256'
        else:
            current_hmac = self.hmac
            params['SignatureMethod'] = 'HmacSHA1'
        keys = params.keys()
        keys.sort()
        pairs = []
        for key in keys:
            val = self._get_utf8_value(params[key])
            val = urllib.quote(val, safe='-_~')
            pairs.append(urllib.quote(key, safe='') + '=' + val)
        qs = '&'.join(pairs)
        LOG.debug('query string: %s', qs)
        string_to_sign += qs
        LOG.debug('string_to_sign: %s', string_to_sign)
        current_hmac.update(string_to_sign)
        b64 = base64.b64encode(current_hmac.digest())
        LOG.debug('len(b64)=%d', len(b64))
        LOG.debug('base64 encoded digest: %s', b64)
        return b64


def trunc_password(password):
    """Truncate passwords to the MAX_PASSWORD_LENGTH."""
    if len(password) > MAX_PASSWORD_LENGTH:
        return password[:MAX_PASSWORD_LENGTH]
    else:
        return password


def hash_password(password):
    """Hash a password. Hard."""
    password_utf8 = trunc_password(password).encode('utf-8')
    if passlib.hash.sha512_crypt.identify(password_utf8):
        return password_utf8
    h = passlib.hash.sha512_crypt.encrypt(password_utf8,
                                          rounds=CONF.crypt_strength)
    return h


def ldap_hash_password(password):
    """Hash a password. Hard."""
    password_utf8 = trunc_password(password).encode('utf-8')
    h = passlib.hash.ldap_salted_sha1.encrypt(password_utf8)
    return h


def ldap_check_password(password, hashed):
    if password is None:
        return False
    password_utf8 = trunc_password(password).encode('utf-8')
    return passlib.hash.ldap_salted_sha1.verify(password_utf8, hashed)


def check_password(password, hashed):
    """Check that a plaintext password matches hashed.

    hashpw returns the salt value concatenated with the actual hash value.
    It extracts the actual salt if this value is then passed as the salt.

    """
    if password is None:
        return False
    password_utf8 = trunc_password(password).encode('utf-8')
    return passlib.hash.sha512_crypt.verify(password_utf8, hashed)


# From python 2.7
def check_output(*popenargs, **kwargs):
    r"""Run command with arguments and return its output as a byte string.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> check_output(['ls', '-l', '/dev/null'])
    'crw-rw-rw- 1 root root 1, 3 Oct 18  2007 /dev/null\n'

    The stdout argument is not allowed as it is used internally.
    To capture standard error in the result, use stderr=STDOUT.

    >>> check_output(['/bin/sh', '-c',
    ...               'ls -l non_existent_file ; exit 0'],
    ...              stderr=STDOUT)
    'ls: non_existent_file: No such file or directory\n'
    """
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    LOG.debug(' '.join(popenargs[0]))
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = popenargs[0]
        raise subprocess.CalledProcessError(retcode, cmd)
    return output


def git(*args):
    return check_output(['git'] + list(args))


def isotime(dt_obj):
    """Format datetime object as ISO compliant string.

    :param dt_obj: datetime.datetime object
    :returns: string representation of datetime object

    """
    return dt_obj.strftime(ISO_TIME_FORMAT)


def unixtime(dt_obj):
    """Format datetime object as unix timestamp

    :param dt_obj: datetime.datetime object
    :returns: float

    """
    return time.mktime(dt_obj.utctimetuple())


def auth_str_equal(provided, known):
    """Constant-time string comparison.

    :params provided: the first string
    :params known: the second string

    :return: True if the strings are equal.

    This function takes two strings and compares them.  It is intended to be
    used when doing a comparison for authentication purposes to help guard
    against timing attacks.  When using the function for this purpose, always
    provide the user-provided password as the first argument.  The time this
    function will take is always a factor of the length of this string.
    """
    result = 0
    p_len = len(provided)
    k_len = len(known)
    for i in xrange(p_len):
        a = ord(provided[i]) if i < p_len else 0
        b = ord(known[i]) if i < k_len else 0
        result |= a ^ b
    return (p_len == k_len) & (result == 0)
