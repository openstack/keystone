# Copyright 2013 Metacloud, Inc.
#
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

"""
Keystone Memcached dogpile.cache backend implementation.
"""

import random as _random
import time

from dogpile.cache import api
from dogpile.cache.backends import memcached
from oslo_config import cfg
from oslo_log import log
from six.moves import range

from keystone.common.cache.backends import memcache_pool
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
LOG = log.getLogger(__name__)
NO_VALUE = api.NO_VALUE
random = _random.SystemRandom()

VALID_DOGPILE_BACKENDS = dict(
    pylibmc=memcached.PylibmcBackend,
    bmemcached=memcached.BMemcachedBackend,
    memcached=memcached.MemcachedBackend,
    pooled_memcached=memcache_pool.PooledMemcachedBackend)


class MemcachedLock(object):
    """Simple distributed lock using memcached.

    This is an adaptation of the lock featured at
    http://amix.dk/blog/post/19386

    """
    def __init__(self, client_fn, key, lock_timeout, max_lock_attempts):
        self.client_fn = client_fn
        self.key = "_lock" + key
        self.lock_timeout = lock_timeout
        self.max_lock_attempts = max_lock_attempts

    def acquire(self, wait=True):
        client = self.client_fn()
        for i in range(self.max_lock_attempts):
            if client.add(self.key, 1, self.lock_timeout):
                return True
            elif not wait:
                return False
            else:
                sleep_time = random.random()
                time.sleep(sleep_time)
        raise exception.UnexpectedError(
            _('Maximum lock attempts on %s occurred.') % self.key)

    def release(self):
        client = self.client_fn()
        client.delete(self.key)


class MemcachedBackend(object):
    """Pivot point to leverage the various dogpile.cache memcached backends.

    To specify a specific dogpile.cache memcached backend, pass the argument
    `memcached_backend` set to one of the provided memcached backends (at this
    time `memcached`, `bmemcached`, `pylibmc` and `pooled_memcached` are
    valid).
    """
    def __init__(self, arguments):
        self._key_mangler = None
        self.raw_no_expiry_keys = set(arguments.pop('no_expiry_keys', set()))
        self.no_expiry_hashed_keys = set()

        self.lock_timeout = arguments.pop('lock_timeout', None)
        self.max_lock_attempts = arguments.pop('max_lock_attempts', 15)
        # NOTE(morganfainberg): Remove distributed locking from the arguments
        # passed to the "real" backend if it exists.
        arguments.pop('distributed_lock', None)
        backend = arguments.pop('memcached_backend', None)
        if 'url' not in arguments:
            # FIXME(morganfainberg): Log deprecation warning for old-style
            # configuration once full dict_config style configuration for
            # KVS backends is supported.  For now use the current memcache
            # section of the configuration.
            arguments['url'] = CONF.memcache.servers

        if backend is None:
            # NOTE(morganfainberg): Use the basic memcached backend if nothing
            # else is supplied.
            self.driver = VALID_DOGPILE_BACKENDS['memcached'](arguments)
        else:
            if backend not in VALID_DOGPILE_BACKENDS:
                raise ValueError(
                    _('Backend `%(backend)s` is not a valid memcached '
                      'backend. Valid backends: %(backend_list)s') %
                    {'backend': backend,
                     'backend_list': ','.join(VALID_DOGPILE_BACKENDS.keys())})
            else:
                self.driver = VALID_DOGPILE_BACKENDS[backend](arguments)

    def __getattr__(self, name):
        """Forward calls to the underlying driver."""
        f = getattr(self.driver, name)
        setattr(self, name, f)
        return f

    def _get_set_arguments_driver_attr(self, exclude_expiry=False):

        # NOTE(morganfainberg): Shallow copy the .set_arguments dict to
        # ensure no changes cause the values to change in the instance
        # variable.
        set_arguments = getattr(self.driver, 'set_arguments', {}).copy()

        if exclude_expiry:
            # NOTE(morganfainberg): Explicitly strip out the 'time' key/value
            # from the set_arguments in the case that this key isn't meant
            # to expire
            set_arguments.pop('time', None)
        return set_arguments

    def set(self, key, value):
        mapping = {key: value}
        self.set_multi(mapping)

    def set_multi(self, mapping):
        mapping_keys = set(mapping.keys())
        no_expiry_keys = mapping_keys.intersection(self.no_expiry_hashed_keys)
        has_expiry_keys = mapping_keys.difference(self.no_expiry_hashed_keys)

        if no_expiry_keys:
            # NOTE(morganfainberg): For keys that have expiry excluded,
            # bypass the backend and directly call the client. Bypass directly
            # to the client is required as the 'set_arguments' are applied to
            # all ``set`` and ``set_multi`` calls by the driver, by calling
            # the client directly it is possible to exclude the ``time``
            # argument to the memcached server.
            new_mapping = {k: mapping[k] for k in no_expiry_keys}
            set_arguments = self._get_set_arguments_driver_attr(
                exclude_expiry=True)
            self.driver.client.set_multi(new_mapping, **set_arguments)

        if has_expiry_keys:
            new_mapping = {k: mapping[k] for k in has_expiry_keys}
            self.driver.set_multi(new_mapping)

    @classmethod
    def from_config_dict(cls, config_dict, prefix):
        prefix_len = len(prefix)
        return cls(
            {key[prefix_len:]: config_dict[key] for key in config_dict
             if key.startswith(prefix)})

    @property
    def key_mangler(self):
        if self._key_mangler is None:
            self._key_mangler = self.driver.key_mangler
        return self._key_mangler

    @key_mangler.setter
    def key_mangler(self, key_mangler):
        if callable(key_mangler):
            self._key_mangler = key_mangler
            self._rehash_keys()
        elif key_mangler is None:
            # NOTE(morganfainberg): Set the hashed key map to the unhashed
            # list since we no longer have a key_mangler.
            self._key_mangler = None
            self.no_expiry_hashed_keys = self.raw_no_expiry_keys
        else:
            raise TypeError(_('`key_mangler` functions must be callable.'))

    def _rehash_keys(self):
        no_expire = set()
        for key in self.raw_no_expiry_keys:
            no_expire.add(self._key_mangler(key))
            self.no_expiry_hashed_keys = no_expire

    def get_mutex(self, key):
        return MemcachedLock(lambda: self.driver.client, key,
                             self.lock_timeout, self.max_lock_attempts)
