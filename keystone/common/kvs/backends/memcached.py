# -*- coding: utf-8 -*-

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

import random
import time

from dogpile.cache import api
from dogpile.cache.backends import memcached

from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)
NO_VALUE = api.NO_VALUE


VALID_DOGPILE_BACKENDS = dict(pylibmc=memcached.PylibmcBackend,
                              bmemcached=memcached.BMemcachedBackend,
                              memcached=memcached.MemcachedBackend)


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
        i = 0
        while True:
            if client.add(self.key, 1, self.lock_timeout):
                return True
            elif not wait:
                return False
            else:
                sleep_time = (((i + 1) * random.random()) + 2 ** i) / 2.5
                time.sleep(sleep_time)
            if i <= self.max_lock_attempts:
                i += 1
            else:
                raise exception.UnexpectedError(
                    _('Maximum lock attempts on %s occurred.') % self.key)

    def release(self):
        client = self.client_fn()
        client.delete(self.key)


class MemcachedBackend(manager.Manager):
    """Pivot point to leverage the various dogpile.cache memcached backends.

    To specify a specific dogpile.cache memcached driver, pass the argument
    `memcached_driver` set to one of the provided memcached drivers (at this
    time `memcached`, `bmemcached`, `pylibmc` are valid).
    """
    def __init__(self, arguments):
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
                    _('Backend `%(driver)s` is not a valid memcached '
                      'backend. Valid drivers: %(driver_list)s') %
                    {'driver': backend,
                     'driver_list': ','.join(VALID_DOGPILE_BACKENDS.keys())})
            else:
                self.driver = VALID_DOGPILE_BACKENDS[backend](arguments)

    @classmethod
    def from_config_dict(cls, config_dict, prefix):
        prefix_len = len(prefix)
        return cls(
            dict((key[prefix_len:], config_dict[key])
                 for key in config_dict
                 if key.startswith(prefix)))

    @property
    def key_mangler(self):
        return self.driver.key_mangler

    def get_mutex(self, key):
        return MemcachedLock(lambda: self.driver.client, key,
                             self.lock_timeout, self.max_lock_attempts)
