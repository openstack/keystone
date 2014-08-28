# Copyright 2014 Mirantis Inc
# All Rights Reserved.
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

"""dogpile.cache backend that uses Memcached connection pool"""

import functools
import logging

from dogpile.cache.backends import memcached as memcached_backend

from keystone.common.cache import _memcache_pool


LOG = logging.getLogger(__name__)


# Helper to ease backend refactoring
class ClientProxy(object):
    def __init__(self, client_pool):
        self.client_pool = client_pool

    def _run_method(self, __name, *args, **kwargs):
        with self.client_pool.acquire() as client:
            return getattr(client, __name)(*args, **kwargs)

    def __getattr__(self, name):
        return functools.partial(self._run_method, name)


class PooledMemcachedBackend(memcached_backend.MemcachedBackend):
    # Composed from GenericMemcachedBackend's and MemcacheArgs's __init__
    def __init__(self, arguments):
        super(PooledMemcachedBackend, self).__init__(arguments)
        self.client_pool = _memcache_pool.MemcacheClientPool(
            self.url,
            arguments={
                'dead_retry': arguments.get('dead_retry', 5 * 60),
                'socket_timeout': arguments.get('socket_timeout', 3),
            },
            maxsize=arguments.get('pool_maxsize', 10),
            unused_timeout=arguments.get('pool_unused_timeout', 60),
            conn_get_timeout=arguments.get('pool_connection_get_timeout', 10),
        )

    # Since all methods in backend just call one of methods of client, this
    # lets us avoid need to hack it too much
    @property
    def client(self):
        return ClientProxy(self.client_pool)
