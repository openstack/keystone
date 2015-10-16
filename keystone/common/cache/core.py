# Copyright 2013 Metacloud
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

"""Keystone Caching Layer Implementation."""

import dogpile.cache
from oslo_cache import core as cache
from oslo_config import cfg


CONF = cfg.CONF
CACHE_REGION = cache.create_region()


def configure_cache(region=None):
    if region is None:
        region = CACHE_REGION
    cache.configure_cache_region(CONF, region)


def get_memoization_decorator(group, expiration_group=None, region=None):
    if region is None:
        region = CACHE_REGION
    return cache.get_memoization_decorator(CONF, region, group,
                                           expiration_group=expiration_group)


# NOTE(stevemar): When memcache_pool, mongo and noop backends are removed
# we no longer need to register the backends here.
dogpile.cache.register_backend(
    'keystone.common.cache.noop',
    'keystone.common.cache.backends.noop',
    'NoopCacheBackend')

dogpile.cache.register_backend(
    'keystone.cache.mongo',
    'keystone.common.cache.backends.mongo',
    'MongoCacheBackend')

dogpile.cache.register_backend(
    'keystone.cache.memcache_pool',
    'keystone.common.cache.backends.memcache_pool',
    'PooledMemcachedBackend')
