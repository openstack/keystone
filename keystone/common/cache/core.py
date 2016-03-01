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
from dogpile.cache import api
from oslo_cache import core as cache
from oslo_config import cfg

from keystone.common.cache import _context_cache


CONF = cfg.CONF
CACHE_REGION = cache.create_region()


def configure_cache(region=None):
    if region is None:
        region = CACHE_REGION
    # NOTE(morganfainberg): running cache.configure_cache_region()
    # sets region.is_configured, this must be captured before
    # cache.configure_cache_region is called.
    configured = region.is_configured
    cache.configure_cache_region(CONF, region)
    # Only wrap the region if it was not configured. This should be pushed
    # to oslo_cache lib somehow.
    if not configured:
        region.wrap(_context_cache._ResponseCacheProxy)


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


# TODO(morganfainberg): Move this logic up into oslo.cache directly
# so we can handle region-wide invalidations or alternatively propose
# a fix to dogpile.cache to make region-wide invalidates possible to
# work across distributed processes.
class _RegionInvalidator(object):

    def __init__(self, region, region_name):
        self.region = region
        self.region_name = region_name
        region_key = '_RegionExpiration.%(type)s.%(region_name)s'
        self.soft_region_key = region_key % {'type': 'soft',
                                             'region_name': self.region_name}
        self.hard_region_key = region_key % {'type': 'hard',
                                             'region_name': self.region_name}

    @property
    def hard_invalidated(self):
        invalidated = self.region.backend.get(self.hard_region_key)
        if invalidated is not api.NO_VALUE:
            return invalidated.payload
        return None

    @hard_invalidated.setter
    def hard_invalidated(self, value):
        self.region.set(self.hard_region_key, value)

    @hard_invalidated.deleter
    def hard_invalidated(self):
        self.region.delete(self.hard_region_key)

    @property
    def soft_invalidated(self):
        invalidated = self.region.backend.get(self.soft_region_key)
        if invalidated is not api.NO_VALUE:
            return invalidated.payload
        return None

    @soft_invalidated.setter
    def soft_invalidated(self, value):
        self.region.set(self.soft_region_key, value)

    @soft_invalidated.deleter
    def soft_invalidated(self):
        self.region.delete(self.soft_region_key)


def apply_invalidation_patch(region, region_name):
    """Patch the region interfaces to ensure we share the expiration time.

    This method is used to patch region.invalidate, region._hard_invalidated,
    and region._soft_invalidated.
    """
    # Patch the region object. This logic needs to be moved up into dogpile
    # itself. Patching the internal interfaces, unfortunately, is the only
    # way to handle this at the moment.
    invalidator = _RegionInvalidator(region=region, region_name=region_name)
    setattr(region, '_hard_invalidated', invalidator.hard_invalidated)
    setattr(region, '_soft_invalidated', invalidator.soft_invalidated)
