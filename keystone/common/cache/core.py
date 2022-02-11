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

import secrets

from dogpile.cache import region
from dogpile.cache import util
from oslo_cache import core as cache

from keystone.common.cache import _context_cache
import keystone.conf


CONF = keystone.conf.CONF


class RegionInvalidationManager(object):

    REGION_KEY_PREFIX = '<<<region>>>:'

    def __init__(self, invalidation_region, region_name):
        self._invalidation_region = invalidation_region
        self._region_key = self.REGION_KEY_PREFIX + region_name

    def _generate_new_id(self):
        return secrets.token_bytes(10)

    @property
    def region_id(self):
        return self._invalidation_region.get_or_create(
            self._region_key, self._generate_new_id, expiration_time=-1)

    def invalidate_region(self):
        new_region_id = self._generate_new_id()
        self._invalidation_region.set(self._region_key, new_region_id)
        return new_region_id

    def is_region_key(self, key):
        return key == self._region_key


class DistributedInvalidationStrategy(region.RegionInvalidationStrategy):

    def __init__(self, region_manager):
        self._region_manager = region_manager

    def invalidate(self, hard=None):
        self._region_manager.invalidate_region()

    def is_invalidated(self, timestamp):
        return False

    def was_hard_invalidated(self):
        return False

    def is_hard_invalidated(self, timestamp):
        return False

    def was_soft_invalidated(self):
        return False

    def is_soft_invalidated(self, timestamp):
        return False


def key_mangler_factory(invalidation_manager, orig_key_mangler):
    def key_mangler(key):
        # NOTE(dstanek): Since *all* keys go through the key mangler we
        # need to make sure the region keys don't get the region_id added.
        # If it were there would be no way to get to it, making the cache
        # effectively useless.
        if not invalidation_manager.is_region_key(key):
            key = '%s:%s' % (key, invalidation_manager.region_id)
        if orig_key_mangler:
            key = orig_key_mangler(key)
        return key
    return key_mangler


def create_region(name):
    """Create a dopile region.

    Wraps oslo_cache.core.create_region. This is used to ensure that the
    Region is properly patched and allows us to more easily specify a region
    name.

    :param str name: The region name
    :returns: The new region.
    :rtype: :class:`dogpile.cache.region.CacheRegion`

    """
    region = cache.create_region()
    region.name = name  # oslo.cache doesn't allow this yet
    return region


CACHE_REGION = create_region(name='shared default')
CACHE_INVALIDATION_REGION = create_region(name='invalidation region')

register_model_handler = _context_cache._register_model_handler


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

        region_manager = RegionInvalidationManager(
            CACHE_INVALIDATION_REGION, region.name)
        region.key_mangler = key_mangler_factory(
            region_manager, region.key_mangler)
        region.region_invalidator = DistributedInvalidationStrategy(
            region_manager)


def _sha1_mangle_key(key):
    """Wrapper for dogpile's sha1_mangle_key.

    dogpile's sha1_mangle_key function expects an encoded string, so we
    should take steps to properly handle multiple inputs before passing
    the key through.

    NOTE(dstanek): this was copied directly from olso_cache
    """
    try:
        key = key.encode('utf-8', errors='xmlcharrefreplace')
    except (UnicodeError, AttributeError):
        # NOTE(stevemar): if encoding fails just continue anyway.
        pass
    return util.sha1_mangle_key(key)


def configure_invalidation_region():
    if CACHE_INVALIDATION_REGION.is_configured:
        return

    # NOTE(dstanek): Configuring this region manually so that we control the
    # expiration and can ensure that the keys don't expire.
    config_dict = cache._build_cache_config(CONF)
    config_dict['expiration_time'] = None  # we don't want an expiration

    CACHE_INVALIDATION_REGION.configure_from_config(
        config_dict, '%s.' % CONF.cache.config_prefix)

    # NOTE(breton): Wrap the cache invalidation region to avoid excessive
    # calls to memcached, which would result in poor performance.
    CACHE_INVALIDATION_REGION.wrap(_context_cache._ResponseCacheProxy)

    # NOTE(morganfainberg): if the backend requests the use of a
    # key_mangler, we should respect that key_mangler function.  If a
    # key_mangler is not defined by the backend, use the sha1_mangle_key
    # mangler provided by dogpile.cache. This ensures we always use a fixed
    # size cache-key.
    if CACHE_INVALIDATION_REGION.key_mangler is None:
        CACHE_INVALIDATION_REGION.key_mangler = _sha1_mangle_key


def get_memoization_decorator(group, expiration_group=None, region=None):
    if region is None:
        region = CACHE_REGION
    return cache.get_memoization_decorator(CONF, region, group,
                                           expiration_group=expiration_group)
