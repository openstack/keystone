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
from dogpile.cache import proxy
from dogpile.cache import util
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils

from keystone import exception
from keystone.i18n import _, _LE


CONF = cfg.CONF
LOG = log.getLogger(__name__)

make_region = dogpile.cache.make_region

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


class DebugProxy(proxy.ProxyBackend):
    """Extra Logging ProxyBackend."""
    # NOTE(morganfainberg): Pass all key/values through repr to ensure we have
    # a clean description of the information.  Without use of repr, it might
    # be possible to run into encode/decode error(s). For logging/debugging
    # purposes encode/decode is irrelevant and we should be looking at the
    # data exactly as it stands.

    def get(self, key):
        value = self.proxied.get(key)
        LOG.debug('CACHE_GET: Key: "%(key)r" Value: "%(value)r"',
                  {'key': key, 'value': value})
        return value

    def get_multi(self, keys):
        values = self.proxied.get_multi(keys)
        LOG.debug('CACHE_GET_MULTI: "%(keys)r" Values: "%(values)r"',
                  {'keys': keys, 'values': values})
        return values

    def set(self, key, value):
        LOG.debug('CACHE_SET: Key: "%(key)r" Value: "%(value)r"',
                  {'key': key, 'value': value})
        return self.proxied.set(key, value)

    def set_multi(self, keys):
        LOG.debug('CACHE_SET_MULTI: "%r"', keys)
        self.proxied.set_multi(keys)

    def delete(self, key):
        self.proxied.delete(key)
        LOG.debug('CACHE_DELETE: "%r"', key)

    def delete_multi(self, keys):
        LOG.debug('CACHE_DELETE_MULTI: "%r"', keys)
        self.proxied.delete_multi(keys)


def build_cache_config():
    """Build the cache region dictionary configuration.

    :returns: dict
    """
    prefix = CONF.cache.config_prefix
    conf_dict = {}
    conf_dict['%s.backend' % prefix] = CONF.cache.backend
    conf_dict['%s.expiration_time' % prefix] = CONF.cache.expiration_time
    for argument in CONF.cache.backend_argument:
        try:
            (argname, argvalue) = argument.split(':', 1)
        except ValueError:
            msg = _LE('Unable to build cache config-key. Expected format '
                      '"<argname>:<value>". Skipping unknown format: %s')
            LOG.error(msg, argument)
            continue

        arg_key = '.'.join([prefix, 'arguments', argname])
        conf_dict[arg_key] = argvalue

        LOG.debug('Keystone Cache Config: %s', conf_dict)
    # NOTE(yorik-sar): these arguments will be used for memcache-related
    # backends. Use setdefault for url to support old-style setting through
    # backend_argument=url:127.0.0.1:11211
    conf_dict.setdefault('%s.arguments.url' % prefix,
                         CONF.cache.memcache_servers)
    for arg in ('dead_retry', 'socket_timeout', 'pool_maxsize',
                'pool_unused_timeout', 'pool_connection_get_timeout'):
        value = getattr(CONF.cache, 'memcache_' + arg)
        conf_dict['%s.arguments.%s' % (prefix, arg)] = value

    return conf_dict


def configure_cache_region(region):
    """Configure a cache region.

    :param region: optional CacheRegion object, if not provided a new region
                   will be instantiated
    :raises: exception.ValidationError
    :returns: dogpile.cache.CacheRegion
    """
    if not isinstance(region, dogpile.cache.CacheRegion):
        raise exception.ValidationError(
            _('region not type dogpile.cache.CacheRegion'))

    if not region.is_configured:
        # NOTE(morganfainberg): this is how you tell if a region is configured.
        # There is a request logged with dogpile.cache upstream to make this
        # easier / less ugly.

        config_dict = build_cache_config()
        region.configure_from_config(config_dict,
                                     '%s.' % CONF.cache.config_prefix)

        if CONF.cache.debug_cache_backend:
            region.wrap(DebugProxy)

        # NOTE(morganfainberg): if the backend requests the use of a
        # key_mangler, we should respect that key_mangler function.  If a
        # key_mangler is not defined by the backend, use the sha1_mangle_key
        # mangler provided by dogpile.cache. This ensures we always use a fixed
        # size cache-key.
        if region.key_mangler is None:
            region.key_mangler = util.sha1_mangle_key

        for class_path in CONF.cache.proxies:
            # NOTE(morganfainberg): if we have any proxy wrappers, we should
            # ensure they are added to the cache region's backend.  Since
            # configure_from_config doesn't handle the wrap argument, we need
            # to manually add the Proxies. For information on how the
            # ProxyBackends work, see the dogpile.cache documents on
            # "changing-backend-behavior"
            cls = importutils.import_class(class_path)
            LOG.debug("Adding cache-proxy '%s' to backend.", class_path)
            region.wrap(cls)

    return region


def get_should_cache_fn(section):
    """Build a function that returns a config section's caching status.

    For any given driver in keystone that has caching capabilities, a boolean
    config option for that driver's section (e.g. ``token``) should exist and
    default to ``True``.  This function will use that value to tell the caching
    decorator if caching for that driver is enabled.  To properly use this
    with the decorator, pass this function the configuration section and assign
    the result to a variable.  Pass the new variable to the caching decorator
    as the named argument ``should_cache_fn``.  e.g.::

        from keystone.common import cache

        SHOULD_CACHE = cache.get_should_cache_fn('token')

        @cache.on_arguments(should_cache_fn=SHOULD_CACHE)
        def function(arg1, arg2):
            ...

    :param section: name of the configuration section to examine
    :type section: string
    :returns: function reference
    """
    def should_cache(value):
        if not CONF.cache.enabled:
            return False
        conf_group = getattr(CONF, section)
        return getattr(conf_group, 'caching', True)
    return should_cache


def get_expiration_time_fn(section):
    """Build a function that returns a config section's expiration time status.

    For any given driver in keystone that has caching capabilities, an int
    config option called ``cache_time`` for that driver's section
    (e.g. ``token``) should exist and typically default to ``None``. This
    function will use that value to tell the caching decorator of the TTL
    override for caching the resulting objects. If the value of the config
    option is ``None`` the default value provided in the
    ``[cache] expiration_time`` option will be used by the decorator. The
    default may be set to something other than ``None`` in cases where the
    caching TTL should not be tied to the global default(s) (e.g.
    revocation_list changes very infrequently and can be cached for >1h by
    default).

    To properly use this with the decorator, pass this function the
    configuration section and assign the result to a variable. Pass the new
    variable to the caching decorator as the named argument
    ``expiration_time``.  e.g.::

        from keystone.common import cache

        EXPIRATION_TIME = cache.get_expiration_time_fn('token')

        @cache.on_arguments(expiration_time=EXPIRATION_TIME)
        def function(arg1, arg2):
            ...

    :param section: name of the configuration section to examine
    :type section: string
    :rtype: function reference
    """
    def get_expiration_time():
        conf_group = getattr(CONF, section)
        return getattr(conf_group, 'cache_time', None)
    return get_expiration_time


def key_generate_to_str(s):
    # NOTE(morganfainberg): Since we need to stringify all arguments, attempt
    # to stringify and handle the Unicode error explicitly as needed.
    try:
        return str(s)
    except UnicodeEncodeError:
        return s.encode('utf-8')


def function_key_generator(namespace, fn, to_str=key_generate_to_str):
    # NOTE(morganfainberg): This wraps dogpile.cache's default
    # function_key_generator to change the default to_str mechanism.
    return util.function_key_generator(namespace, fn, to_str=to_str)


REGION = dogpile.cache.make_region(
    function_key_generator=function_key_generator)
on_arguments = REGION.cache_on_arguments


def get_memoization_decorator(section, expiration_section=None):
    """Build a function based on the `on_arguments` decorator for the section.

    For any given driver in Keystone that has caching capabilities, a
    pair of functions is required to properly determine the status of the
    caching capabilities (a toggle to indicate caching is enabled and any
    override of the default TTL for cached data). This function will return
    an object that has the memoization decorator ``on_arguments``
    pre-configured for the driver.

    Example usage::

        from keystone.common import cache

        MEMOIZE = cache.get_memoization_decorator(section='token')

        @MEMOIZE
        def function(arg1, arg2):
            ...


        ALTERNATE_MEMOIZE = cache.get_memoization_decorator(
            section='token', expiration_section='revoke')

        @ALTERNATE_MEMOIZE
        def function2(arg1, arg2):
            ...

    :param section: name of the configuration section to examine
    :type section: string
    :param expiration_section: name of the configuration section to examine
                               for the expiration option. This will fall back
                               to using ``section`` if the value is unspecified
                               or ``None``
    :type expiration_section: string
    :rtype: function reference
    """
    if expiration_section is None:
        expiration_section = section
    should_cache = get_should_cache_fn(section)
    expiration_time = get_expiration_time_fn(expiration_section)

    memoize = REGION.cache_on_arguments(should_cache_fn=should_cache,
                                        expiration_time=expiration_time)

    # Make sure the actual "should_cache" and "expiration_time" methods are
    # available. This is potentially interesting/useful to pre-seed cache
    # values.
    memoize.should_cache = should_cache
    memoize.get_expiration_time = expiration_time

    return memoize
