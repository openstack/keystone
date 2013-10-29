# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone import config
from keystone import exception
from keystone.openstack.common import importutils
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)

make_region = dogpile.cache.make_region

dogpile.cache.register_backend(
    'keystone.common.cache.noop',
    'keystone.common.cache.backends.noop',
    'NoopCacheBackend')


class DebugProxy(proxy.ProxyBackend):
    """Extra Logging ProxyBackend."""
    # NOTE(morganfainberg): Pass all key/values through repr to ensure we have
    # a clean description of the information.  Without use of repr, it might
    # be possible to run into encode/decode error(s). For logging/debugging
    # purposes encode/decode is irrelevant and we should be looking at the
    # data exactly as it stands.

    def get(self, key):
        value = self.proxied.get(key)
        LOG.debug(_('CACHE_GET: Key: "%(key)r" Value: "%(value)r"'),
                  {'key': key, 'value': value})
        return value

    def get_multi(self, keys):
        values = self.proxied.get_multi(keys)
        LOG.debug(_('CACHE_GET_MULTI: "%(keys)r" Values: "%(values)r"'),
                  {'keys': keys, 'values': values})
        return values

    def set(self, key, value):
        LOG.debug(_('CACHE_SET: Key: "%(key)r" Value: "%(value)r"'),
                  {'key': key, 'value': value})
        return self.proxied.set(key, value)

    def set_multi(self, keys):
        LOG.debug(_('CACHE_SET_MULTI: "%r"'), keys)
        self.proxied.set_multi(keys)

    def delete(self, key):
        self.proxied.delete(key)
        LOG.debug(_('CACHE_DELETE: "%r"'), key)

    def delete_multi(self, keys):
        LOG.debug(_('CACHE_DELETE_MULTI: "%r"'), keys)
        self.proxied.delete_multi(keys)


def build_cache_config():
    """Build the cache region dictionary configuration.

    :param conf: configuration object for keystone
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
            msg = _('Unable to build cache config-key. Expected format '
                    '"<argname>:<value>". Skipping unknown format: %s')
            LOG.error(msg, argument)
            continue

        arg_key = '.'.join([prefix, 'arguments', argname])
        conf_dict[arg_key] = argvalue

        LOG.debug(_('Keystone Cache Config: %s'), conf_dict)

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

    if 'backend' not in region.__dict__:
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
        # size cache-key.  This is toggle-able for debug purposes; if disabled
        # this could cause issues with certain backends (such as memcached) and
        # its limited key-size.
        if region.key_mangler is None:
            if CONF.cache.use_key_mangler:
                region.key_mangler = util.sha1_mangle_key

        for class_path in CONF.cache.proxies:
            # NOTE(morganfainberg): if we have any proxy wrappers, we should
            # ensure they are added to the cache region's backend.  Since
            # configure_from_config doesn't handle the wrap argument, we need
            # to manually add the Proxies. For information on how the
            # ProxyBackends work, see the dogpile.cache documents on
            # "changing-backend-behavior"
            cls = importutils.import_class(class_path)
            LOG.debug(_("Adding cache-proxy '%s' to backend."), class_path)
            region.wrap(cls)

    return region


def should_cache_fn(section):
    """Build a function that returns a config section's caching status.

    For any given driver in keystone that has caching capabilities, a boolean
    config option for that driver's section (e.g. ``token``) should exist and
    default to ``True``.  This function will use that value to tell the caching
    decorator if caching for that driver is enabled.  To properly use this
    with the decorator, pass this function the configuration section and assign
    the result to a variable.  Pass the new variable to the caching decorator
    as the named argument ``should_cache_fn``.  e.g.:

        from keystone.common import cache

        SHOULD_CACHE = cache.should_cache_fn('token')

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
