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

import contextlib
import threading
import time
import weakref

from dogpile.cache import api
from dogpile.cache import proxy
from dogpile.cache import region
from dogpile.cache import util as dogpile_util
from dogpile.core import nameregistry
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils

from keystone import exception
from keystone.i18n import _
from keystone.i18n import _LI
from keystone.i18n import _LW


__all__ = ['KeyValueStore', 'KeyValueStoreLock', 'LockTimeout',
           'get_key_value_store']


BACKENDS_REGISTERED = False
CONF = cfg.CONF
KEY_VALUE_STORE_REGISTRY = weakref.WeakValueDictionary()
LOCK_WINDOW = 1
LOG = log.getLogger(__name__)
NO_VALUE = api.NO_VALUE


def _register_backends():
    # NOTE(morganfainberg): This function exists to ensure we do not try and
    # register the backends prior to the configuration object being fully
    # available.  We also need to ensure we do not register a given backend
    # more than one time.  All backends will be prefixed with openstack.kvs
    # as the "short" name to reference them for configuration purposes.  This
    # function is used in addition to the pre-registered backends in the
    # __init__ file for the KVS system.
    global BACKENDS_REGISTERED

    if not BACKENDS_REGISTERED:
        prefix = 'openstack.kvs.%s'
        for backend in CONF.kvs.backends:
            module, cls = backend.rsplit('.', 1)
            backend_name = prefix % cls
            LOG.debug(('Registering Dogpile Backend %(backend_path)s as '
                       '%(backend_name)s'),
                      {'backend_path': backend, 'backend_name': backend_name})
            region.register_backend(backend_name, module, cls)
        BACKENDS_REGISTERED = True


class LockTimeout(exception.UnexpectedError):
    debug_message_format = _('Lock Timeout occurred for key, %(target)s')


class KeyValueStore(object):
    """Basic KVS manager object to support Keystone Key-Value-Store systems.

    This manager also supports the concept of locking a given key resource to
    allow for a guaranteed atomic transaction to the backend.
    """
    def __init__(self, kvs_region):
        self.locking = True
        self._lock_timeout = 0
        self._region = kvs_region
        self._security_strategy = None
        self._secret_key = None
        self._lock_registry = nameregistry.NameRegistry(self._create_mutex)

    def configure(self, backing_store, key_mangler=None, proxy_list=None,
                  locking=True, **region_config_args):
        """Configure the KeyValueStore instance.

        :param backing_store: dogpile.cache short name of the region backend
        :param key_mangler: key_mangler function
        :param proxy_list: list of proxy classes to apply to the region
        :param locking: boolean that allows disabling of locking mechanism for
                        this instantiation
        :param region_config_args: key-word args passed to the dogpile.cache
                                   backend for configuration
        :return:
        """
        if self.is_configured:
            # NOTE(morganfainberg): It is a bad idea to reconfigure a backend,
            # there are a lot of pitfalls and potential memory leaks that could
            # occur.  By far the best approach is to re-create the KVS object
            # with the new configuration.
            raise RuntimeError(_('KVS region %s is already configured. '
                                 'Cannot reconfigure.') % self._region.name)

        self.locking = locking
        self._lock_timeout = region_config_args.pop(
            'lock_timeout', CONF.kvs.default_lock_timeout)
        self._configure_region(backing_store, **region_config_args)
        self._set_key_mangler(key_mangler)
        self._apply_region_proxy(proxy_list)

    @property
    def is_configured(self):
        return 'backend' in self._region.__dict__

    def _apply_region_proxy(self, proxy_list):
        if isinstance(proxy_list, list):
            proxies = []

            for item in proxy_list:
                if isinstance(item, str):
                    LOG.debug('Importing class %s as KVS proxy.', item)
                    pxy = importutils.import_class(item)
                else:
                    pxy = item

                if issubclass(pxy, proxy.ProxyBackend):
                    proxies.append(pxy)
                else:
                    LOG.warning(_LW('%s is not a dogpile.proxy.ProxyBackend'),
                                pxy.__name__)

            for proxy_cls in reversed(proxies):
                LOG.info(_LI('Adding proxy \'%(proxy)s\' to KVS %(name)s.'),
                         {'proxy': proxy_cls.__name__,
                          'name': self._region.name})
                self._region.wrap(proxy_cls)

    def _assert_configured(self):
        if'backend' not in self._region.__dict__:
            raise exception.UnexpectedError(_('Key Value Store not '
                                              'configured: %s'),
                                            self._region.name)

    def _set_keymangler_on_backend(self, key_mangler):
        try:
            self._region.backend.key_mangler = key_mangler
        except Exception as e:
            # NOTE(morganfainberg): The setting of the key_mangler on the
            # backend is used to allow the backend to
            # calculate a hashed key value as needed. Not all backends
            # require the ability to calculate hashed keys. If the
            # backend does not support/require this feature log a
            # debug line and move on otherwise raise the proper exception.
            # Support of the feature is implied by the existence of the
            # 'raw_no_expiry_keys' attribute.
            if not hasattr(self._region.backend, 'raw_no_expiry_keys'):
                LOG.debug(('Non-expiring keys not supported/required by '
                           '%(region)s backend; unable to set '
                           'key_mangler for backend: %(err)s'),
                          {'region': self._region.name, 'err': e})
            else:
                raise

    def _set_key_mangler(self, key_mangler):
        # Set the key_mangler that is appropriate for the given region being
        # configured here.  The key_mangler function is called prior to storing
        # the value(s) in the backend.  This is to help prevent collisions and
        # limit issues such as memcache's limited cache_key size.
        use_backend_key_mangler = getattr(self._region.backend,
                                          'use_backend_key_mangler', False)
        if ((key_mangler is None or use_backend_key_mangler) and
                (self._region.backend.key_mangler is not None)):
            # NOTE(morganfainberg): Use the configured key_mangler as a first
            # choice. Second choice would be the key_mangler defined by the
            # backend itself.  Finally, fall back to the defaults.  The one
            # exception is if the backend defines `use_backend_key_mangler`
            # as True, which indicates the backend's key_mangler should be
            # the first choice.
            key_mangler = self._region.backend.key_mangler

        if CONF.kvs.enable_key_mangler:
            if key_mangler is not None:
                msg = _LI('Using %(func)s as KVS region %(name)s key_mangler')
                if callable(key_mangler):
                    self._region.key_mangler = key_mangler
                    LOG.info(msg, {'func': key_mangler.__name__,
                                   'name': self._region.name})
                else:
                    # NOTE(morganfainberg): We failed to set the key_mangler,
                    # we should error out here to ensure we aren't causing
                    # key-length or collision issues.
                    raise exception.ValidationError(
                        _('`key_mangler` option must be a function reference'))
            else:
                LOG.info(_LI('Using default dogpile sha1_mangle_key as KVS '
                             'region %s key_mangler'), self._region.name)
                # NOTE(morganfainberg): Sane 'default' keymangler is the
                # dogpile sha1_mangle_key function.  This ensures that unless
                # explicitly changed, we mangle keys.  This helps to limit
                # unintended cases of exceeding cache-key in backends such
                # as memcache.
                self._region.key_mangler = dogpile_util.sha1_mangle_key
            self._set_keymangler_on_backend(self._region.key_mangler)
        else:
            LOG.info(_LI('KVS region %s key_mangler disabled.'),
                     self._region.name)
            self._set_keymangler_on_backend(None)

    def _configure_region(self, backend, **config_args):
        prefix = CONF.kvs.config_prefix
        conf_dict = {}
        conf_dict['%s.backend' % prefix] = backend

        if 'distributed_lock' not in config_args:
            config_args['distributed_lock'] = True

        config_args['lock_timeout'] = self._lock_timeout

        # NOTE(morganfainberg): To mitigate race conditions on comparing
        # the timeout and current time on the lock mutex, we are building
        # in a static 1 second overlap where the lock will still be valid
        # in the backend but not from the perspective of the context
        # manager.  Since we must develop to the lowest-common-denominator
        # when it comes to the backends, memcache's cache store is not more
        # refined than 1 second, therefore we must build in at least a 1
        # second overlap.  `lock_timeout` of 0 means locks never expire.
        if config_args['lock_timeout'] > 0:
            config_args['lock_timeout'] += LOCK_WINDOW

        for argument, value in config_args.items():
            arg_key = '.'.join([prefix, 'arguments', argument])
            conf_dict[arg_key] = value

        LOG.debug('KVS region configuration for %(name)s: %(config)r',
                  {'name': self._region.name, 'config': conf_dict})
        self._region.configure_from_config(conf_dict, '%s.' % prefix)

    def _mutex(self, key):
        return self._lock_registry.get(key)

    def _create_mutex(self, key):
        mutex = self._region.backend.get_mutex(key)
        if mutex is not None:
            return mutex
        else:
            return self._LockWrapper(lock_timeout=self._lock_timeout)

    class _LockWrapper(object):
        """weakref-capable threading.Lock wrapper."""
        def __init__(self, lock_timeout):
            self.lock = threading.Lock()
            self.lock_timeout = lock_timeout

        def acquire(self, wait=True):
            return self.lock.acquire(wait)

        def release(self):
            self.lock.release()

    def get(self, key):
        """Get a single value from the KVS backend."""
        self._assert_configured()
        value = self._region.get(key)
        if value is NO_VALUE:
            raise exception.NotFound(target=key)
        return value

    def get_multi(self, keys):
        """Get multiple values in a single call from the KVS backend."""
        self._assert_configured()
        values = self._region.get_multi(keys)
        not_found = []
        for index, key in enumerate(keys):
            if values[index] is NO_VALUE:
                not_found.append(key)
        if not_found:
            # NOTE(morganfainberg): If any of the multi-get values are non-
            # existent, we should raise a NotFound error to mimic the .get()
            # method's behavior.  In all cases the internal dogpile NO_VALUE
            # should be masked from the consumer of the KeyValueStore.
            raise exception.NotFound(target=not_found)
        return values

    def set(self, key, value, lock=None):
        """Set a single value in the KVS backend."""
        self._assert_configured()
        with self._action_with_lock(key, lock):
            self._region.set(key, value)

    def set_multi(self, mapping):
        """Set multiple key/value pairs in the KVS backend at once.

        Like delete_multi, this call does not serialize through the
        KeyValueStoreLock mechanism (locking cannot occur on more than one
        key in a given context without significant deadlock potential).
        """
        self._assert_configured()
        self._region.set_multi(mapping)

    def delete(self, key, lock=None):
        """Delete a single key from the KVS backend.

        This method will raise NotFound if the key doesn't exist.  The get and
        delete are done in a single transaction (via KeyValueStoreLock
        mechanism).
        """
        self._assert_configured()

        with self._action_with_lock(key, lock):
            self.get(key)
            self._region.delete(key)

    def delete_multi(self, keys):
        """Delete multiple keys from the KVS backend in a single call.

        Like set_multi, this call does not serialize through the
        KeyValueStoreLock mechanism (locking cannot occur on more than one
        key in a given context without significant deadlock potential).
        """
        self._assert_configured()
        self._region.delete_multi(keys)

    def get_lock(self, key):
        """Get a write lock on the KVS value referenced by `key`.

        The ability to get a context manager to pass into the set/delete
        methods allows for a single-transaction to occur while guaranteeing the
        backing store will not change between the start of the 'lock' and the
        end.  Lock timeout is fixed to the KeyValueStore configured lock
        timeout.
        """
        self._assert_configured()
        return KeyValueStoreLock(self._mutex(key), key, self.locking,
                                 self._lock_timeout)

    @contextlib.contextmanager
    def _action_with_lock(self, key, lock=None):
        """Wrapper context manager to validate and handle the lock and lock
        timeout if passed in.
        """
        if not isinstance(lock, KeyValueStoreLock):
            # NOTE(morganfainberg): Locking only matters if a lock is passed in
            # to this method.  If lock isn't a KeyValueStoreLock, treat this as
            # if no locking needs to occur.
            yield
        else:
            if not lock.key == key:
                raise ValueError(_('Lock key must match target key: %(lock)s '
                                   '!= %(target)s') %
                                 {'lock': lock.key, 'target': key})
            if not lock.active:
                raise exception.ValidationError(_('Must be called within an '
                                                  'active lock context.'))
            if not lock.expired:
                yield
            else:
                raise LockTimeout(target=key)


class KeyValueStoreLock(object):
    """Basic KeyValueStoreLock context manager that hooks into the
    dogpile.cache backend mutex allowing for distributed locking on resources.

    This is only a write lock, and will not prevent reads from occurring.
    """
    def __init__(self, mutex, key, locking_enabled=True, lock_timeout=0):
        self.mutex = mutex
        self.key = key
        self.enabled = locking_enabled
        self.lock_timeout = lock_timeout
        self.active = False
        self.acquire_time = 0

    def acquire(self):
        if self.enabled:
            self.mutex.acquire()
            LOG.debug('KVS lock acquired for: %s', self.key)
        self.active = True
        self.acquire_time = time.time()
        return self

    __enter__ = acquire

    @property
    def expired(self):
        if self.lock_timeout:
            calculated = time.time() - self.acquire_time + LOCK_WINDOW
            return calculated > self.lock_timeout
        else:
            return False

    def release(self):
        if self.enabled:
            self.mutex.release()
            if not self.expired:
                LOG.debug('KVS lock released for: %s', self.key)
            else:
                LOG.warning(_LW('KVS lock released (timeout reached) for: %s'),
                            self.key)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


def get_key_value_store(name, kvs_region=None):
    """Instantiate a new :class:`.KeyValueStore` or return a previous
    instantiation that has the same name.
    """
    global KEY_VALUE_STORE_REGISTRY

    _register_backends()
    key_value_store = KEY_VALUE_STORE_REGISTRY.get(name)
    if key_value_store is None:
        if kvs_region is None:
            kvs_region = region.make_region(name=name)
        key_value_store = KeyValueStore(kvs_region)
        KEY_VALUE_STORE_REGISTRY[name] = key_value_store
    return key_value_store
