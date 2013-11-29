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

import uuid

from dogpile.cache import api
from dogpile.cache.backends import memcached as dogpile_memcached
from dogpile.cache import proxy
from dogpile.cache import util

from keystone.common.kvs.backends import inmemdb
from keystone.common.kvs import core
from keystone import exception
from keystone import tests

NO_VALUE = api.NO_VALUE


class MutexFixture(object):
    def __init__(self, storage_dict, key, timeout):
        self.database = storage_dict
        self.key = '_lock' + key
        self.lock_timeout = timeout

    def acquire(self, wait=True):
        while True:
            try:
                self.database[self.key] = 1
                return True
            except KeyError:
                return False

    def release(self):
        self.database.pop(self.key, None)


class KVSBackendFixture(inmemdb.MemoryBackend):
    def __init__(self, arguments):
        class InmemTestDB(dict):
            def __setitem__(self, key, value):
                if key in self:
                    raise KeyError('Key %s already exists' % key)
                super(InmemTestDB, self).__setitem__(key, value)

        self._db = InmemTestDB()
        self.lock_timeout = arguments.pop('lock_timeout', 5)
        self.test_arg = arguments.pop('test_arg', None)

    def get_mutex(self, key):
        return MutexFixture(self._db, key, self.lock_timeout)

    @classmethod
    def key_mangler(cls, key):
        return 'KVSBackend_' + key


class KVSBackendForcedKeyMangleFixture(KVSBackendFixture):
    use_backend_key_mangler = True

    @classmethod
    def key_mangler(cls, key):
        return 'KVSBackendForcedKeyMangle_' + key


class RegionProxyFixture(proxy.ProxyBackend):
    """A test dogpile.cache proxy that does nothing."""


class RegionProxy2Fixture(proxy.ProxyBackend):
    """A test dogpile.cache proxy that does nothing."""


class KVSTest(tests.TestCase):
    def setUp(self):
        super(KVSTest, self).setUp()
        self.key_foo = 'foo_' + uuid.uuid4().hex
        self.value_foo = uuid.uuid4().hex
        self.key_bar = 'bar_' + uuid.uuid4().hex
        self.value_bar = {'complex_data_structure': uuid.uuid4().hex}

    def _get_kvs_region(self, name=None):
        if name is None:
            name = uuid.uuid4().hex
        return core.get_key_value_store(name)

    def test_kvs_basic_configuration(self):
        # Test that the most basic configuration options pass through to the
        # backend.
        region_one = uuid.uuid4().hex
        region_two = uuid.uuid4().hex
        test_arg = 100
        kvs = self._get_kvs_region(region_one)
        kvs.configure('openstack.kvs.Memory')

        self.assertIsInstance(kvs._region.backend, inmemdb.MemoryBackend)
        self.assertEqual(kvs._region.name, region_one)

        kvs = self._get_kvs_region(region_two)
        kvs.configure('openstack.kvs.KVSBackendFixture',
                      test_arg=test_arg)

        self.assertEqual(kvs._region.name, region_two)
        self.assertEqual(kvs._region.backend.test_arg, test_arg)

    def test_kvs_proxy_configuration(self):
        # Test that proxies are applied correctly and in the correct (reverse)
        # order to the kvs region.
        kvs = self._get_kvs_region()
        kvs.configure(
            'openstack.kvs.Memory',
            proxy_list=['keystone.tests.test_kvs.RegionProxyFixture',
                        'keystone.tests.test_kvs.RegionProxy2Fixture'])

        self.assertIsInstance(kvs._region.backend, RegionProxyFixture)
        self.assertIsInstance(kvs._region.backend.proxied, RegionProxy2Fixture)
        self.assertIsInstance(kvs._region.backend.proxied.proxied,
                              inmemdb.MemoryBackend)

    def test_kvs_key_mangler_fallthrough_default(self):
        # Test to make sure we default to the standard dogpile sha1 hashing
        # key_mangler
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        self.assertIs(kvs._region.key_mangler, util.sha1_mangle_key)

    def test_kvs_key_mangler_configuration_backend(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendFixture')
        expected = KVSBackendFixture.key_mangler(self.key_foo)
        self.assertEqual(expected, kvs._region.key_mangler(self.key_foo))

    def test_kvs_key_mangler_configuration_forced_backend(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendForcedKeyMangleFixture',
                      key_mangler=util.sha1_mangle_key)
        expected = KVSBackendForcedKeyMangleFixture.key_mangler(self.key_foo)
        self.assertEqual(expected, kvs._region.key_mangler(self.key_foo))

    def test_kvs_key_mangler_configuration_disabled(self):
        # Test that no key_mangler is set if enable_key_mangler is false
        self.opt_in_group('kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        self.assertIs(kvs._region.key_mangler, None)

    def test_kvs_basic_get_set_delete(self):
        # Test the basic get/set/delete actions on the KVS region
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        # Not found should be raised if the key doesn't exist
        self.assertRaises(exception.NotFound, kvs.get, key=self.key_bar)
        kvs.set(self.key_bar, self.value_bar)
        returned_value = kvs.get(self.key_bar)
        # The returned value should be the same value as the value in .set
        self.assertEqual(returned_value, self.value_bar)
        # The value should not be the exact object used in .set
        self.assertIsNot(returned_value, self.value_bar)
        kvs.delete(self.key_bar)
        # Second delete should raise NotFound
        self.assertRaises(exception.NotFound, kvs.delete, key=self.key_bar)

    def _kvs_multi_get_set_delete(self, kvs):
        keys = [self.key_foo, self.key_bar]
        expected = [self.value_foo, self.value_bar]

        kvs.set_multi({self.key_foo: self.value_foo,
                       self.key_bar: self.value_bar})
        # Returned value from get_multi should be a list of the values of the
        # keys
        self.assertEqual(kvs.get_multi(keys), expected)
        # Delete both keys
        kvs.delete_multi(keys)
        # make sure that NotFound is properly raised when trying to get the now
        # deleted keys
        self.assertRaises(exception.NotFound, kvs.get_multi, keys=keys)
        self.assertRaises(exception.NotFound, kvs.get, key=self.key_foo)
        self.assertRaises(exception.NotFound, kvs.get, key=self.key_bar)
        # Make sure get_multi raises NotFound if one of the keys isn't found
        kvs.set(self.key_foo, self.value_foo)
        self.assertRaises(exception.NotFound, kvs.get_multi, keys=keys)

    def test_kvs_multi_get_set_delete(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        self._kvs_multi_get_set_delete(kvs)

    def test_kvs_locking_context_handler(self):
        # Make sure we're creating the correct key/value pairs for the backend
        # distributed locking mutex.
        self.opt_in_group('kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendFixture')

        lock_key = '_lock' + self.key_foo
        self.assertNotIn(lock_key, kvs._region.backend._db)
        with core.KeyValueStoreLock(kvs._mutex(self.key_foo), self.key_foo):
            self.assertIn(lock_key, kvs._region.backend._db)
            self.assertIs(kvs._region.backend._db[lock_key], 1)

        self.assertNotIn(lock_key, kvs._region.backend._db)

    def test_kvs_locking_context_handler_locking_disabled(self):
        # Make sure no creation of key/value pairs for the backend
        # distributed locking mutex occurs if locking is disabled.
        self.opt_in_group('kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendFixture', locking=False)
        lock_key = '_lock' + self.key_foo
        self.assertNotIn(lock_key, kvs._region.backend._db)
        with core.KeyValueStoreLock(kvs._mutex(self.key_foo), self.key_foo,
                                    False):
            self.assertNotIn(lock_key, kvs._region.backend._db)

        self.assertNotIn(lock_key, kvs._region.backend._db)

    def test_kvs_with_lock_action_context_manager_timeout(self):
        kvs = self._get_kvs_region()
        lock_timeout = 5
        kvs.configure('openstack.kvs.Memory', lock_timeout=lock_timeout)

        def do_with_lock_action_timeout(kvs_region, key, offset):
            with kvs_region.get_lock(key) as lock_in_use:
                self.assertTrue(lock_in_use.active)
                # Subtract the offset from the acquire_time.  If this puts the
                # acquire_time difference from time.time() at >= lock_timeout
                # this should raise a LockTimeout exception.  This is because
                # there is a built-in 1-second overlap where the context
                # manager thinks the lock is expired but the lock is still
                # active.  This is to help mitigate race conditions on the
                # time-check itself.
                lock_in_use.acquire_time -= offset
                with kvs_region._action_with_lock(key, lock_in_use):
                    pass

        # This should succeed, we are not timed-out here.
        do_with_lock_action_timeout(kvs, key=uuid.uuid4().hex, offset=2)
        # Try it now with an offset equal to the lock_timeout
        self.assertRaises(core.LockTimeout,
                          do_with_lock_action_timeout,
                          kvs_region=kvs,
                          key=uuid.uuid4().hex,
                          offset=lock_timeout)
        # Final test with offset significantly greater than the lock_timeout
        self.assertRaises(core.LockTimeout,
                          do_with_lock_action_timeout,
                          kvs_region=kvs,
                          key=uuid.uuid4().hex,
                          offset=100)

    def test_kvs_with_lock_action_mismatched_keys(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        def do_with_lock_action(kvs_region, lock_key, target_key):
            with kvs_region.get_lock(lock_key) as lock_in_use:
                self.assertTrue(lock_in_use.active)
                with kvs_region._action_with_lock(target_key, lock_in_use):
                    pass

        # Ensure we raise a ValueError if the lock key mismatches from the
        # target key.
        self.assertRaises(ValueError,
                          do_with_lock_action,
                          kvs_region=kvs,
                          lock_key=self.key_foo,
                          target_key=self.key_bar)

    def test_kvs_with_lock_action_context_manager(self):
        # Make sure we're creating the correct key/value pairs for the backend
        # distributed locking mutex.
        self.opt_in_group('kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendFixture')

        lock_key = '_lock' + self.key_foo
        self.assertNotIn(lock_key, kvs._region.backend._db)
        with kvs.get_lock(self.key_foo) as lock:
            with kvs._action_with_lock(self.key_foo, lock):
                self.assertTrue(lock.active)
                self.assertIn(lock_key, kvs._region.backend._db)
                self.assertIs(kvs._region.backend._db[lock_key], 1)

        self.assertNotIn(lock_key, kvs._region.backend._db)

    def test_kvs_with_lock_action_context_manager_no_lock(self):
        # Make sure we're not locking unless an actual lock is passed into the
        # context manager
        self.opt_in_group('kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.KVSBackendFixture')

        lock_key = '_lock' + self.key_foo
        lock = None
        self.assertNotIn(lock_key, kvs._region.backend._db)
        with kvs._action_with_lock(self.key_foo, lock):
            self.assertNotIn(lock_key, kvs._region.backend._db)

        self.assertNotIn(lock_key, kvs._region.backend._db)

    def test_kvs_backend_registration_does_not_reregister_backends(self):
        # SetUp registers the test backends.  Running this again would raise an
        # exception if re-registration of the backends occurred.
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')
        core._register_backends()

    def test_kvs_memcache_manager_valid_dogpile_memcache_backend(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memcached',
                      dogpile_memcache_backend='MemcachedBackend')
        self.assertIsInstance(kvs._region.backend.driver,
                              dogpile_memcached.MemcachedBackend)

    def test_kvs_memcache_manager_invalid_dogpile_memcache_backend(self):
        # Invalid dogpile memcache backend should raise ValueError
        kvs = self._get_kvs_region()
        self.assertRaises(ValueError,
                          kvs.configure,
                          backing_store='openstack.kvs.Memcached',
                          dogpile_memcache_backend=uuid.uuid4().hex)
