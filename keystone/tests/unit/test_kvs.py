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

import time
import uuid

from dogpile.cache import api
from dogpile.cache import proxy
from dogpile.cache import util
import mock
import six
from testtools import matchers

from keystone.common.kvs.backends import inmemdb
from keystone.common.kvs.backends import memcached
from keystone.common.kvs import core
from keystone import exception
from keystone.tests import unit


NO_VALUE = api.NO_VALUE


class MutexFixture(object):
    def __init__(self, storage_dict, key, timeout):
        self.database = storage_dict
        self.key = '_lock' + key

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


class TestMemcacheDriver(api.CacheBackend):
    """A test dogpile.cache backend that conforms to the mixin-mechanism for
    overriding set and set_multi methods on dogpile memcached drivers.
    """
    class test_client(object):
        # FIXME(morganfainberg): Convert this test client over to using mock
        # and/or mock.MagicMock as appropriate

        def __init__(self):
            self.__name__ = 'TestingMemcacheDriverClientObject'
            self.set_arguments_passed = None
            self.keys_values = {}
            self.lock_set_time = None
            self.lock_expiry = None

        def set(self, key, value, **set_arguments):
            self.keys_values.clear()
            self.keys_values[key] = value
            self.set_arguments_passed = set_arguments

        def set_multi(self, mapping, **set_arguments):
            self.keys_values.clear()
            self.keys_values = mapping
            self.set_arguments_passed = set_arguments

        def add(self, key, value, expiry_time):
            # NOTE(morganfainberg): `add` is used in this case for the
            # memcache lock testing. If further testing is required around the
            # actual memcache `add` interface, this method should be
            # expanded to work more like the actual memcache `add` function
            if self.lock_expiry is not None and self.lock_set_time is not None:
                if time.time() - self.lock_set_time < self.lock_expiry:
                    return False
            self.lock_expiry = expiry_time
            self.lock_set_time = time.time()
            return True

        def delete(self, key):
            # NOTE(morganfainberg): `delete` is used in this case for the
            # memcache lock testing. If further testing is required around the
            # actual memcache `delete` interface, this method should be
            # expanded to work more like the actual memcache `delete` function.
            self.lock_expiry = None
            self.lock_set_time = None
            return True

    def __init__(self, arguments):
        self.client = self.test_client()
        self.set_arguments = {}
        # NOTE(morganfainberg): This is the same logic as the dogpile backend
        # since we need to mirror that functionality for the `set_argument`
        # values to appear on the actual backend.
        if 'memcached_expire_time' in arguments:
            self.set_arguments['time'] = arguments['memcached_expire_time']

    def set(self, key, value):
        self.client.set(key, value, **self.set_arguments)

    def set_multi(self, mapping):
        self.client.set_multi(mapping, **self.set_arguments)


class KVSTest(unit.TestCase):
    def setUp(self):
        super(KVSTest, self).setUp()
        self.key_foo = 'foo_' + uuid.uuid4().hex
        self.value_foo = uuid.uuid4().hex
        self.key_bar = 'bar_' + uuid.uuid4().hex
        self.value_bar = {'complex_data_structure': uuid.uuid4().hex}
        self.addCleanup(memcached.VALID_DOGPILE_BACKENDS.pop,
                        'TestDriver',
                        None)
        memcached.VALID_DOGPILE_BACKENDS['TestDriver'] = TestMemcacheDriver

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
        self.assertEqual(region_one, kvs._region.name)

        kvs = self._get_kvs_region(region_two)
        kvs.configure('openstack.kvs.KVSBackendFixture',
                      test_arg=test_arg)

        self.assertEqual(region_two, kvs._region.name)
        self.assertEqual(test_arg, kvs._region.backend.test_arg)

    def test_kvs_proxy_configuration(self):
        # Test that proxies are applied correctly and in the correct (reverse)
        # order to the kvs region.
        kvs = self._get_kvs_region()
        kvs.configure(
            'openstack.kvs.Memory',
            proxy_list=['keystone.tests.unit.test_kvs.RegionProxyFixture',
                        'keystone.tests.unit.test_kvs.RegionProxy2Fixture'])

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
        # The backend should also have the keymangler set the same as the
        # region now.
        self.assertIs(kvs._region.backend.key_mangler, util.sha1_mangle_key)

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
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        self.assertIsNone(kvs._region.key_mangler)
        self.assertIsNone(kvs._region.backend.key_mangler)

    def test_kvs_key_mangler_set_on_backend(self):
        def test_key_mangler(key):
            return key

        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')
        self.assertIs(kvs._region.backend.key_mangler, util.sha1_mangle_key)
        kvs._set_key_mangler(test_key_mangler)
        self.assertIs(kvs._region.backend.key_mangler, test_key_mangler)

    def test_kvs_basic_get_set_delete(self):
        # Test the basic get/set/delete actions on the KVS region
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memory')

        # Not found should be raised if the key doesn't exist
        self.assertRaises(exception.NotFound, kvs.get, key=self.key_bar)
        kvs.set(self.key_bar, self.value_bar)
        returned_value = kvs.get(self.key_bar)
        # The returned value should be the same value as the value in .set
        self.assertEqual(self.value_bar, returned_value)
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
        self.assertEqual(expected, kvs.get_multi(keys))
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
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
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
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
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
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
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
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
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

    def test_kvs_memcached_manager_valid_dogpile_memcached_backend(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memcached',
                      memcached_backend='TestDriver')
        self.assertIsInstance(kvs._region.backend.driver,
                              TestMemcacheDriver)

    def test_kvs_memcached_manager_invalid_dogpile_memcached_backend(self):
        # Invalid dogpile memcache backend should raise ValueError
        kvs = self._get_kvs_region()
        self.assertRaises(ValueError,
                          kvs.configure,
                          backing_store='openstack.kvs.Memcached',
                          memcached_backend=uuid.uuid4().hex)

    def test_kvs_memcache_manager_no_expiry_keys(self):
        # Make sure the memcache backend recalculates the no-expiry keys
        # correctly when a key-mangler is set on it.

        def new_mangler(key):
            return '_mangled_key_' + key

        kvs = self._get_kvs_region()
        no_expiry_keys = set(['test_key'])
        kvs.configure('openstack.kvs.Memcached',
                      memcached_backend='TestDriver',
                      no_expiry_keys=no_expiry_keys)
        calculated_keys = set([kvs._region.key_mangler(key)
                               for key in no_expiry_keys])
        self.assertIs(kvs._region.backend.key_mangler, util.sha1_mangle_key)
        self.assertSetEqual(calculated_keys,
                            kvs._region.backend.no_expiry_hashed_keys)
        self.assertSetEqual(no_expiry_keys,
                            kvs._region.backend.raw_no_expiry_keys)
        calculated_keys = set([new_mangler(key) for key in no_expiry_keys])
        kvs._region.backend.key_mangler = new_mangler
        self.assertSetEqual(calculated_keys,
                            kvs._region.backend.no_expiry_hashed_keys)
        self.assertSetEqual(no_expiry_keys,
                            kvs._region.backend.raw_no_expiry_keys)

    def test_kvs_memcache_key_mangler_set_to_none(self):
        kvs = self._get_kvs_region()
        no_expiry_keys = set(['test_key'])
        kvs.configure('openstack.kvs.Memcached',
                      memcached_backend='TestDriver',
                      no_expiry_keys=no_expiry_keys)
        self.assertIs(kvs._region.backend.key_mangler, util.sha1_mangle_key)
        kvs._region.backend.key_mangler = None
        self.assertSetEqual(kvs._region.backend.raw_no_expiry_keys,
                            kvs._region.backend.no_expiry_hashed_keys)
        self.assertIsNone(kvs._region.backend.key_mangler)

    def test_noncallable_key_mangler_set_on_driver_raises_type_error(self):
        kvs = self._get_kvs_region()
        kvs.configure('openstack.kvs.Memcached',
                      memcached_backend='TestDriver')
        self.assertRaises(TypeError,
                          setattr,
                          kvs._region.backend,
                          'key_mangler',
                          'Non-Callable')

    def test_kvs_memcache_set_arguments_and_memcache_expires_ttl(self):
        # Test the "set_arguments" (arguments passed on all set calls) logic
        # and the no-expiry-key modifications of set_arguments for the explicit
        # memcache TTL.
        self.config_fixture.config(group='kvs', enable_key_mangler=False)
        kvs = self._get_kvs_region()
        memcache_expire_time = 86400

        expected_set_args = {'time': memcache_expire_time}
        expected_no_expiry_args = {}

        expected_foo_keys = [self.key_foo]
        expected_bar_keys = [self.key_bar]

        mapping_foo = {self.key_foo: self.value_foo}
        mapping_bar = {self.key_bar: self.value_bar}

        kvs.configure(backing_store='openstack.kvs.Memcached',
                      memcached_backend='TestDriver',
                      memcached_expire_time=memcache_expire_time,
                      some_other_arg=uuid.uuid4().hex,
                      no_expiry_keys=[self.key_bar])
        kvs_driver = kvs._region.backend.driver

        # Ensure the set_arguments are correct
        self.assertDictEqual(
            kvs._region.backend._get_set_arguments_driver_attr(),
            expected_set_args)

        # Set a key that would have an expiry and verify the correct result
        # occurred and that the correct set_arguments were passed.
        kvs.set(self.key_foo, self.value_foo)
        self.assertDictEqual(
            kvs._region.backend.driver.client.set_arguments_passed,
            expected_set_args)
        observed_foo_keys = list(kvs_driver.client.keys_values.keys())
        self.assertEqual(expected_foo_keys, observed_foo_keys)
        self.assertEqual(
            self.value_foo,
            kvs._region.backend.driver.client.keys_values[self.key_foo][0])

        # Set a key that would not have an expiry and verify the correct result
        # occurred and that the correct set_arguments were passed.
        kvs.set(self.key_bar, self.value_bar)
        self.assertDictEqual(
            kvs._region.backend.driver.client.set_arguments_passed,
            expected_no_expiry_args)
        observed_bar_keys = list(kvs_driver.client.keys_values.keys())
        self.assertEqual(expected_bar_keys, observed_bar_keys)
        self.assertEqual(
            self.value_bar,
            kvs._region.backend.driver.client.keys_values[self.key_bar][0])

        # set_multi a dict that would have an expiry and verify the correct
        # result occurred and that the correct set_arguments were passed.
        kvs.set_multi(mapping_foo)
        self.assertDictEqual(
            kvs._region.backend.driver.client.set_arguments_passed,
            expected_set_args)
        observed_foo_keys = list(kvs_driver.client.keys_values.keys())
        self.assertEqual(expected_foo_keys, observed_foo_keys)
        self.assertEqual(
            self.value_foo,
            kvs._region.backend.driver.client.keys_values[self.key_foo][0])

        # set_multi a dict that would not have an expiry and verify the correct
        # result occurred and that the correct set_arguments were passed.
        kvs.set_multi(mapping_bar)
        self.assertDictEqual(
            kvs._region.backend.driver.client.set_arguments_passed,
            expected_no_expiry_args)
        observed_bar_keys = list(kvs_driver.client.keys_values.keys())
        self.assertEqual(expected_bar_keys, observed_bar_keys)
        self.assertEqual(
            self.value_bar,
            kvs._region.backend.driver.client.keys_values[self.key_bar][0])

    def test_memcached_lock_max_lock_attempts(self):
        kvs = self._get_kvs_region()
        max_lock_attempts = 1
        test_key = uuid.uuid4().hex

        kvs.configure(backing_store='openstack.kvs.Memcached',
                      memcached_backend='TestDriver',
                      max_lock_attempts=max_lock_attempts)

        self.assertEqual(max_lock_attempts,
                         kvs._region.backend.max_lock_attempts)
        # Simple Lock success test
        with kvs.get_lock(test_key) as lock:
            kvs.set(test_key, 'testing', lock)

        def lock_within_a_lock(key):
            with kvs.get_lock(key) as first_lock:
                kvs.set(test_key, 'lock', first_lock)
                with kvs.get_lock(key) as second_lock:
                    kvs.set(key, 'lock-within-a-lock', second_lock)

        self.assertRaises(exception.UnexpectedError,
                          lock_within_a_lock,
                          key=test_key)


class TestMemcachedBackend(unit.TestCase):

    @mock.patch('keystone.common.kvs.backends.memcached._', six.text_type)
    def test_invalid_backend_fails_initialization(self):
        raises_valueerror = matchers.Raises(matchers.MatchesException(
            ValueError, r'.*FakeBackend.*'))

        options = {
            'url': 'needed to get to the focus of this test (the backend)',
            'memcached_backend': 'FakeBackend',
        }
        self.assertThat(lambda: memcached.MemcachedBackend(options),
                        raises_valueerror)
