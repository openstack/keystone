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

from keystone.common.kvs import core as kvs_core
from keystone import tests
from keystone import token
from keystone.token.backends import kvs as proxy_kvs
from keystone.token.backends import memcache as proxy_memcache
from keystone.token.backends import sql as proxy_sql
from keystone.token.persistence.backends import kvs
from keystone.token.persistence.backends import memcache
from keystone.token.persistence.backends import sql


class TokenPersistenceProxyTest(tests.BaseTestCase):
    def test_symbols(self):
        """Verify token persistence proxy symbols.

        The Token manager has been moved from `keystone.token.core` to
        `keystone.token.persistence`. This test verifies that the symbols
        resolve as expected.

        """
        self.assertTrue(issubclass(token.Manager, token.persistence.Manager))
        self.assertTrue(issubclass(token.Driver, token.persistence.Driver))


class TokenPersistenceBackendSymbols(tests.TestCase):
    def test_symbols(self):
        """Verify the token persistence backend proxy symbols.

        Make sure that the modules that are (for compat reasons) located at
        `keystone.token.backends` are the same as the new location
        `keystone.token.persistence.backends`.
        """
        self.assertTrue(issubclass(proxy_kvs.Token, kvs.Token))
        self.assertTrue(issubclass(proxy_memcache.Token, memcache.Token))
        self.assertTrue(issubclass(proxy_sql.Token, sql.Token))
        self.assertIs(proxy_sql.TokenModel, sql.TokenModel)

    def test_instantiation_kvs(self):
        self.config_fixture.config(
            group='token',
            driver='keystone.token.backends.kvs.Token')

        # Clear the KVS registry so we can re-instantiate the KVS backend. This
        # is required because the KVS core tries to limit duplication of
        # CacheRegion objects and CacheRegion objects cannot be reconfigured.
        kvs_core.KEY_VALUE_STORE_REGISTRY.clear()

        manager = token.persistence.PersistenceManager()
        self.assertIsInstance(manager.driver, proxy_kvs.Token)
        self.assertIsInstance(manager.driver, kvs.Token)

    def test_instantiation_memcache(self):
        self.config_fixture.config(
            group='token',
            driver='keystone.token.backends.memcache.Token')

        # The memcache token backend is just a light wrapper around the KVS
        # token backend. Clear the KVS registry so we can re-instantiate the
        # KVS backend. This is required because the KVS core tries to limit
        # duplication of CacheRegion objects and CacheRegion objects cannot be
        # reconfigured.
        kvs_core.KEY_VALUE_STORE_REGISTRY.clear()

        manager = token.persistence.PersistenceManager()
        self.assertIsInstance(manager.driver, proxy_memcache.Token)
        self.assertIsInstance(manager.driver, memcache.Token)

    def test_instantiation_sql(self):
        self.config_fixture.config(
            group='token',
            driver='keystone.token.backends.sql.Token')
        manager = token.persistence.PersistenceManager()
        self.assertIsInstance(manager.driver, proxy_sql.Token)
        self.assertIsInstance(manager.driver, sql.Token)
