from keystone import test
from keystone.identity.backends import kvs as identity_kvs
from keystone.token.backends import kvs as token_kvs
from keystone.catalog.backends import kvs as catalog_kvs

import test_backend
import default_fixtures


class KvsIdentity(test.TestCase, test_backend.IdentityTests):
  def setUp(self):
    super(KvsIdentity, self).setUp()
    self.identity_api = identity_kvs.Identity(db={})
    self.load_fixtures(default_fixtures)


class KvsToken(test.TestCase, test_backend.TokenTests):
  def setUp(self):
    super(KvsToken, self).setUp()
    self.token_api = token_kvs.Token(db={})


class KvsCatalog(test.TestCase):
  def setUp(self):
    super(KvsCatalog, self).setUp()
    self.catalog_api = catalog_kvs.Catalog(db={})
    self._load_fixtures()

  def _load_fixtures(self):
    self.catalog_foobar = self.catalog_api._create_catalog(
        'foo', 'bar',
        {'RegionFoo': {'service_bar': {'foo': 'bar'}}})

  def test_get_catalog_bad_user(self):
    catalog_ref = self.catalog_api.get_catalog('foo' + 'WRONG', 'bar')
    self.assert_(catalog_ref is None)

  def test_get_catalog_bad_tenant(self):
    catalog_ref = self.catalog_api.get_catalog('foo', 'bar' + 'WRONG')
    self.assert_(catalog_ref is None)

  def test_get_catalog(self):
    catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
    self.assertDictEquals(catalog_ref, self.catalog_foobar)
