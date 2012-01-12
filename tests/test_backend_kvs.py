import uuid

from keystone import test
from keystone.backends import kvs

import test_backend
import default_fixtures


class KvsIdentity(test.TestCase, test_backend.IdentityTests):
  def setUp(self):
    super(KvsIdentity, self).setUp()
    self.identity_api = kvs.KvsIdentity(db={})
    self.load_fixtures(default_fixtures)


class KvsToken(test.TestCase):
  def setUp(self):
    super(KvsToken, self).setUp()
    self.token_api = kvs.KvsToken(db={})

  def test_token_crud(self):
    token_id = uuid.uuid4().hex
    data = {'id': token_id,
            'a': 'b'}
    data_ref = self.token_api.create_token(token_id, data)
    self.assertDictEquals(data_ref, data)

    new_data_ref = self.token_api.get_token(token_id)
    self.assertEquals(new_data_ref, data)

    self.token_api.delete_token(token_id)
    deleted_data_ref = self.token_api.get_token(token_id)
    self.assert_(deleted_data_ref is None)


class KvsCatalog(test.TestCase):
  def setUp(self):
    super(KvsCatalog, self).setUp()
    self.catalog_api = kvs.KvsCatalog(db={})
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
