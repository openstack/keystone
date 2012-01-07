import os
import uuid

from keystonelight import models
from keystonelight import test
from keystonelight.backends import sql
from keystonelight.backends.sql import migration

import test_backends
import default_fixtures


class SqlIdentity(test.TestCase, test_backends.IdentityTests):
  def setUp(self):
    super(SqlIdentity, self).setUp()
    self.options = self.appconfig('default')
    os.unlink('bla.db')
    migration.db_sync(self.options, 1)
    self.identity_api = sql.SqlIdentity(options=self.options)
    self.load_fixtures(default_fixtures)


#class SqlToken(test_backend_kvs.KvsToken):
#  def setUp(self):
#    super(SqlToken, self).setUp()
#    self.token_api = sql.SqlToken(options=options)
#    self.load_fixtures(default_fixtures)

#  def test_token_crud(self):
#    token_id = uuid.uuid4().hex
#    data = {'id': token_id,
#            'a': 'b'}
#    data_ref = self.token_api.create_token(token_id, data)
#    self.assertDictEquals(data_ref, data)

#    new_data_ref = self.token_api.get_token(token_id)
#    self.assertEquals(new_data_ref, data)

#    self.token_api.delete_token(token_id)
#    deleted_data_ref = self.token_api.get_token(token_id)
#    self.assert_(deleted_data_ref is None)


#class SqlCatalog(test_backend_kvs.KvsCatalog):
#  def setUp(self):
#    super(SqlCatalog, self).setUp()
#    self.catalog_api = sql.SqlCatalog(options=options)
#    self._load_fixtures()

#  def _load_fixtures(self):
#    self.catalog_foobar = self.catalog_api._create_catalog(
#        'foo', 'bar',
#        {'RegionFoo': {'service_bar': {'foo': 'bar'}}})

#  def test_get_catalog_bad_user(self):
#    catalog_ref = self.catalog_api.get_catalog('foo' + 'WRONG', 'bar')
#    self.assert_(catalog_ref is None)

#  def test_get_catalog_bad_tenant(self):
#    catalog_ref = self.catalog_api.get_catalog('foo', 'bar' + 'WRONG')
#    self.assert_(catalog_ref is None)

#  def test_get_catalog(self):
#    catalog_ref = self.catalog_api.get_catalog('foo', 'bar')
#    self.assertDictEquals(catalog_ref, self.catalog_foobar)
