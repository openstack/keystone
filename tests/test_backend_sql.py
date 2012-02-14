# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import config
from keystone import test
from keystone.common.sql import util as sql_util
from keystone.identity.backends import sql as identity_sql
from keystone.token.backends import sql as token_sql

import test_backend
import default_fixtures


CONF = config.CONF


class SqlIdentity(test.TestCase, test_backend.IdentityTests):
  def setUp(self):
    super(SqlIdentity, self).setUp()
    CONF(config_files=[test.etcdir('keystone.conf'),
                       test.testsdir('test_overrides.conf'),
                       test.testsdir('backend_sql.conf')])
    sql_util.setup_test_database()
    self.identity_api = identity_sql.Identity()
    self.load_fixtures(default_fixtures)


class SqlToken(test.TestCase, test_backend.TokenTests):
  def setUp(self):
    super(SqlToken, self).setUp()
    CONF(config_files=[test.etcdir('keystone.conf'),
                       test.testsdir('test_overrides.conf'),
                       test.testsdir('backend_sql.conf')])
    sql_util.setup_test_database()
    self.token_api = token_sql.Token()


#class SqlCatalog(test_backend_kvs.KvsCatalog):
#  def setUp(self):
#    super(SqlCatalog, self).setUp()
#    self.catalog_api = sql.SqlCatalog()
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
