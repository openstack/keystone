import uuid

from keystonelight import models
from keystonelight import test
from keystonelight.backends import kvs

import default_fixtures

class KvsIdentity(test.TestCase):
  def setUp(self):
    super(KvsIdentity, self).setUp()
    self.options = self.appconfig('default')
    self.identity_api = kvs.KvsIdentity(options=self.options, db={})
    self.load_fixtures(default_fixtures)

  def test_authenticate_bad_user(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'] + 'WRONG',
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'])

  def test_authenticate_bad_password(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'] + 'WRONG')

  def test_authenticate_invalid_tenant(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'] + 'WRONG',
        password=self.user_foo['password'])

  def test_authenticate_no_tenant(self):
    user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
        user_id=self.user_foo['id'],
        password=self.user_foo['password'])
    self.assertDictEquals(user_ref, self.user_foo)
    self.assert_(tenant_ref is None)
    self.assert_(not extras_ref)

  def test_authenticate(self):
    user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'])
    self.assertDictEquals(user_ref, self.user_foo)
    self.assertDictEquals(tenant_ref, self.tenant_bar)
    self.assertDictEquals(extras_ref, self.extras_foobar)

  def test_get_tenant_bad_tenant(self):
    tenant_ref = self.identity_api.get_tenant(
        tenant_id=self.tenant_bar['id'] + 'WRONG')
    self.assert_(tenant_ref is None)

  def test_get_tenant(self):
    tenant_ref = self.identity_api.get_tenant(tenant_id=self.tenant_bar['id'])
    self.assertDictEquals(tenant_ref, self.tenant_bar)

  def test_get_tenant_by_name_bad_tenant(self):
    tenant_ref = self.identity_api.get_tenant(
        tenant_id=self.tenant_bar['name'] + 'WRONG')
    self.assert_(tenant_ref is None)

  def test_get_tenant_by_name(self):
    tenant_ref = self.identity_api.get_tenant_by_name(
        tenant_name=self.tenant_bar['name'])
    self.assertDictEquals(tenant_ref, self.tenant_bar)

  def test_get_user_bad_user(self):
    user_ref = self.identity_api.get_user(
        user_id=self.user_foo['id'] + 'WRONG')
    self.assert_(user_ref is None)

  def test_get_user(self):
    user_ref = self.identity_api.get_user(user_id=self.user_foo['id'])
    self.assertDictEquals(user_ref, self.user_foo)

  def test_get_extras_bad_user(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'] + 'WRONG',
        tenant_id=self.tenant_bar['id'])
    self.assert_(extras_ref is None)

  def test_get_extras_bad_tenant(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'] + 'WRONG')
    self.assert_(extras_ref is None)

  def test_get_extras(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'])
    self.assertDictEquals(extras_ref, self.extras_foobar)

  def test_get_role(self):
    role_ref = self.identity_api.get_role(
        role_id=self.role_keystone_admin['id'])
    self.assertDictEquals(role_ref, self.role_keystone_admin)


class KvsToken(test.TestCase):
  def setUp(self):
    super(KvsToken, self).setUp()
    options = self.appconfig('default')
    self.token_api = kvs.KvsToken(options=options, db={})

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
    options = self.appconfig('default')
    self.catalog_api = kvs.KvsCatalog(options=options, db={})
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
