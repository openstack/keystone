
from keystonelight import models
from keystonelight import test
from keystonelight.backends import kvs


class KvsIdentity(test.TestCase):
  def setUp(self):
    super(KvsIdentity, self).setUp()
    options = self.appconfig('default')
    self.identity_api = kvs.KvsIdentity(options=options, db={})
    self._load_fixtures()

  def _load_fixtures(self):
    self.tenant_bar = self.identity_api._create_tenant(
        'bar',
        models.Tenant(id='bar', name='BAR'))
    self.user_foo = self.identity_api._create_user(
        'foo',
        models.User(id='foo',
                    name='FOO',
                    password='foo2',
                    tenants=[self.tenant_bar['id']]))


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
