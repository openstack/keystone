import json
import uuid

from keystonelight import client
from keystonelight import models
from keystonelight import test
from keystonelight import utils
from keystonelight.backends import kvs


class IdentityApi(test.TestCase):
  def setUp(self):
    super(IdentityApi, self).setUp()
    self.options = self.appconfig('default')
    app = self.loadapp('default')
    self.app = app

    self.identity_backend = utils.import_object(
        self.options['identity_driver'], options=self.options)
    self.token_backend = utils.import_object(
        self.options['token_driver'], options=self.options)
    self.catalog_backend = utils.import_object(
        self.options['catalog_driver'], options=self.options)
    self._load_fixtures()

  def _load_fixtures(self):
    self.tenant_bar = self.identity_backend._create_tenant(
        'bar',
        models.Tenant(id='bar', name='BAR'))
    self.user_foo = self.identity_backend._create_user(
        'foo',
        models.User(id='foo',
                    name='FOO',
                    password='foo2',
                    tenants=[self.tenant_bar['id']]))
    self.extras_foobar = self.identity_backend._create_extras(
        'foo', 'bar',
        {'extra': 'extra'})

  def _login(self):
    c = client.TestClient(self.app)
    post_data = {'user_id': self.user_foo['id'],
                 'tenant_id': self.tenant_bar['id'],
                 'password': self.user_foo['password']}
    resp = c.post('/tokens', body=post_data)
    token = json.loads(resp.body)
    return token

  def test_authenticate(self):
    c = client.TestClient(self.app)
    post_data = {'user_id': self.user_foo['id'],
                 'tenant_id': self.tenant_bar['id'],
                 'password': self.user_foo['password']}
    resp = c.authenticate(**post_data)
    data = json.loads(resp.body)
    self.assertEquals(self.user_foo['id'], data['user']['id'])
    self.assertEquals(self.tenant_bar['id'], data['tenant']['id'])
    self.assertDictEquals(self.extras_foobar, data['extras'])

  def test_authenticate_no_tenant(self):
    c = client.TestClient(self.app)
    post_data = {'user_id': self.user_foo['id'],
                 'password': self.user_foo['password']}
    resp = c.authenticate(**post_data)
    data = json.loads(resp.body)
    self.assertEquals(self.user_foo['id'], data['user']['id'])
    self.assertEquals(None, data['tenant'])
    self.assertEquals(None, data['extras'])

  def test_get_tenants(self):
    token = self._login()
    c = client.TestClient(self.app, token['id'])
    resp = c.get_tenants(user_id=self.user_foo['id'])
    data = json.loads(resp.body)
    self.assertDictEquals(self.tenant_bar, data[0])

  def test_create_user(self):
    token_id = self.options['admin_token']
    c = client.TestClient(self.app, token=token_id)
    user_ref = models.User()
    resp = c.create_user(**user_ref)
    data = json.loads(resp.body)
    self.assert_(data['id'])

    get_resp = c.get_user(user_id=data['id'])
    get_data = json.loads(get_resp.body)

    self.assertDictEquals(data, get_data)

    del_resp = c.delete_user(user_id=data['id'])
    self.assertEquals(del_resp.body, '')

    delget_resp = c.get_user(user_id=data['id'])
