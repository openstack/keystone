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
    self.tenant_bar = self.identity_backend.create_tenant(
        'bar',
        models.Tenant(id='bar', name='BAR'))
    self.user_foo = self.identity_backend.create_user(
        'foo',
        models.User(id='foo',
                    name='FOO',
                    password='foo2',
                    tenants=[self.tenant_bar['id']]))
    self.extras_foobar = self.identity_backend.create_extras(
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
    self.assertEquals({}, data['extras'])

  def test_get_tenants(self):
    token = self._login()
    c = client.TestClient(self.app, token['id'])
    resp = c.get_tenants(user_id=self.user_foo['id'])
    data = json.loads(resp.body)
    self.assertDictEquals(self.tenant_bar, data[0])

  def test_crud_user(self):
    token_id = self.options['admin_token']
    c = client.TestClient(self.app, token=token_id)
    user_ref = models.User(name='FOO')
    resp = c.create_user(**user_ref)
    data = json.loads(resp.body)
    self.assert_(data['id'])

    get_resp = c.get_user(user_id=data['id'])
    get_data = json.loads(get_resp.body)

    self.assertDictEquals(data, get_data)

    update_resp = c.update_user(user_id=data['id'],
                                name='FOO',
                                id=data['id'],
                                password='foo')
    update_data = json.loads(update_resp.body)

    self.assertEquals(data['id'], update_data['id'])
    self.assertEquals('foo', update_data['password'])

    del_resp = c.delete_user(user_id=data['id'])
    self.assertEquals(del_resp.body, '')

    delget_resp = c.get_user(user_id=data['id'])
    self.assertEquals(delget_resp.body, '')
    # TODO(termie): we should probably return not founds instead of None
    #self.assertEquals(delget_resp.status, '404 Not Found')

  def test_crud_tenant(self):
    token_id = self.options['admin_token']
    c = client.TestClient(self.app, token=token_id)
    tenant_ref = models.Tenant(name='BAZ')
    resp = c.create_tenant(**tenant_ref)
    data = json.loads(resp.body)
    self.assert_(data['id'])

    get_resp = c.get_tenant(tenant_id=data['id'])
    get_data = json.loads(get_resp.body)
    self.assertDictEquals(data, get_data)

    getname_resp = c.get_tenant_by_name(tenant_name=data['name'])
    getname_data = json.loads(getname_resp.body)
    self.assertDictEquals(data, getname_data)

    update_resp = c.update_tenant(tenant_id=data['id'],
                                id=data['id'],
                                name='NEWBAZ')
    update_data = json.loads(update_resp.body)

    self.assertEquals(data['id'], update_data['id'])
    self.assertEquals('NEWBAZ', update_data['name'])

    # make sure we can't get the old name
    getname_resp = c.get_tenant_by_name(tenant_name=data['name'])
    self.assertEquals(getname_resp.body, '')

    # but can get the new name
    getname_resp = c.get_tenant_by_name(tenant_name=update_data['name'])
    getname_data = json.loads(getname_resp.body)
    self.assertDictEquals(update_data, getname_data)

    del_resp = c.delete_tenant(tenant_id=data['id'])
    self.assertEquals(del_resp.body, '')

    delget_resp = c.get_tenant(tenant_id=data['id'])
    self.assertEquals(delget_resp.body, '')

    delgetname_resp = c.get_tenant_by_name(tenant_name=update_data['name'])
    self.assertEquals(delgetname_resp.body, '')
    # TODO(termie): we should probably return not founds instead of None
    #self.assertEquals(delget_resp.status, '404 Not Found')

  def test_crud_extras(self):
    token_id = self.options['admin_token']
    user_id = 'foo'
    tenant_id = 'bar'
    c = client.TestClient(self.app, token=token_id)
    extras_ref = dict(baz='qaz')
    resp = c.create_extras(user_id=user_id, tenant_id=tenant_id, **extras_ref)
    data = json.loads(resp.body)
    self.assertEquals(data['baz'], 'qaz')

    get_resp = c.get_extras(user_id=user_id, tenant_id=tenant_id)
    get_data = json.loads(get_resp.body)

    self.assertDictEquals(data, get_data)

    update_resp = c.update_extras(user_id=user_id,
                                  tenant_id=tenant_id,
                                  baz='WAZ')
    update_data = json.loads(update_resp.body)

    self.assertEquals('WAZ', update_data['baz'])

    del_resp = c.delete_extras(user_id=user_id, tenant_id=tenant_id)
    self.assertEquals(del_resp.body, '')

    delget_resp = c.get_extras(user_id=user_id, tenant_id=tenant_id)
    self.assertEquals(delget_resp.body, '')
    # TODO(termie): we should probably return not founds instead of None
    #self.assertEquals(delget_resp.status, '404 Not Found')
