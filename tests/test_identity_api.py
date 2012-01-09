import json

from keystone import client
from keystone import config
from keystone import models
from keystone import test

import default_fixtures


CONF = config.CONF


class IdentityApi(test.TestCase):
  def setUp(self):
    super(IdentityApi, self).setUp()
    CONF(config_files=['default.conf'])
    self.app = self.loadapp('default')

    self.load_backends()
    self.load_fixtures(default_fixtures)

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
    self.assertDictEquals(self.metadata_foobar, data['metadata'])

  def test_authenticate_no_tenant(self):
    c = client.TestClient(self.app)
    post_data = {'user_id': self.user_foo['id'],
                 'password': self.user_foo['password']}
    resp = c.authenticate(**post_data)
    data = json.loads(resp.body)
    self.assertEquals(self.user_foo['id'], data['user']['id'])
    self.assertEquals(None, data['tenant'])
    self.assertEquals({}, data['metadata'])

  def test_get_tenants(self):
    token = self._login()
    c = client.TestClient(self.app, token['id'])
    resp = c.get_tenants(user_id=self.user_foo['id'])
    data = json.loads(resp.body)
    self.assertDictEquals(self.tenant_bar, data[0])

  def test_crud_user(self):
    token_id = CONF.admin_token
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
    token_id = CONF.admin_token
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

  def test_crud_metadata(self):
    token_id = CONF.admin_token
    user_id = 'foo'
    tenant_id = 'bar'
    c = client.TestClient(self.app, token=token_id)
    metadata_ref = dict(baz='qaz')
    resp = c.create_metadata(user_id=user_id, tenant_id=tenant_id, **metadata_ref)
    data = json.loads(resp.body)
    self.assertEquals(data['baz'], 'qaz')

    get_resp = c.get_metadata(user_id=user_id, tenant_id=tenant_id)
    get_data = json.loads(get_resp.body)

    self.assertDictEquals(data, get_data)

    update_resp = c.update_metadata(user_id=user_id,
                                  tenant_id=tenant_id,
                                  baz='WAZ')
    update_data = json.loads(update_resp.body)

    self.assertEquals('WAZ', update_data['baz'])

    del_resp = c.delete_metadata(user_id=user_id, tenant_id=tenant_id)
    self.assertEquals(del_resp.body, '')

    delget_resp = c.get_metadata(user_id=user_id, tenant_id=tenant_id)
    self.assertEquals(delget_resp.body, '')
    # TODO(termie): we should probably return not founds instead of None
    #self.assertEquals(delget_resp.status, '404 Not Found')
