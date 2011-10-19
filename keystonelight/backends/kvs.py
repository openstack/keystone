
class DictKvs(dict):
  def set(self, key, value):
    self[key] = value

  def delete(self, key):
    del self[key]

INMEMDB = DictKvs()

class KvsIdentity(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    self.db = db

  # Public interface
  def authenticate(self, user_id=None, tenant_id=None, password=None):
    user_ref = self.get_user(user_id)
    tenant_ref = None
    extras_ref = None
    if user_ref['password'] != password:
      raise AssertionError('Invalid user / password')

    if tenant_id and tenant_id in user_ref['tenants']:
      tenant_ref = self.get_tenant(tenant_id)
      extras_ref = self.get_extras(user_id, tenant_id)
    return (user_ref, tenant_ref, extras_ref)

  def get_tenant(self, tenant_id):
    tenant_ref = self.db.get('tenant-%s' % tenant_id)
    return tenant_ref

  def get_user(self, user_id):
    user_ref = self.db.get('user-%s' % user_id)
    return user_ref

  def get_extras(self, user_id, tenant_id):
    return self.db.get('extras-%s-%s' % (user_id, tenant_id))

  # Private CRUD for testing
  def _create_user(self, id, user):
    self.db.set('user-%s' % id, user)
    return user

  def _create_tenant(self, id, tenant):
    self.db.set('tenant-%s' % id, tenant)
    return tenant

  def _create_extras(self, user_id, tenant_id, extras):
    self.db.set('extras-%s-%s' % (user_id, tenant_id), extras)
    return extras




class KvsToken(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    self.db = db

  # Public interface
  def get_token(self, id):
    return self.db.get('token-%s' % id)

  def create_token(self, id, data):
    self.db.set('token-%s' % id, data)
    return data

  def delete_token(self, id):
    return self.db.delete('token-%s' % id)


class KvsCatalog(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    self.db = db

  # Public interface
  def get_catalog(self, user_id, tenant_id, extras=None):
    return self.db.get('catalog-%s' % tenant_id)

  # Private interface
  def _create_catalog(self, user_id, tenant_id, data):
    self.db.set('catalog-%s' % tenant_id, data)
