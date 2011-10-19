
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
  def tenants_for_user(self, user_id):
    user = self.db.get('user-%s' % user_id)
    o = []
    for tenant_id in user['tenants']:
      o.append(self.db.get('tenant-%s' % tenant_id))

    return o

  # Private CRUD for testing
  def _create_user(self, id, user):
    self.db.set('user-%s' % id, user)
    return user

  def _create_tenant(self, id, tenant):
    self.db.set('tenant-%s' % id, tenant)
    return tenant


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
  def get_catalog(self, user, tenant, extras=None):
    return self.db.get('catalog-%s' % tenant['id'])
