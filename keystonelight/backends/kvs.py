
class DictKvs(dict):
  def set(self, key, value):
    self[key] = value

INMEMDB = DictKvs()

class KvsIdentity(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    self.db = db

  # Public Interface
  def tenants_for_token(self, token_id):
    token = self.db.get('token-%s' % token_id)
    user = self.db.get('user-%s' % token['user'])
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

  def _create_token(self, id, token):
    self.db.set('token-%s' % id, token)
    return token
