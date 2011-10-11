class DictKvs(dict):
  def set(self, key, value):
    return self[key] = value


class KvsIdentity(object):
  def __init__(self, db=None):
    if db is None:
      db = DictKvs()
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

  def _create_tenant(self, id, tenant):
    self.db.set('tenant-%s' % id, tenant)

  def _create_token(self, id, token):
    self.db.set('token-%s' % id, token)
