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
    elif type(db) is type({}):
      db = DictKvs(db)
    self.db = db

  # Public interface
  def authenticate(self, user_id=None, tenant_id=None, password=None):
    """Authenticate based on a user, tenant and password.

    Expects the user object to have a password field and the tenant to be
    in the list of tenants on the user.

    """
    user_ref = self.get_user(user_id)
    tenant_ref = None
    extras_ref = None
    if not user_ref or user_ref.get('password') != password:
      raise AssertionError('Invalid user / password')
    if tenant_id and tenant_id not in user_ref['tenants']:
      raise AssertionError('Invalid tenant')

    tenant_ref = self.get_tenant(tenant_id)
    if tenant_ref:
      extras_ref = self.get_extras(user_id, tenant_id)
    else:
      extras_ref = {}
    return (user_ref, tenant_ref, extras_ref)

  def get_tenant(self, tenant_id):
    tenant_ref = self.db.get('tenant-%s' % tenant_id)
    return tenant_ref

  def get_tenant_by_name(self, tenant_name):
    tenant_ref = self.db.get('tenant_name-%s' % tenant_name)
    return tenant_ref

  def get_user(self, user_id):
    user_ref = self.db.get('user-%s' % user_id)
    return user_ref

  def get_user_by_name(self, user_name):
    user_ref = self.db.get('user_name-%s' % user_name)
    return user_ref

  def get_extras(self, user_id, tenant_id):
    return self.db.get('extras-%s-%s' % (tenant_id, user_id))

  def get_role(self, role_id):
    role_ref = self.db.get('role-%s' % role_id)
    return role_ref

  def list_users(self):
    return self.db.get('user_list', [])

  def list_roles(self):
    return self.db.get('role_list', [])

  # These should probably be part of the high-level API
  def add_user_to_tenant(self, tenant_id, user_id):
    user_ref = self.get_user(user_id)
    tenants = set(user_ref.get('tenants', []))
    tenants.add(tenant_id)
    user_ref['tenants'] = list(tenants)
    self.update_user(user_id, user_ref)

  def remove_user_from_tenant(self, tenant_id, user_id):
    user_ref = self.get_user(user_id)
    tenants = set(user_ref.get('tenants', []))
    tenants.remove(tenant_id)
    user_ref['tenants'] = list(tenants)
    self.update_user(user_id, user_ref)

  def get_tenants_for_user(self, user_id):
    user_ref = self.get_user(user_id)
    return user_ref.get('tenants', [])

  def get_roles_for_user_and_tenant(self, user_id, tenant_id):
    extras_ref = self.get_extras(user_id, tenant_id)
    if not extras_ref:
      extras_ref = {}
    return extras_ref.get('roles', [])

  def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
    extras_ref = self.get_extras(user_id, tenant_id)
    if not extras_ref:
      extras_ref = {}
    roles = set(extras_ref.get('roles', []))
    roles.add(role_id)
    extras_ref['roles'] = list(roles)
    self.update_extras(user_id, tenant_id, extras_ref)

  def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
    extras_ref = self.get_extras(user_id, tenant_id)
    if not extras_ref:
      extras_ref = {}
    roles = set(extras_ref.get('roles', []))
    roles.remove(role_id)
    extras_ref['roles'] = list(roles)
    self.update_extras(user_id, tenant_id, extras_ref)



  # CRUD
  def create_user(self, id, user):
    self.db.set('user-%s' % id, user)
    self.db.set('user_name-%s' % user['name'], user)
    user_list = set(self.db.get('user_list', []))
    user_list.add(id)
    self.db.set('user_list', list(user_list))
    return user

  def update_user(self, id, user):
    # get the old name and delete it too
    old_user = self.db.get('user-%s' % id)
    self.db.delete('user_name-%s' % old_user['name'])
    self.db.set('user-%s' % id, user)
    self.db.set('user_name-%s' % user['name'], user)
    return user

  def delete_user(self, id):
    old_user = self.db.get('user-%s' % id)
    self.db.delete('user_name-%s' % old_user['name'])
    self.db.delete('user-%s' % id)
    user_list = set(self.db.get('user_list', []))
    user_list.remove(id)
    self.db.set('user_list', list(user_list))
    return None

  def create_tenant(self, id, tenant):
    self.db.set('tenant-%s' % id, tenant)
    self.db.set('tenant_name-%s' % tenant['name'], tenant)
    return tenant

  def update_tenant(self, id, tenant):
    # get the old name and delete it too
    old_tenant = self.db.get('tenant-%s' % id)
    self.db.delete('tenant_name-%s' % old_tenant['name'])
    self.db.set('tenant-%s' % id, tenant)
    self.db.set('tenant_name-%s' % tenant['name'], tenant)
    return tenant

  def delete_tenant(self, id):
    old_tenant = self.db.get('tenant-%s' % id)
    self.db.delete('tenant_name-%s' % old_tenant['name'])
    self.db.delete('tenant-%s' % id)
    return None


  def create_extras(self, user_id, tenant_id, extras):
    self.db.set('extras-%s-%s' % (tenant_id, user_id), extras)
    return extras

  def update_extras(self, user_id, tenant_id, extras):
    self.db.set('extras-%s-%s' % (tenant_id, user_id), extras)
    return extras

  def delete_extras(self, user_id, tenant_id):
    self.db.delete('extras-%s-%s' % (tenant_id, user_id))
    return None

  def create_role(self, id, role):
    self.db.set('role-%s' % id, role)
    role_list = set(self.db.get('role_list', []))
    role_list.add(id)
    self.db.set('role_list', list(role_list))
    return role

  def update_role(self, id, role):
    self.db.set('role-%s' % id, role)
    return role

  def delete_role(self, id):
    self.db.delete('role-%s' % id)
    role_list = set(self.db.get('role_list', []))
    role_list.remove(id)
    self.db.set('role_list', list(role_list))
    return None


class KvsToken(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    elif type(db) is type({}):
      db = DictKvs(db)
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
    elif type(db) is type({}):
      db = DictKvs(db)
    self.db = db

  # Public interface
  def get_catalog(self, user_id, tenant_id, extras=None):
    return self.db.get('catalog-%s-%s' % (tenant_id, user_id))

  # Private interface
  def _create_catalog(self, user_id, tenant_id, data):
    self.db.set('catalog-%s-%s' % (tenant_id, user_id), data)
    return data


class KvsPolicy(object):
  def __init__(self, options, db=None):
    if db is None:
      db = INMEMDB
    elif type(db) is type({}):
      db = DictKvs(db)
    self.db = db

  def can_haz(self, target, action, credentials):
    pass
