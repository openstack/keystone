import json

import sqlalchemy as sql
from sqlalchemy import types as sql_types
from sqlalchemy.ext import declarative

from keystonelight import models


Base = declarative_base()


class JsonBlob(sql_types.TypeDecorator):
  impl = sql.Text

  def process_bind_param(self, value, dialect):
    return json.dumps(value)

  def process_result_value(self, value, dialect):
    return json.loads(value)


class DictBase(Base):
  def __setitem__(self, key, value):
    setattr(self, key, value)

  def __getitem__(self, key):
    return getattr(self, key)

  def get(self, key, default=None):
    return getattr(self, key, default)

  def __iter__(self):
    self._i = iter(object_mapper(self).columns)
    return self

  def next(self):
    n = self._i.next().name
    return n, getattr(self, n)

  def update(self, values):
    """Make the model object behave like a dict."""
    for k, v in values.iteritems():
      setattr(self, k, v)

  def iteritems(self):
    """Make the model object behave like a dict.

    Includes attributes from joins.

    """
    local = dict(self)
    joined = dict([(k, v) for k, v in self.__dict__.iteritems()
                   if not k[0] == '_'])
    local.update(joined)
    return local.iteritems()


class User(Base):
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64), unique=True)


class Tenant(Base):
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64), unique=True)


class Role(Base):
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64))


class Extras(Base):
  __table_args__ = (
      sql.Index('idx_extras_usertenant', 'user', 'tenant'),
      )

  user = sql.Column(sql.String(64))
  tenant = sql.Column(sql.String(64))
  data = sql.Column(JsonBlob())


class Token(Base):
  id = sql.Column(sql.String(64), primary_key=True)
  data = sql.Column(JsonBlob())


class SqlIdentity(object):
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
    tenant_ref = self.query(Tenant).filter(Tenant.id == tenant_id)
    return models.Tenant(**tenant_ref)

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


