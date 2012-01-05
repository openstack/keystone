"""SQL backends for the various services."""

import json

import eventlet.db_pool
import sqlalchemy as sql
from sqlalchemy import types as sql_types
from sqlalchemy.ext import declarative
import sqlalchemy.orm
import sqlalchemy.pool
import sqlalchemy.engine.url

from keystonelight import models


Base = declarative.declarative_base()


class JsonBlob(sql_types.TypeDecorator):
  impl = sql.Text

  def process_bind_param(self, value, dialect):
    return json.dumps(value)

  def process_result_value(self, value, dialect):
    return json.loads(value)


class DictBase(object):
  def to_dict(self):
    return dict(self.iteritems())

  def __setitem__(self, key, value):
    setattr(self, key, value)

  def __getitem__(self, key):
    return getattr(self, key)

  def get(self, key, default=None):
    return getattr(self, key, default)

  def __iter__(self):
    self._i = iter(sqlalchemy.orm.object_mapper(self).columns)
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


class User(Base, DictBase):
  __tablename__ = 'user'
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64), unique=True)
  password = sql.Column(sql.String(64))


class Tenant(Base, DictBase):
  __tablename__ = 'tenant'
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64), unique=True)


class Role(Base, DictBase):
  __tablename__ = 'role'
  id = sql.Column(sql.String(64), primary_key=True)
  name = sql.Column(sql.String(64))


class Extras(Base, DictBase):
  __tablename__ = 'extras'
  __table_args__ = (
      sql.Index('idx_extras_usertenant', 'user', 'tenant'),
      )

  user = sql.Column(sql.String(64), primary_key=True)
  tenant = sql.Column(sql.String(64), primary_key=True)
  data = sql.Column(JsonBlob())


class Token(Base, DictBase):
  __tablename__ = 'token'
  id = sql.Column(sql.String(64), primary_key=True)
  user = sql.Column(sql.String(64))
  tenant = sql.Column(sql.String(64))
  data = sql.Column(JsonBlob())



class SqlBase(object):
  _MAKER = None
  _ENGINE = None

  def __init__(self, options):
    self.options = options

  def get_session(self, autocommit=True, expire_on_commit=False):
    """Return a SQLAlchemy session."""
    if self._MAKER is None or self._ENGINE is None:
      self._ENGINE = self.get_engine()
      self._MAKER = self.get_maker(self._ENGINE, autocommit, expire_on_commit)

    session = self._MAKER()
    # TODO(termie): we may want to do something similar
    #session.query = nova.exception.wrap_db_error(session.query)
    #session.flush = nova.exception.wrap_db_error(session.flush)
    return session

  def get_engine(self):
    """Return a SQLAlchemy engine."""
    connection_dict = sqlalchemy.engine.url.make_url(
        self.options.get('sql_connection'))

    engine_args = {
        "pool_recycle": self.options.get('sql_idle_timeout'),
        "echo": False,
        }

    if "sqlite" in connection_dict.drivername:
      engine_args["poolclass"] = sqlalchemy.pool.NullPool
    elif MySQLdb and "mysql" in connection_dict.drivername:
      LOG.info(_("Using mysql/eventlet db_pool."))
      # MySQLdb won't accept 'None' in the password field
      password = connection_dict.password or ''
      pool_args = {
          "db": connection_dict.database,
          "passwd": password,
          "host": connection_dict.host,
          "user": connection_dict.username,
          "min_size": self.options.get('sql_min_pool_size'),
          "max_size": self.options.get('sql_max_pool_size'),
          "max_idle": self.options.get('sql_idle_timeout'),
          }
      creator = eventlet.db_pool.ConnectionPool(MySQLdb, **pool_args)
      engine_args["pool_size"] = self.options.get('sql_max_pool_size')
      engine_args["pool_timeout"] = self.options('sql_pool_timeout')
      engine_args["creator"] = creator.create

    return sql.create_engine(self.options.get('sql_connection'),
                             **engine_args)

  def get_maker(self, engine, autocommit=True, expire_on_commit=False):
    """Return a SQLAlchemy sessionmaker using the given engine."""
    return sqlalchemy.orm.sessionmaker(bind=engine,
                                       autocommit=autocommit,
                                       expire_on_commit=expire_on_commit)


class SqlIdentity(SqlBase):
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
    session = self.get_session()
    tenant_ref = session.query(Tenant).filter_by(id=tenant_id).first()
    return tenant_ref

  def get_tenant_by_name(self, tenant_name):
    tenant_ref = self.db.get('tenant_name-%s' % tenant_name)
    return tenant_ref

  def get_user(self, user_id):
    session = self.get_session()
    user_ref = session.query(User).filter_by(id=user_id).first()
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
    session = self.get_session()
    session.add(User(**user))
    session.flush()
    #self.db.set('user-%s' % id, user)
    #self.db.set('user_name-%s' % user['name'], user)
    #user_list = set(self.db.get('user_list', []))
    #user_list.add(id)
    #self.db.set('user_list', list(user_list))
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
    session = self.get_session()
    session.add(Tenant(**tenant))
    #session.commit()
    #self.db.set('tenant-%s' % id, tenant)
    #self.db.set('tenant_name-%s' % tenant['name'], tenant)
    return models.Tenant(**tenant)

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




class SqlToken(SqlBase):
  pass

class SqlCatalog(SqlBase):
  pass
