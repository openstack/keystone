# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from sqlalchemy import Column, String, Integer, ForeignKey, \
    UniqueConstraint, Boolean, DateTime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, object_mapper

# pylint: disable=C0103
Base = declarative_base()


class KeystoneBase(object):
    """Base class for Keystone Models."""
    __api__ = None
    # pylint: disable=C0103
    _i = None

    def save(self, session=None):
        """Save this object."""

        if not session:
            from keystone.backends.sqlalchemy import get_session
            session = get_session()
        session.add(self)
        try:
            session.flush()
        except IntegrityError:
            raise

    def delete(self, session=None):
        """Delete this object."""
        self.save(session=session)

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
        """Make the model object behave like a dict"""
        for k, v in values.iteritems():
            setattr(self, k, v)

    def iteritems(self):
        """Make the model object behave like a dict.

        Includes attributes from joins."""
        local = dict(self)
        joined = dict([(k, v) for k, v in self.__dict__.iteritems()
                      if not k[0] == '_'])
        local.update(joined)
        return local.iteritems()

    def copy(self):
        """Make the model object behave like a dict."""
        return dict(self).copy()


# Define associations first
class UserRoleAssociation(Base, KeystoneBase):
    __tablename__ = 'user_roles'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    role_id = Column(Integer, ForeignKey('roles.id'))
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    __table_args__ = (UniqueConstraint("user_id", "role_id", "tenant_id"), {})

    user = relationship('User')
    role = relationship('Role')


class Endpoints(Base, KeystoneBase):
    __tablename__ = 'endpoints'
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer)
    endpoint_template_id = Column(Integer, ForeignKey('endpoint_templates.id'))
    __table_args__ = (
        UniqueConstraint("endpoint_template_id", "tenant_id"), {})


# Define objects
class Role(Base, KeystoneBase):
    __tablename__ = 'roles'
    __api__ = 'role'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255))
    desc = Column(String(255))
    service_id = Column(Integer, ForeignKey('services.id'))
    __table_args__ = (
        UniqueConstraint("name", "service_id"), {})


class Service(Base, KeystoneBase):
    __tablename__ = 'services'
    __api__ = 'service'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True)
    type = Column(String(255))
    desc = Column(String(255))
    owner_id = Column(Integer, ForeignKey('users.id'))


class Tenant(Base, KeystoneBase):
    __tablename__ = 'tenants'
    __api__ = 'tenant'
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), unique=True)
    desc = Column(String(255))
    enabled = Column(Boolean)


class User(Base, KeystoneBase):
    __tablename__ = 'users'
    __api__ = 'user'
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), unique=True)
    password = Column(String(255))
    email = Column(String(255))
    enabled = Column(Boolean)
    tenant_id = Column(Integer, ForeignKey('tenants.id'))
    roles = relationship(UserRoleAssociation, cascade="all")
    credentials = relationship('Credentials', backref='user', cascade="all")


class Credentials(Base, KeystoneBase):
    __tablename__ = 'credentials'
    __api__ = 'credentials'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=True)
    type = Column(String(20))  # ('Password','APIKey','EC2')
    key = Column(String(255))
    secret = Column(String(255))


class Token(Base, KeystoneBase):
    __tablename__ = 'tokens'
    __api__ = 'token'
    id = Column(String(255), primary_key=True, unique=True)
    user_id = Column(Integer)
    tenant_id = Column(Integer)
    expires = Column(DateTime)


class EndpointTemplates(Base, KeystoneBase):
    __tablename__ = 'endpoint_templates'
    __api__ = 'endpoint_template'
    id = Column(Integer, primary_key=True)
    region = Column(String(255))
    service_id = Column(Integer, ForeignKey('services.id'))
    public_url = Column(String(2000))
    admin_url = Column(String(2000))
    internal_url = Column(String(2000))
    enabled = Column(Boolean)
    is_global = Column(Boolean)
    version_id = Column(String(20))
    version_list = Column(String(2000))
    version_info = Column(String(500))
