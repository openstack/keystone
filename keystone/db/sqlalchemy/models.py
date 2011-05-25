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
# Not Yet PEP8 standardized

from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, UniqueConstraint
from sqlalchemy import DateTime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, object_mapper
import api as db_api
Base = declarative_base()


class KeystoneBase(object):
    """Base class for Keystone Models."""

    def save(self, session=None):
        """Save this object."""
        if not session:
            session =  db_api.get_session()
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


# Define associations first
class UserGroupAssociation(Base, KeystoneBase):
    __tablename__ = 'user_group_association'

    user_id = Column(String(255), ForeignKey('users.id'), primary_key=True)
    group_id = Column(String(255), ForeignKey('groups.id'), primary_key=True)


class UserRoleAssociation(Base, KeystoneBase):
    __tablename__ = 'user_roles'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(255), ForeignKey('users.id'))
    role_id = Column(String(255), ForeignKey('roles.id'))
    tenant_id = Column(String(255), ForeignKey('tenants.id'))
    UniqueConstraint('user_id', 'role_id', 'tenant_id', name='user_role_tenant_uniquness')


# Define objects
class Role(Base, KeystoneBase):
    __tablename__ = 'roles'

    id = Column(String(255), primary_key=True, unique=True)
    desc = Column(String(255))


class Tenant(Base, KeystoneBase):
    __tablename__ = 'tenants'

    id = Column(String(255), primary_key=True, unique=True)
    desc = Column(String(255))
    enabled = Column(Integer)
    groups = relationship('Group', backref='tenants')


class User(Base, KeystoneBase):
    __tablename__ = 'users'

    id = Column(String(255), primary_key=True, unique=True)
    password = Column(String(255))
    email = Column(String(255))
    enabled = Column(Integer)
    tenant_id = Column(String(255), ForeignKey('tenants.id'))
    
    groups = relationship(UserGroupAssociation, backref='users')
    roles = relationship(UserRoleAssociation,cascade="all,delete")

class Credentials(Base, KeystoneBase):
    __tablename__ = 'credentials'

    user_id = Column(String(255), ForeignKey('users.id'), primary_key=True)
    type = Column(String(20)) #('Password','APIKey','EC2')
    key = Column(String(255))
    secret = Column(String(255))


class Group(Base, KeystoneBase):
    __tablename__ = 'groups'

    id = Column(String(255), primary_key=True, unique=True)
    desc = Column(String(255))
    tenant_id = Column(String(255), ForeignKey('tenants.id'))


class Token(Base, KeystoneBase):
    __tablename__ = 'token'

    token_id = Column(String(255), primary_key=True, unique=True)
    user_id = Column(String(255))
    tenant_id = Column(String(255))
    expires = Column(DateTime)


class Endpoints(Base, KeystoneBase):
    __tablename__ = 'endpoints'

    id = Column(String(255), primary_key=True, unique=True)
    service = Column(String(255))
    desc = Column(String(255))
