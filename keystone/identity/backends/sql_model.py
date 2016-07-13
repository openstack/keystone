# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime

from oslo_config import cfg
import sqlalchemy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import orm

from keystone.common import sql


CONF = cfg.CONF


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'domain_id', 'password', 'enabled',
                  'default_project_id']
    id = sql.Column(sql.String(64), primary_key=True)
    _enabled = sql.Column('enabled', sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    default_project_id = sql.Column(sql.String(64))
    local_user = orm.relationship('LocalUser', uselist=False,
                                  single_parent=True, lazy='subquery',
                                  cascade='all,delete-orphan', backref='user')
    federated_users = orm.relationship('FederatedUser',
                                       single_parent=True,
                                       lazy='subquery',
                                       cascade='all,delete-orphan',
                                       backref='user')
    nonlocal_users = orm.relationship('NonLocalUser',
                                      single_parent=True,
                                      lazy='subquery',
                                      cascade='all,delete-orphan',
                                      backref='user')
    created_at = sql.Column(sql.DateTime, nullable=True)
    last_active_at = sql.Column(sql.Date, nullable=True)

    # name property
    @hybrid_property
    def name(self):
        if self.local_user:
            return self.local_user.name
        elif self.nonlocal_users:
            return self.nonlocal_users[0].name
        elif self.federated_users:
            return self.federated_users[0].display_name
        else:
            return None

    @name.setter
    def name(self, value):
        if not self.local_user:
            self.local_user = LocalUser()
        self.local_user.name = value

    @name.expression
    def name(cls):
        return LocalUser.name

    # password properties
    @hybrid_property
    def password_ref(self):
        """Return the current password."""
        if self.local_user and self.local_user.passwords:
            return self.local_user.passwords[-1]
        return None

    @hybrid_property
    def password(self):
        if self.password_ref:
            return self.password_ref.password
        return None

    @hybrid_property
    def password_expires_at(self):
        if self.password_ref:
            return self.password_ref.expires_at
        return None

    @password.setter
    def password(self, value):
        now = datetime.datetime.utcnow()
        if not self.local_user:
            self.local_user = LocalUser()
        # set all previous passwords to be expired
        for ref in self.local_user.passwords:
            if not ref.expires_at or ref.expires_at > now:
                ref.expires_at = now
        new_password_ref = Password()
        new_password_ref.password = value
        new_password_ref.created_at = now
        self.local_user.passwords.append(new_password_ref)

    @password.expression
    def password(cls):
        return Password.password

    # domain_id property
    @hybrid_property
    def domain_id(self):
        if self.local_user:
            return self.local_user.domain_id
        elif self.nonlocal_users:
            return self.nonlocal_users[0].domain_id
        else:
            return None

    @domain_id.setter
    def domain_id(self, value):
        if not self.local_user:
            self.local_user = LocalUser()
        self.local_user.domain_id = value

    @domain_id.expression
    def domain_id(cls):
        return LocalUser.domain_id

    # enabled property
    @hybrid_property
    def enabled(self):
        if self._enabled:
            max_days = (
                CONF.security_compliance.disable_user_account_days_inactive)
            last_active = self.last_active_at
            if not last_active and self.created_at:
                last_active = self.created_at.date()
            if max_days and last_active:
                now = datetime.datetime.utcnow().date()
                days_inactive = (now - last_active).days
                if days_inactive >= max_days:
                    self._enabled = False
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if (value and
                CONF.security_compliance.disable_user_account_days_inactive):
            self.last_active_at = datetime.datetime.utcnow().date()
        self._enabled = value

    @enabled.expression
    def enabled(cls):
        return User._enabled

    def to_dict(self, include_extra_dict=False):
        d = super(User, self).to_dict(include_extra_dict=include_extra_dict)
        if 'default_project_id' in d and d['default_project_id'] is None:
            del d['default_project_id']
        return d


class LocalUser(sql.ModelBase, sql.DictBase):
    __tablename__ = 'local_user'
    attributes = ['id', 'user_id', 'domain_id', 'name']
    id = sql.Column(sql.Integer, primary_key=True)
    user_id = sql.Column(sql.String(64), sql.ForeignKey('user.id',
                         ondelete='CASCADE'), unique=True)
    domain_id = sql.Column(sql.String(64), nullable=False)
    name = sql.Column(sql.String(255), nullable=False)
    passwords = orm.relationship('Password',
                                 single_parent=True,
                                 cascade='all,delete-orphan',
                                 lazy='subquery',
                                 backref='local_user',
                                 order_by='Password.created_at')
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Password(sql.ModelBase, sql.DictBase):
    __tablename__ = 'password'
    attributes = ['id', 'local_user_id', 'password', 'created_at',
                  'expires_at']
    id = sql.Column(sql.Integer, primary_key=True)
    local_user_id = sql.Column(sql.Integer, sql.ForeignKey('local_user.id',
                               ondelete='CASCADE'))
    password = sql.Column(sql.String(128), nullable=True)
    # created_at default set here to safe guard in case it gets missed
    created_at = sql.Column(sql.DateTime, nullable=False,
                            default=datetime.datetime.utcnow)
    expires_at = sql.Column(sql.DateTime, nullable=True)


class FederatedUser(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'federated_user'
    attributes = ['id', 'user_id', 'idp_id', 'protocol_id', 'unique_id',
                  'display_name']
    id = sql.Column(sql.Integer, primary_key=True)
    user_id = sql.Column(sql.String(64), sql.ForeignKey('user.id',
                                                        ondelete='CASCADE'))
    idp_id = sql.Column(sql.String(64), sql.ForeignKey('identity_provider.id',
                                                       ondelete='CASCADE'))
    protocol_id = sql.Column(sql.String(64), nullable=False)
    unique_id = sql.Column(sql.String(255), nullable=False)
    display_name = sql.Column(sql.String(255), nullable=True)
    __table_args__ = (
        sql.UniqueConstraint('idp_id', 'protocol_id', 'unique_id'),
        sqlalchemy.ForeignKeyConstraint(['protocol_id', 'idp_id'],
                                        ['federation_protocol.id',
                                         'federation_protocol.idp_id'])
    )


class NonLocalUser(sql.ModelBase, sql.ModelDictMixin):
    """SQL data model for nonlocal users (LDAP and custom)."""

    __tablename__ = 'nonlocal_user'
    attributes = ['domain_id', 'name', 'user_id']
    domain_id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), primary_key=True)
    user_id = sql.Column(sql.String(64), sql.ForeignKey('user.id',
                                                        ondelete='CASCADE'))


class Group(sql.ModelBase, sql.DictBase):
    __tablename__ = 'group'
    attributes = ['id', 'name', 'domain_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'),)


class UserGroupMembership(sql.ModelBase, sql.DictBase):
    """Group membership join table."""

    __tablename__ = 'user_group_membership'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    group_id = sql.Column(sql.String(64),
                          sql.ForeignKey('group.id'),
                          primary_key=True)
