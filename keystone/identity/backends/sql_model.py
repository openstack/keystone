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

from oslo_log import versionutils
import sqlalchemy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import orm
from sqlalchemy.orm import collections

from keystone.common import resource_options
from keystone.common import sql
import keystone.conf
from keystone.identity.backends import resource_options as iro


CONF = keystone.conf.CONF


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'domain_id', 'password', 'enabled',
                  'default_project_id', 'password_expires_at']
    readonly_attributes = ['id', 'password_expires_at']
    resource_options_registry = iro.USER_OPTIONS_REGISTRY
    id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), nullable=False)
    _enabled = sql.Column('enabled', sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    default_project_id = sql.Column(sql.String(64))
    _resource_option_mapper = orm.relationship(
        'UserOption',
        single_parent=True,
        cascade='all,delete,delete-orphan',
        lazy='subquery',
        backref='user',
        collection_class=collections.attribute_mapped_collection('option_id'))
    local_user = orm.relationship('LocalUser', uselist=False,
                                  single_parent=True, lazy='subquery',
                                  cascade='all,delete-orphan', backref='user')
    federated_users = orm.relationship('FederatedUser',
                                       single_parent=True,
                                       lazy='subquery',
                                       cascade='all,delete-orphan',
                                       backref='user')
    nonlocal_user = orm.relationship('NonLocalUser',
                                     uselist=False,
                                     single_parent=True,
                                     lazy='subquery',
                                     cascade='all,delete-orphan',
                                     backref='user')
    created_at = sql.Column(sql.DateTime, nullable=True)
    last_active_at = sql.Column(sql.Date, nullable=True)
    # unique constraint needed here to support composite fk constraints
    __table_args__ = (sql.UniqueConstraint('id', 'domain_id'), {})

    # NOTE(stevemar): we use a hybrid property here because we leverage the
    # expression method, see `@name.expression` and `LocalUser.name` below.
    @hybrid_property
    def name(self):
        """Return the current user name."""
        if self.local_user:
            return self.local_user.name
        elif self.nonlocal_user:
            return self.nonlocal_user.name
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
    @property
    def password_ref(self):
        """Return the current password ref."""
        if self.local_user and self.local_user.passwords:
            return self.local_user.passwords[-1]
        return None

    # NOTE(stevemar): we use a hybrid property here because we leverage the
    # expression method, see `@password.expression` and `Password.password`
    # below.
    @hybrid_property
    def password(self):
        """Return the current password."""
        if self.password_ref:
            return self.password_ref.password
        return None

    @property
    def password_created_at(self):
        """Return when password was created at."""
        if self.password_ref:
            return self.password_ref.created_at
        return None

    @property
    def password_expires_at(self):
        """Return when password expires at."""
        if self.password_ref:
            return self.password_ref.expires_at
        return None

    @property
    def password_is_expired(self):
        """Return whether password is expired or not."""
        if self.password_expires_at:
            return datetime.datetime.utcnow() >= self.password_expires_at
        return False

    @password.setter
    def password(self, value):
        now = datetime.datetime.utcnow()
        if not self.local_user:
            self.local_user = LocalUser()
        # truncate extra passwords
        if self.local_user.passwords:
            unique_cnt = CONF.security_compliance.unique_last_password_count
            self.local_user.passwords = self.local_user.passwords[-unique_cnt:]
        # set all previous passwords to be expired
        for ref in self.local_user.passwords:
            if not ref.expires_at or ref.expires_at > now:
                ref.expires_at = now
        new_password_ref = Password()
        new_password_ref.password = value
        new_password_ref.created_at = now
        new_password_ref.expires_at = self._get_password_expires_at(now)
        self.local_user.passwords.append(new_password_ref)

    def _get_password_expires_at(self, created_at):
        expires_days = CONF.security_compliance.password_expires_days
        # NOTE(notmorgan): This option is deprecated and subject to removal
        # in a future release.
        ignore_list = CONF.security_compliance.password_expires_ignore_user_ids
        if ignore_list:
            versionutils.deprecated(
                what='[security_compliance]\password_expires_ignore_user_ids',
                as_of=versionutils.deprecated.OCATA,
                remove_in=+1,
                in_favor_of=('Using the `ignore_password_expiry` value set to '
                             '`True` in the `user["options"]` dictionary on '
                             'User creation or update (via API call).'))
        # Get the IGNORE_PASSWORD_EXPIRY_OPT value from the user's
        # option_mapper.

        ignore_pw_expiry = getattr(
            self.get_resource_option(iro.IGNORE_PASSWORD_EXPIRY_OPT.option_id),
            'option_value',
            False)
        if (self.id not in ignore_list) and not ignore_pw_expiry:
            if expires_days:
                expired_date = (created_at +
                                datetime.timedelta(days=expires_days))
                return expired_date.replace(microsecond=0)
        return None

    @password.expression
    def password(cls):
        return Password.password

    # NOTE(stevemar): we use a hybrid property here because we leverage the
    # expression method, see `@enabled.expression` and `User._enabled` below.
    @hybrid_property
    def enabled(self):
        """Return whether user is enabled or not."""
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
        if value and self.local_user:
            self.local_user.failed_auth_count = 0
            self.local_user.failed_auth_at = None
        self._enabled = value

    @enabled.expression
    def enabled(cls):
        return User._enabled

    def get_resource_option(self, option_id):
        if option_id in self._resource_option_mapper.keys():
            return self._resource_option_mapper[option_id]
        return None

    def to_dict(self, include_extra_dict=False):
        d = super(User, self).to_dict(include_extra_dict=include_extra_dict)
        if 'default_project_id' in d and d['default_project_id'] is None:
            del d['default_project_id']
        # NOTE(notmorgan): Eventually it may make sense to drop the empty
        # option dict creation to the superclass (if enough models use it)
        d['options'] = resource_options.ref_mapper_to_dict_options(self)
        return d

    @classmethod
    def from_dict(cls, user_dict):
        """Override from_dict to remove password_expires_at attribute.

        Overriding this method to remove password_expires_at attribute to
        support update_user and unit tests where password_expires_at
        inadvertently gets added by calling to_dict followed by from_dict.

        :param user_dict: User entity dictionary
        :returns User: User object

        """
        new_dict = user_dict.copy()
        resource_options = {}
        options = new_dict.pop('options', {})
        password_expires_at_key = 'password_expires_at'
        if password_expires_at_key in user_dict:
            del new_dict[password_expires_at_key]
        for opt in cls.resource_options_registry.options:
            if opt.option_name in options:
                opt_value = options[opt.option_name]
                # NOTE(notmorgan): None is always a valid type
                if opt_value is not None:
                    opt.validator(opt_value)
                resource_options[opt.option_id] = opt_value
        user_obj = super(User, cls).from_dict(new_dict)
        setattr(user_obj, '_resource_options', resource_options)
        return user_obj


class LocalUser(sql.ModelBase, sql.DictBase):
    __tablename__ = 'local_user'
    attributes = ['id', 'user_id', 'domain_id', 'name']
    id = sql.Column(sql.Integer, primary_key=True)
    user_id = sql.Column(sql.String(64))
    domain_id = sql.Column(sql.String(64), nullable=False)
    name = sql.Column(sql.String(255), nullable=False)
    passwords = orm.relationship('Password',
                                 single_parent=True,
                                 cascade='all,delete-orphan',
                                 lazy='subquery',
                                 backref='local_user',
                                 order_by='Password.created_at')
    failed_auth_count = sql.Column(sql.Integer, nullable=True)
    failed_auth_at = sql.Column(sql.DateTime, nullable=True)
    __table_args__ = (
        sql.UniqueConstraint('user_id'),
        sql.UniqueConstraint('domain_id', 'name'),
        sqlalchemy.ForeignKeyConstraint(['user_id', 'domain_id'],
                                        ['user.id', 'user.domain_id'],
                                        onupdate='CASCADE', ondelete='CASCADE')
    )


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
    self_service = sql.Column(sql.Boolean, default=False, nullable=False,
                              server_default='0')


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
    user_id = sql.Column(sql.String(64))
    __table_args__ = (
        sql.UniqueConstraint('user_id'),
        sqlalchemy.ForeignKeyConstraint(
            ['user_id', 'domain_id'], ['user.id', 'user.domain_id'],
            onupdate='CASCADE', ondelete='CASCADE'),)


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


class UserOption(sql.ModelBase):
    __tablename__ = 'user_option'
    user_id = sql.Column(sql.String(64), sql.ForeignKey('user.id',
                         ondelete='CASCADE'), nullable=False,
                         primary_key=True)
    option_id = sql.Column(sql.String(4), nullable=False,
                           primary_key=True)
    option_value = sql.Column(sql.JsonBlob, nullable=True)

    def __init__(self, option_id, option_value):
        self.option_id = option_id
        self.option_value = option_value
