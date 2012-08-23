# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import copy
import functools

from keystone import clean
from keystone.common import sql
from keystone.common.sql import migration
from keystone.common import utils
from keystone import exception
from keystone import identity


def _filter_user(user_ref):
    if user_ref:
        user_ref.pop('password', None)
    return user_ref


def _ensure_hashed_password(user_ref):
    pw = user_ref.get('password', None)
    if pw is not None:
        user_ref['password'] = utils.hash_password(pw)
    return user_ref


def handle_conflicts(type='object'):
    """Converts IntegrityError into HTTP 409 Conflict."""
    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except sql.IntegrityError as e:
                raise exception.Conflict(type=type, details=e.message)
        return wrapper
    return decorator


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    #password = sql.Column(sql.String(64))
    extra = sql.Column(sql.JsonBlob())

    @classmethod
    def from_dict(cls, user_dict):
        # shove any non-indexed properties into extra
        extra = {}
        for k, v in user_dict.copy().iteritems():
            # TODO(termie): infer this somehow
            if k not in ['id', 'name', 'extra']:
                extra[k] = user_dict.pop(k)

        user_dict['extra'] = extra
        return cls(**user_dict)

    def to_dict(self):
        extra_copy = self.extra.copy()
        extra_copy['id'] = self.id
        extra_copy['name'] = self.name
        return extra_copy


class Tenant(sql.ModelBase, sql.DictBase):
    __tablename__ = 'tenant'
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())

    @classmethod
    def from_dict(cls, tenant_dict):
        # shove any non-indexed properties into extra
        extra = {}
        for k, v in tenant_dict.copy().iteritems():
            # TODO(termie): infer this somehow
            if k not in ['id', 'name', 'extra']:
                extra[k] = tenant_dict.pop(k)

        tenant_dict['extra'] = extra
        return cls(**tenant_dict)

    def to_dict(self):
        extra_copy = copy.deepcopy(self.extra)
        extra_copy['id'] = self.id
        extra_copy['name'] = self.name
        return extra_copy


class Role(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role'
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)


class Metadata(sql.ModelBase, sql.DictBase):
    __tablename__ = 'metadata'
    #__table_args__ = (
    #    sql.Index('idx_metadata_usertenant', 'user', 'tenant'),
    #    )

    user_id = sql.Column(sql.String(64), primary_key=True)
    tenant_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())


class UserTenantMembership(sql.ModelBase, sql.DictBase):
    """Tenant membership join table."""
    __tablename__ = 'user_tenant_membership'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    tenant_id = sql.Column(sql.String(64),
                           sql.ForeignKey('tenant.id'),
                           primary_key=True)


class Identity(sql.Base, identity.Driver):
    # Internal interface to manage the database
    def db_sync(self):
        migration.db_sync()

    def _check_password(self, password, user_ref):
        """Check the specified password against the data store.

        This is modeled on ldap/core.py.  The idea is to make it easier to
        subclass Identity so that you can still use it to store all the data,
        but use some other means to check the password.
        Note that we'll pass in the entire user_ref in case the subclass
        needs things like user_ref.get('name')
        For further justification, please see the follow up suggestion at
        https://blueprints.launchpad.net/keystone/+spec/sql-identiy-pam

        """
        return utils.check_password(password, user_ref.get('password'))

    # Identity interface
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.

        """
        user_ref = None
        tenant_ref = None
        metadata_ref = {}

        try:
            user_ref = self._get_user(user_id)
        except exception.UserNotFound:
            raise AssertionError('Invalid user / password')

        if not utils.check_password(password, user_ref.get('password')):
            raise AssertionError('Invalid user / password')

        if tenant_id is not None:
            if tenant_id not in self.get_tenants_for_user(user_id):
                raise AssertionError('Invalid tenant')

            try:
                tenant_ref = self.get_tenant(tenant_id)
                metadata_ref = self.get_metadata(user_id, tenant_id)
            except exception.TenantNotFound:
                tenant_ref = None
                metadata_ref = {}
            except exception.MetadataNotFound:
                metadata_ref = {}

        return (_filter_user(user_ref), tenant_ref, metadata_ref)

    def get_tenant(self, tenant_id):
        session = self.get_session()
        tenant_ref = session.query(Tenant).filter_by(id=tenant_id).first()
        if tenant_ref is None:
            raise exception.TenantNotFound(tenant_id=tenant_id)
        return tenant_ref.to_dict()

    def get_tenant_by_name(self, tenant_name):
        session = self.get_session()
        tenant_ref = session.query(Tenant).filter_by(name=tenant_name).first()
        if not tenant_ref:
            raise exception.TenantNotFound(tenant_id=tenant_name)
        return tenant_ref.to_dict()

    def get_tenant_users(self, tenant_id):
        session = self.get_session()
        self.get_tenant(tenant_id)
        user_refs = session.query(User)\
            .join(UserTenantMembership)\
            .filter(UserTenantMembership.tenant_id ==
                    tenant_id)\
            .all()
        return [_filter_user(user_ref.to_dict()) for user_ref in user_refs]

    def _get_user(self, user_id):
        session = self.get_session()
        user_ref = session.query(User).filter_by(id=user_id).first()
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)
        return user_ref.to_dict()

    def _get_user_by_name(self, user_name):
        session = self.get_session()
        user_ref = session.query(User).filter_by(name=user_name).first()
        if not user_ref:
            raise exception.UserNotFound(user_id=user_name)
        return user_ref.to_dict()

    def get_user(self, user_id):
        return _filter_user(self._get_user(user_id))

    def get_user_by_name(self, user_name):
        return _filter_user(self._get_user_by_name(user_name))

    def get_metadata(self, user_id, tenant_id):
        session = self.get_session()
        metadata_ref = session.query(Metadata)\
                              .filter_by(user_id=user_id)\
                              .filter_by(tenant_id=tenant_id)\
                              .first()
        if metadata_ref is None:
            raise exception.MetadataNotFound()
        return metadata_ref.data

    def get_role(self, role_id):
        session = self.get_session()
        role_ref = session.query(Role).filter_by(id=role_id).first()
        if role_ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return role_ref

    def list_users(self):
        session = self.get_session()
        user_refs = session.query(User)
        return [_filter_user(x.to_dict()) for x in user_refs]

    def list_roles(self):
        session = self.get_session()
        role_refs = session.query(Role)
        return list(role_refs)

    # These should probably be part of the high-level API
    def add_user_to_tenant(self, tenant_id, user_id):
        session = self.get_session()
        self.get_tenant(tenant_id)
        self.get_user(user_id)
        q = session.query(UserTenantMembership)\
                   .filter_by(user_id=user_id)\
                   .filter_by(tenant_id=tenant_id)
        rv = q.first()
        if rv:
            return

        with session.begin():
            session.add(UserTenantMembership(user_id=user_id,
                                             tenant_id=tenant_id))
            session.flush()

    def remove_user_from_tenant(self, tenant_id, user_id):
        session = self.get_session()
        self.get_tenant(tenant_id)
        self.get_user(user_id)
        membership_ref = session.query(UserTenantMembership)\
                                .filter_by(user_id=user_id)\
                                .filter_by(tenant_id=tenant_id)\
                                .first()
        if membership_ref is None:
            raise exception.NotFound('User not found in tenant')
        with session.begin():
            session.delete(membership_ref)
            session.flush()

    def get_tenants(self):
        session = self.get_session()
        tenant_refs = session.query(Tenant).all()
        return [tenant_ref.to_dict() for tenant_ref in tenant_refs]

    def get_tenants_for_user(self, user_id):
        session = self.get_session()
        self.get_user(user_id)
        membership_refs = session.query(UserTenantMembership)\
                                 .filter_by(user_id=user_id)\
                                 .all()
        return [x.tenant_id for x in membership_refs]

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        try:
            metadata_ref = self.get_metadata(user_id, tenant_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        return metadata_ref.get('roles', [])

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        self.get_role(role_id)
        try:
            metadata_ref = self.get_metadata(user_id, tenant_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True
        roles = set(metadata_ref.get('roles', []))
        if role_id in roles:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, tenant_id))
            raise exception.Conflict(type='role grant', details=msg)
        roles.add(role_id)
        metadata_ref['roles'] = list(roles)
        if is_new:
            self.create_metadata(user_id, tenant_id, metadata_ref)
        else:
            self.update_metadata(user_id, tenant_id, metadata_ref)

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        try:
            metadata_ref = self.get_metadata(user_id, tenant_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True
        roles = set(metadata_ref.get('roles', []))
        if role_id not in roles:
            msg = 'Cannot remove role that has not been granted, %s' % role_id
            raise exception.RoleNotFound(message=msg)

        roles.remove(role_id)
        metadata_ref['roles'] = list(roles)
        if is_new:
            self.create_metadata(user_id, tenant_id, metadata_ref)
        else:
            self.update_metadata(user_id, tenant_id, metadata_ref)

    # CRUD
    @handle_conflicts(type='user')
    def create_user(self, user_id, user):
        user['name'] = clean.user_name(user['name'])
        user = _ensure_hashed_password(user)
        session = self.get_session()
        with session.begin():
            user_ref = User.from_dict(user)
            session.add(user_ref)
            session.flush()
        return user_ref.to_dict()

    @handle_conflicts(type='user')
    def update_user(self, user_id, user):
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        session = self.get_session()
        if 'id' in user and user_id != user['id']:
            raise exception.ValidationError('Cannot change user ID')
        with session.begin():
            user_ref = session.query(User).filter_by(id=user_id).first()
            if user_ref is None:
                raise exception.UserNotFound(user_id=user_id)
            old_user_dict = user_ref.to_dict()
            user = _ensure_hashed_password(user)
            for k in user:
                old_user_dict[k] = user[k]
            new_user = User.from_dict(old_user_dict)

            user_ref.name = new_user.name
            user_ref.extra = new_user.extra
            session.flush()
        return user_ref

    def delete_user(self, user_id):
        session = self.get_session()
        with session.begin():
            session.query(UserTenantMembership)\
                   .filter_by(user_id=user_id).delete(False)
            session.query(Metadata)\
                   .filter_by(user_id=user_id).delete(False)
            if not session.query(User).filter_by(id=user_id).delete(False):
                raise exception.UserNotFound(user_id=user_id)

    @handle_conflicts(type='tenant')
    def create_tenant(self, tenant_id, tenant):
        tenant['name'] = clean.tenant_name(tenant['name'])
        session = self.get_session()
        with session.begin():
            tenant_ref = Tenant.from_dict(tenant)
            session.add(tenant_ref)
            session.flush()
        return tenant_ref.to_dict()

    @handle_conflicts(type='tenant')
    def update_tenant(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.tenant_name(tenant['name'])
        session = self.get_session()
        with session.begin():
            tenant_ref = session.query(Tenant).filter_by(id=tenant_id).first()
            if tenant_ref is None:
                raise exception.TenantNotFound(tenant_id=tenant_id)
            old_tenant_dict = tenant_ref.to_dict()
            for k in tenant:
                old_tenant_dict[k] = tenant[k]
            new_tenant = Tenant.from_dict(old_tenant_dict)

            tenant_ref.name = new_tenant.name
            tenant_ref.extra = new_tenant.extra
            session.flush()
        return tenant_ref

    def delete_tenant(self, tenant_id):
        session = self.get_session()
        with session.begin():
            session.query(UserTenantMembership)\
                   .filter_by(tenant_id=tenant_id).delete(False)
            session.query(Metadata)\
                   .filter_by(tenant_id=tenant_id).delete(False)
            if not session.query(Tenant).filter_by(id=tenant_id).delete(False):
                raise exception.TenantNotFound(tenant_id=tenant_id)

    @handle_conflicts(type='metadata')
    def create_metadata(self, user_id, tenant_id, metadata):
        session = self.get_session()
        with session.begin():
            session.add(Metadata(user_id=user_id,
                                 tenant_id=tenant_id,
                                 data=metadata))
            session.flush()
        return metadata

    @handle_conflicts(type='metadata')
    def update_metadata(self, user_id, tenant_id, metadata):
        session = self.get_session()
        with session.begin():
            metadata_ref = session.query(Metadata)\
                                  .filter_by(user_id=user_id)\
                                  .filter_by(tenant_id=tenant_id)\
                                  .first()
            data = metadata_ref.data.copy()
            for k in metadata:
                data[k] = metadata[k]
            metadata_ref.data = data
            session.flush()
        return metadata_ref

    def delete_metadata(self, user_id, tenant_id):
        self.db.delete('metadata-%s-%s' % (tenant_id, user_id))
        return None

    @handle_conflicts(type='role')
    def create_role(self, role_id, role):
        session = self.get_session()
        with session.begin():
            session.add(Role(**role))
            session.flush()
        return role

    @handle_conflicts(type='role')
    def update_role(self, role_id, role):
        session = self.get_session()
        with session.begin():
            role_ref = session.query(Role).filter_by(id=role_id).first()
            if role_ref is None:
                raise exception.RoleNotFound(role_id=role_id)
            for k in role:
                role_ref[k] = role[k]
            session.flush()
        return role_ref

    def delete_role(self, role_id):
        session = self.get_session()
        with session.begin():
            if not session.query(Role).filter_by(id=role_id).delete():
                raise exception.RoleNotFound(role_id=role_id)
            session.flush()
