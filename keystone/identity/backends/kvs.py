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

from keystone import clean
from keystone import exception
from keystone import identity
from keystone.common import kvs
from keystone.common import utils


def _filter_user(user_ref):
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
    return user_ref


def _ensure_hashed_password(user_ref):
    pw = user_ref.get('password', None)
    if pw is not None:
        user_ref['password'] = utils.hash_password(pw)
    return user_ref


class Identity(kvs.Base, identity.Driver):
    # Public interface
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.

        """
        user_ref = self._get_user(user_id)
        tenant_ref = None
        metadata_ref = None
        if (not user_ref
            or not utils.check_password(password, user_ref.get('password'))):
            raise AssertionError('Invalid user / password')

        tenants = self.get_tenants_for_user(user_id)
        if tenant_id and tenant_id not in tenants:
            raise AssertionError('Invalid tenant')

        tenant_ref = self.get_tenant(tenant_id)
        if tenant_ref:
            metadata_ref = self.get_metadata(user_id, tenant_id)
        else:
            metadata_ref = {}
        return (_filter_user(user_ref), tenant_ref, metadata_ref)

    def get_tenant(self, tenant_id):
        tenant_ref = self.db.get('tenant-%s' % tenant_id)
        return tenant_ref

    def get_tenants(self):
        tenant_keys = filter(lambda x: x.startswith("tenant-"), self.db.keys())
        return [self.db.get(key) for key in tenant_keys]

    def get_tenant_by_name(self, tenant_name):
        tenant_ref = self.db.get('tenant_name-%s' % tenant_name)
        return tenant_ref

    def get_tenant_users(self, tenant_id):
        user_keys = filter(lambda x: x.startswith("user-"), self.db.keys())
        user_refs = [self.db.get(key) for key in user_keys]
        return filter(lambda x: tenant_id in x['tenants'], user_refs)

    def _get_user(self, user_id):
        user_ref = self.db.get('user-%s' % user_id)
        return user_ref

    def _get_user_by_name(self, user_name):
        user_ref = self.db.get('user_name-%s' % user_name)
        return user_ref

    def get_user(self, user_id):
        return _filter_user(self._get_user(user_id))

    def get_user_by_name(self, user_name):
        return _filter_user(self._get_user_by_name(user_name))

    def get_metadata(self, user_id, tenant_id):
        return self.db.get('metadata-%s-%s' % (tenant_id, user_id)) or {}

    def get_role(self, role_id):
        return self.db.get('role-%s' % role_id)

    def list_users(self):
        user_ids = self.db.get('user_list', [])
        return [self.get_user(x) for x in user_ids]

    def list_roles(self):
        role_ids = self.db.get('role_list', [])
        return [self.get_role(x) for x in role_ids]

    # These should probably be part of the high-level API
    def add_user_to_tenant(self, tenant_id, user_id):
        user_ref = self._get_user(user_id)
        tenants = set(user_ref.get('tenants', []))
        tenants.add(tenant_id)
        self.update_user(user_id, {'tenants': list(tenants)})

    def remove_user_from_tenant(self, tenant_id, user_id):
        user_ref = self._get_user(user_id)
        tenants = set(user_ref.get('tenants', []))
        tenants.remove(tenant_id)
        self.update_user(user_id, {'tenants': list(tenants)})

    def get_tenants_for_user(self, user_id):
        user_ref = self._get_user(user_id)
        return user_ref.get('tenants', [])

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        return metadata_ref.get('roles', [])

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        roles = set(metadata_ref.get('roles', []))
        roles.add(role_id)
        metadata_ref['roles'] = list(roles)
        self.update_metadata(user_id, tenant_id, metadata_ref)

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        roles = set(metadata_ref.get('roles', []))
        if role_id not in roles:
            msg = 'Cannot remove role that has not been granted, %s' % role_id
            raise exception.RoleNotFound(message=msg)

        roles.remove(role_id)
        metadata_ref['roles'] = list(roles)
        self.update_metadata(user_id, tenant_id, metadata_ref)

    # CRUD
    def create_user(self, user_id, user):
        if self.get_user(user_id):
            msg = 'Duplicate ID, %s.' % user_id
            raise exception.Conflict(type='user', details=msg)
        if self.get_user_by_name(user['name']):
            msg = 'Duplicate name, %s.' % user['name']
            raise exception.Conflict(type='user', details=msg)
        user = _ensure_hashed_password(user)
        self.db.set('user-%s' % user_id, user)
        self.db.set('user_name-%s' % user['name'], user)
        user_list = set(self.db.get('user_list', []))
        user_list.add(user_id)
        self.db.set('user_list', list(user_list))
        return user

    def update_user(self, user_id, user):
        if 'name' in user:
            existing = self.db.get('user_name-%s' % user['name'])
            if existing and user_id != existing['id']:
                msg = 'Duplicate name, %s.' % user['name']
                raise exception.Conflict(type='user', details=msg)
        # get the old name and delete it too
        old_user = self.db.get('user-%s' % user_id)
        new_user = old_user.copy()
        user = _ensure_hashed_password(user)
        new_user.update(user)
        new_user['id'] = user_id
        self.db.delete('user_name-%s' % old_user['name'])
        self.db.set('user-%s' % user_id, new_user)
        self.db.set('user_name-%s' % new_user['name'], new_user)
        return new_user

    def delete_user(self, user_id):
        old_user = self.db.get('user-%s' % user_id)
        self.db.delete('user_name-%s' % old_user['name'])
        self.db.delete('user-%s' % user_id)
        user_list = set(self.db.get('user_list', []))
        user_list.remove(user_id)
        self.db.set('user_list', list(user_list))
        return None

    def create_tenant(self, tenant_id, tenant):
        tenant['name'] = clean.tenant_name(tenant['name'])
        if self.get_tenant(tenant_id):
            msg = 'Duplicate ID, %s.' % tenant_id
            raise exception.Conflict(type='tenant', details=msg)
        if self.get_tenant_by_name(tenant['name']):
            msg = 'Duplicate name, %s.' % tenant['name']
            raise exception.Conflict(type='tenant', details=msg)
        self.db.set('tenant-%s' % tenant_id, tenant)
        self.db.set('tenant_name-%s' % tenant['name'], tenant)
        return tenant

    def update_tenant(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.tenant_name(tenant['name'])
            existing = self.db.get('tenant_name-%s' % tenant['name'])
            if existing and tenant_id != existing['id']:
                msg = 'Duplicate name, %s.' % tenant['name']
                raise exception.Conflict(type='tenant', details=msg)
        # get the old name and delete it too
        old_tenant = self.db.get('tenant-%s' % tenant_id)
        new_tenant = old_tenant.copy()
        new_tenant.update(tenant)
        new_tenant['id'] = tenant_id
        self.db.delete('tenant_name-%s' % old_tenant['name'])
        self.db.set('tenant-%s' % tenant_id, new_tenant)
        self.db.set('tenant_name-%s' % new_tenant['name'], new_tenant)
        return new_tenant

    def delete_tenant(self, tenant_id):
        old_tenant = self.db.get('tenant-%s' % tenant_id)
        self.db.delete('tenant_name-%s' % old_tenant['name'])
        self.db.delete('tenant-%s' % tenant_id)
        return None

    def create_metadata(self, user_id, tenant_id, metadata):
        self.db.set('metadata-%s-%s' % (tenant_id, user_id), metadata)
        return metadata

    def update_metadata(self, user_id, tenant_id, metadata):
        self.db.set('metadata-%s-%s' % (tenant_id, user_id), metadata)
        return metadata

    def delete_metadata(self, user_id, tenant_id):
        self.db.delete('metadata-%s-%s' % (tenant_id, user_id))
        return None

    def create_role(self, role_id, role):
        role_ref = self.get_role(role_id)
        if role_ref:
            msg = 'Duplicate ID, %s.' % role_id
            raise exception.Conflict(type='role', details=msg)
        role_refs = self.list_roles()
        for role_ref in role_refs:
            if role['name'] == role_ref['name']:
                msg = 'Duplicate name, %s.' % role['name']
                raise exception.Conflict(type='role', details=msg)
        self.db.set('role-%s' % role_id, role)
        role_list = set(self.db.get('role_list', []))
        role_list.add(role_id)
        self.db.set('role_list', list(role_list))
        return role

    def update_role(self, role_id, role):
        role_refs = self.list_roles()
        old_role_ref = None
        for role_ref in role_refs:
            if role['name'] == role_ref['name'] and role_id != role_ref['id']:
                msg = 'Duplicate name, %s.' % role['name']
                raise exception.Conflict(type='role', details=msg)
            if role_id == role_ref['id']:
                old_role_ref = role_ref
        if old_role_ref:
            role['id'] = role_id
            self.db.set('role-%s' % role_id, role)
        else:
            raise exception.RoleNotFound(role_id=role_id)
        return role

    def delete_role(self, role_id):
        self.db.delete('role-%s' % role_id)
        role_list = set(self.db.get('role_list', []))
        role_list.remove(role_id)
        self.db.set('role_list', list(role_list))
        return None
