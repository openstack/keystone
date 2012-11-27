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

import functools

from keystone import clean
from keystone.common import sql
from keystone.common.sql import migration
from keystone.common import utils
from keystone import exception
from keystone import identity


def handle_conflicts(type='object'):
    """Converts IntegrityError into HTTP 409 Conflict."""
    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except sql.IntegrityError as e:
                raise exception.Conflict(type=type, details=str(e.orig))
        return wrapper
    return decorator


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'password', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    password = sql.Column(sql.String(128))
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())


class Credential(sql.ModelBase, sql.DictBase):
    __tablename__ = 'credential'
    attributes = ['id', 'user_id', 'project_id', 'blob', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         nullable=False)
    project_id = sql.Column(sql.String(64), sql.ForeignKey('tenant.id'))
    blob = sql.Column(sql.JsonBlob(), nullable=False)
    type = sql.Column(sql.String(255), nullable=False)
    extra = sql.Column(sql.JsonBlob())


class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())


# TODO(dolph): rename to Project
class Tenant(sql.ModelBase, sql.DictBase):
    # TODO(dolph): rename to project
    __tablename__ = 'tenant'
    attributes = ['id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())


class Role(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role'
    attributes = ['id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())


class UserProjectMetadata(sql.ModelBase, sql.DictBase):
    # TODO(dolph): rename to user_project_metadata (needs a migration)
    __tablename__ = 'metadata'
    user_id = sql.Column(sql.String(64), primary_key=True)
    # TODO(dolph): rename to project_id (needs a migration)
    tenant_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())

    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        Metadata doesn't have non-indexed 'extra' attributes, so the parent
        implementation is not applicable.
        """
        return dict(self.iteritems())


class UserDomainMetadata(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user_domain_metadata'
    user_id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())


# TODO(dolph): ... do we need this table?
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

        if not self._check_password(password, user_ref):
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

        return (identity.filter_user(user_ref), tenant_ref, metadata_ref)

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
        query = session.query(User)
        query = query.join(UserTenantMembership)
        query = query.filter(UserTenantMembership.tenant_id == tenant_id)
        user_refs = query.all()
        return [identity.filter_user(user_ref.to_dict())
                for user_ref in user_refs]

    def get_metadata(self, user_id, tenant_id=None, domain_id=None):
        session = self.get_session()

        if tenant_id:
            q = session.query(UserProjectMetadata)
            q = q.filter_by(tenant_id=tenant_id)
        elif domain_id:
            q = session.query(UserDomainMetadata)
            q = q.filter_by(domain_id=domain_id)
        q = q.filter_by(user_id=user_id)

        try:
            return q.one().data
        except sql.NotFound:
            raise exception.MetadataNotFound()

    def create_grant(self, role_id, user_id, domain_id, project_id):
        self.get_role(role_id)
        self.get_user(user_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_tenant(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id, domain_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True
        roles = set(metadata_ref.get('roles', []))
        roles.add(role_id)
        metadata_ref['roles'] = list(roles)
        if is_new:
            self.create_metadata(user_id, project_id, metadata_ref, domain_id)
        else:
            self.update_metadata(user_id, project_id, metadata_ref, domain_id)

    def list_grants(self, user_id, domain_id, project_id):
        metadata_ref = self.get_metadata(user_id, project_id, domain_id)
        return [self.get_role(x) for x in metadata_ref.get('roles', [])]

    def get_grant(self, role_id, user_id, domain_id, project_id):
        metadata_ref = self.get_metadata(user_id, project_id, domain_id)
        role_ids = set(metadata_ref.get('roles', []))
        if role_id not in role_ids:
            raise exception.RoleNotFound(role_id=role_id)
        return self.get_role(role_id)

    def delete_grant(self, role_id, user_id, domain_id, project_id):
        self.get_role(role_id)
        self.get_user(user_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_tenant(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id, domain_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True
        roles = set(metadata_ref.get('roles', []))
        try:
            roles.remove(role_id)
        except KeyError:
            raise exception.RoleNotFound(role_id=role_id)
        metadata_ref['roles'] = list(roles)
        if is_new:
            self.create_metadata(user_id, project_id, metadata_ref, domain_id)
        else:
            self.update_metadata(user_id, project_id, metadata_ref, domain_id)

    # These should probably be part of the high-level API
    def add_user_to_tenant(self, tenant_id, user_id):
        session = self.get_session()
        self.get_tenant(tenant_id)
        self.get_user(user_id)
        query = session.query(UserTenantMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(tenant_id=tenant_id)
        rv = query.first()
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
        query = session.query(UserTenantMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(tenant_id=tenant_id)
        membership_ref = query.first()
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
        query = session.query(UserTenantMembership)
        query = query.filter_by(user_id=user_id)
        membership_refs = query.all()
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
        session = self.get_session()

        if 'name' in tenant:
            tenant['name'] = clean.tenant_name(tenant['name'])

        try:
            tenant_ref = session.query(Tenant).filter_by(id=tenant_id).one()
        except sql.NotFound:
            raise exception.TenantNotFound(tenant_id=tenant_id)

        with session.begin():
            old_tenant_dict = tenant_ref.to_dict()
            for k in tenant:
                old_tenant_dict[k] = tenant[k]
            new_tenant = Tenant.from_dict(old_tenant_dict)
            tenant_ref.name = new_tenant.name
            tenant_ref.extra = new_tenant.extra
            session.flush()
        return tenant_ref.to_dict(include_extra_dict=True)

    def delete_tenant(self, tenant_id):
        session = self.get_session()

        try:
            tenant_ref = session.query(Tenant).filter_by(id=tenant_id).one()
        except sql.NotFound:
            raise exception.TenantNotFound(tenant_id=tenant_id)

        with session.begin():
            q = session.query(UserTenantMembership)
            q = q.filter_by(tenant_id=tenant_id)
            q.delete(False)

            q = session.query(UserProjectMetadata)
            q = q.filter_by(tenant_id=tenant_id)
            q.delete(False)

            if not session.query(Tenant).filter_by(id=tenant_id).delete(False):
                raise exception.TenantNotFound(tenant_id=tenant_id)

            session.delete(tenant_ref)
            session.flush()

    @handle_conflicts(type='metadata')
    def create_metadata(self, user_id, tenant_id, metadata, domain_id=None):
        session = self.get_session()
        with session.begin():
            if tenant_id:
                session.add(UserProjectMetadata(user_id=user_id,
                                                tenant_id=tenant_id,
                                                data=metadata))
            elif domain_id:
                session.add(UserDomainMetadata(user_id=user_id,
                                               domain_id=domain_id,
                                               data=metadata))
            session.flush()
        return metadata

    @handle_conflicts(type='metadata')
    def update_metadata(self, user_id, tenant_id, metadata, domain_id=None):
        session = self.get_session()
        with session.begin():
            if tenant_id:
                metadata_ref = session.query(UserProjectMetadata)\
                                      .filter_by(user_id=user_id)\
                                      .filter_by(tenant_id=tenant_id)\
                                      .first()
            elif domain_id:
                metadata_ref = session.query(UserDomainMetadata)\
                                      .filter_by(user_id=user_id)\
                                      .filter_by(domain_id=domain_id)\
                                      .first()
            data = metadata_ref.data.copy()
            data.update(metadata)
            metadata_ref.data = data
            session.flush()
        return metadata_ref

    # domain crud

    @handle_conflicts(type='domain')
    def create_domain(self, domain_id, domain):
        session = self.get_session()
        with session.begin():
            ref = Domain.from_dict(domain)
            session.add(ref)
            session.flush()
        return ref.to_dict()

    def list_domains(self):
        session = self.get_session()
        refs = session.query(Domain).all()
        return [ref.to_dict() for ref in refs]

    def get_domain(self, domain_id):
        session = self.get_session()
        ref = session.query(Domain).filter_by(id=domain_id).first()
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref.to_dict()

    @handle_conflicts(type='domain')
    def update_domain(self, domain_id, domain):
        session = self.get_session()
        with session.begin():
            ref = session.query(Domain).filter_by(id=domain_id).first()
            if ref is None:
                raise exception.DomainNotFound(domain_id=domain_id)
            old_dict = ref.to_dict()
            for k in domain:
                old_dict[k] = domain[k]
            new_domain = Domain.from_dict(old_dict)
            for attr in Domain.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_domain, attr))
            ref.extra = new_domain.extra
            session.flush()
        return ref.to_dict()

    def delete_domain(self, domain_id):
        session = self.get_session()
        ref = session.query(Domain).filter_by(id=domain_id).first()
        if not ref:
            raise exception.DomainNotFound(domain_id=domain_id)
        with session.begin():
            session.delete(ref)
            session.flush()

    # project crud

    @handle_conflicts(type='project')
    def create_project(self, project_id, project):
        return self.create_tenant(project_id, project)

    def get_project(self, project_id):
        return self.get_tenant(project_id)

    def list_projects(self):
        return self.get_tenants()

    @handle_conflicts(type='project')
    def update_project(self, project_id, project):
        session = self.get_session()
        with session.begin():
            ref = session.query(Tenant).filter_by(id=project_id).first()
            if ref is None:
                raise exception.TenantNotFound(project_id=project_id)
            old_dict = ref.to_dict()
            for k in project:
                old_dict[k] = project[k]
            new_project = Tenant.from_dict(old_dict)
            for attr in Tenant.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_project, attr))
            ref.extra = new_project.extra
            session.flush()
        return ref.to_dict()

    def delete_project(self, project_id):
        return self.delete_tenant(project_id)

    def list_user_projects(self, user_id):
        session = self.get_session()
        user = self.get_user(user_id)
        metadata_refs = session\
            .query(UserProjectMetadata)\
            .filter_by(user_id=user_id)
        project_ids = set([x.tenant_id for x in metadata_refs
                           if x.data.get('roles')])
        if user.get('project_id'):
            project_ids.add(user['project_id'])

        # FIXME(dolph): this should be removed with proper migrations
        if user.get('tenant_id'):
            project_ids.add(user['tenant_id'])

        return [self.get_project(x) for x in project_ids]

    # user crud

    @handle_conflicts(type='user')
    def create_user(self, user_id, user):
        user['name'] = clean.user_name(user['name'])
        if not 'enabled' in user:
            user['enabled'] = True
        user = utils.hash_user_password(user)
        session = self.get_session()
        with session.begin():
            user_ref = User.from_dict(user)
            session.add(user_ref)
            session.flush()
        return identity.filter_user(user_ref.to_dict())

    def list_users(self):
        session = self.get_session()
        user_refs = session.query(User)
        return [identity.filter_user(x.to_dict()) for x in user_refs]

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
        return identity.filter_user(self._get_user(user_id))

    def get_user_by_name(self, user_name):
        return identity.filter_user(self._get_user_by_name(user_name))

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
            user = utils.hash_user_password(user)
            for k in user:
                old_user_dict[k] = user[k]
            new_user = User.from_dict(old_user_dict)
            for attr in User.attributes:
                if attr != 'id':
                    setattr(user_ref, attr, getattr(new_user, attr))
            user_ref.extra = new_user.extra
            session.flush()
        return identity.filter_user(user_ref.to_dict(include_extra_dict=True))

    def delete_user(self, user_id):
        session = self.get_session()

        try:
            ref = session.query(User).filter_by(id=user_id).one()
        except sql.NotFound:
            raise exception.UserNotFound(user_id=user_id)

        with session.begin():
            q = session.query(UserTenantMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserProjectMetadata)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            if not session.query(User).filter_by(id=user_id).delete(False):
                raise exception.UserNotFound(user_id=user_id)

            session.delete(ref)
            session.flush()

    # credential crud

    @handle_conflicts(type='credential')
    def create_credential(self, credential_id, credential):
        session = self.get_session()
        with session.begin():
            ref = Credential.from_dict(credential)
            session.add(ref)
            session.flush()
        return ref.to_dict()

    def list_credentials(self):
        session = self.get_session()
        refs = session.query(Credential).all()
        return [ref.to_dict() for ref in refs]

    def get_credential(self, credential_id):
        session = self.get_session()
        ref = session.query(Credential).filter_by(id=credential_id).first()
        if ref is None:
            raise exception.CredentialNotFound(credential_id=credential_id)
        return ref.to_dict()

    @handle_conflicts(type='credential')
    def update_credential(self, credential_id, credential):
        session = self.get_session()
        with session.begin():
            ref = session.query(Credential).filter_by(id=credential_id).first()
            if ref is None:
                raise exception.CredentialNotFound(credential_id=credential_id)
            old_dict = ref.to_dict()
            for k in credential:
                old_dict[k] = credential[k]
            new_credential = Credential.from_dict(old_dict)
            for attr in Credential.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_credential, attr))
            ref.extra = new_credential.extra
            session.flush()
        return ref.to_dict()

    def delete_credential(self, credential_id):
        session = self.get_session()

        try:
            ref = session.query(Credential).filter_by(id=credential_id).one()
        except sql.NotFound:
            raise exception.CredentialNotFound(credential_id=credential_id)

        with session.begin():
            session.delete(ref)
            session.flush()

    # role crud

    @handle_conflicts(type='role')
    def create_role(self, role_id, role):
        session = self.get_session()
        with session.begin():
            ref = Role.from_dict(role)
            session.add(ref)
            session.flush()
        return ref.to_dict()

    def list_roles(self):
        session = self.get_session()
        refs = session.query(Role).all()
        return [ref.to_dict() for ref in refs]

    def get_role(self, role_id):
        session = self.get_session()
        ref = session.query(Role).filter_by(id=role_id).first()
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref.to_dict()

    @handle_conflicts(type='role')
    def update_role(self, role_id, role):
        session = self.get_session()
        with session.begin():
            ref = session.query(Role).filter_by(id=role_id).first()
            if ref is None:
                raise exception.RoleNotFound(role_id=role_id)
            old_dict = ref.to_dict()
            for k in role:
                old_dict[k] = role[k]
            new_role = Role.from_dict(old_dict)
            for attr in Role.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_role, attr))
            ref.extra = new_role.extra
            session.flush()
        return ref.to_dict()

    def delete_role(self, role_id):
        session = self.get_session()

        try:
            ref = session.query(Role).filter_by(id=role_id).one()
        except sql.NotFound:
            raise exception.RoleNotFound(role_id=role_id)

        with session.begin():
            for metadata_ref in session.query(UserProjectMetadata):
                metadata = metadata_ref.to_dict()
                try:
                    self.remove_role_from_user_and_tenant(
                        metadata['user_id'], metadata['tenant_id'], role_id)
                except exception.RoleNotFound:
                    pass

            # FIXME(dolph): user-domain metadata needs to be updated

            if not session.query(Role).filter_by(id=role_id).delete():
                raise exception.RoleNotFound(role_id=role_id)

            session.delete(ref)
            session.flush()
