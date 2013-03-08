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
from keystone import config
from keystone.common import sql
from keystone.common.sql import migration
from keystone.common import utils
from keystone import exception
from keystone import identity


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'domain_id', 'password', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    password = sql.Column(sql.String(128))
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Group(sql.ModelBase, sql.DictBase):
    __tablename__ = 'group'
    attributes = ['id', 'name', 'domain_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Credential(sql.ModelBase, sql.DictBase):
    __tablename__ = 'credential'
    attributes = ['id', 'user_id', 'project_id', 'blob', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         nullable=False)
    project_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    blob = sql.Column(sql.JsonBlob(), nullable=False)
    type = sql.Column(sql.String(255), nullable=False)
    extra = sql.Column(sql.JsonBlob())


class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    enabled = sql.Column(sql.Boolean, default=True)
    extra = sql.Column(sql.JsonBlob())


class Project(sql.ModelBase, sql.DictBase):
    __tablename__ = 'project'
    attributes = ['id', 'name', 'domain_id', 'description', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Role(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role'
    attributes = ['id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), unique=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())


class BaseGrant(sql.DictBase):
    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        Grant tables don't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(self.iteritems())


class UserProjectGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'user_project_metadata'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    project_id = sql.Column(sql.String(64),
                            sql.ForeignKey('project.id'),
                            primary_key=True)
    data = sql.Column(sql.JsonBlob())


class UserDomainGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'user_domain_metadata'
    user_id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())


class GroupProjectGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'group_project_metadata'
    group_id = sql.Column(sql.String(64), primary_key=True)
    project_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())


class GroupDomainGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'group_domain_metadata'
    group_id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), primary_key=True)
    data = sql.Column(sql.JsonBlob())


class UserGroupMembership(sql.ModelBase, sql.DictBase):
    """Group membership join table."""
    __tablename__ = 'user_group_membership'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    group_id = sql.Column(sql.String(64),
                          sql.ForeignKey('group.id'),
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
            # FIXME(gyee): this should really be
            # get_roles_for_user_and_project() after the dusts settle
            if tenant_id not in self.get_projects_for_user(user_id):
                raise AssertionError('Invalid project')
            try:
                tenant_ref = self.get_project(tenant_id)
                metadata_ref = self.get_metadata(user_id, tenant_id)
            except exception.ProjectNotFound:
                tenant_ref = None
                metadata_ref = {}
            except exception.MetadataNotFound:
                metadata_ref = {}
        return (identity.filter_user(user_ref), tenant_ref, metadata_ref)

    def get_project(self, tenant_id):
        session = self.get_session()
        tenant_ref = session.query(Project).filter_by(id=tenant_id).first()
        if tenant_ref is None:
            raise exception.ProjectNotFound(project_id=tenant_id)
        return tenant_ref.to_dict()

    def get_project_by_name(self, tenant_name, domain_id):
        session = self.get_session()
        query = session.query(Project)
        query = query.filter_by(name=tenant_name)
        query = query.filter_by(domain_id=domain_id)
        try:
            project_ref = query.one()
        except sql.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_name)
        return project_ref.to_dict()

    def get_project_users(self, tenant_id):
        session = self.get_session()
        self.get_project(tenant_id)
        query = session.query(User)
        query = query.join(UserProjectGrant)
        query = query.filter(UserProjectGrant.project_id == tenant_id)
        user_refs = query.all()
        return [identity.filter_user(user_ref.to_dict())
                for user_ref in user_refs]

    def get_metadata(self, user_id=None, tenant_id=None,
                     domain_id=None, group_id=None):
        session = self.get_session()

        if user_id:
            if tenant_id:
                q = session.query(UserProjectGrant)
                q = q.filter_by(project_id=tenant_id)
            elif domain_id:
                q = session.query(UserDomainGrant)
                q = q.filter_by(domain_id=domain_id)
            q = q.filter_by(user_id=user_id)
        elif group_id:
            if tenant_id:
                q = session.query(GroupProjectGrant)
                q = q.filter_by(project_id=tenant_id)
            elif domain_id:
                q = session.query(GroupDomainGrant)
                q = q.filter_by(domain_id=domain_id)
            q = q.filter_by(group_id=group_id)
        try:
            return q.one().data
        except sql.NotFound:
            raise exception.MetadataNotFound()

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):

        self.get_role(role_id)
        if user_id:
            self.get_user(user_id)
        if group_id:
            self.get_group(group_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id,
                                             domain_id, group_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True
        roles = set(metadata_ref.get('roles', []))
        roles.add(role_id)
        metadata_ref['roles'] = list(roles)
        if is_new:
            self.create_metadata(user_id, project_id, metadata_ref,
                                 domain_id, group_id)
        else:
            self.update_metadata(user_id, project_id, metadata_ref,
                                 domain_id, group_id)

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None):
        if user_id:
            self.get_user(user_id)
        if group_id:
            self.get_group(group_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id,
                                             domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        return [self.get_role(x) for x in metadata_ref.get('roles', [])]

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None):
        self.get_role(role_id)
        if user_id:
            self.get_user(user_id)
        if group_id:
            self.get_group(group_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id,
                                             domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        role_ids = set(metadata_ref.get('roles', []))
        if role_id not in role_ids:
            raise exception.RoleNotFound(role_id=role_id)
        return self.get_role(role_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):
        self.get_role(role_id)
        if user_id:
            self.get_user(user_id)
        if group_id:
            self.get_group(group_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self.get_metadata(user_id, project_id,
                                             domain_id, group_id)
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
            self.create_metadata(user_id, project_id, metadata_ref,
                                 domain_id, group_id)
        else:
            self.update_metadata(user_id, project_id, metadata_ref,
                                 domain_id, group_id)

    def list_projects(self):
        session = self.get_session()
        tenant_refs = session.query(Project).all()
        return [tenant_ref.to_dict() for tenant_ref in tenant_refs]

    def get_projects_for_user(self, user_id):
        session = self.get_session()
        self.get_user(user_id)
        query = session.query(UserProjectGrant)
        query = query.filter_by(user_id=user_id)
        membership_refs = query.all()
        return [x.project_id for x in membership_refs]

    def _get_user_group_project_roles(self, metadata_ref, user_id, project_id):
        group_refs = self.list_groups_for_user(user_id=user_id)
        for x in group_refs:
            try:
                metadata_ref.update(
                    self.get_metadata(group_id=x['id'],
                                      tenant_id=project_id))
            except exception.MetadataNotFound:
                # no group grant, skip
                pass

    def _get_user_project_roles(self, metadata_ref, user_id, project_id):
        try:
            metadata_ref.update(self.get_metadata(user_id, project_id))
        except exception.MetadataNotFound:
            pass

    def _get_user_group_domain_roles(self, metadata_ref, user_id, domain_id):
        group_refs = self.list_groups_for_user(user_id=user_id)
        for x in group_refs:
            try:
                metadata_ref.update(
                    self.get_metadata(group_id=x['id'],
                                      domain_id=domain_id))
            except exception.MetadataNotFound:
                # no group grant, skip
                pass

    def _get_user_domain_roles(self, metadata_ref, user_id, domain_id):
        try:
            metadata_ref.update(self.get_metadata(user_id,
                                                  domain_id=domain_id))
        except exception.MetadataNotFound:
            pass

    def get_roles_for_user_and_project(self, user_id, tenant_id):
        self.get_user(user_id)
        self.get_project(tenant_id)
        metadata_ref = {}
        self._get_user_project_roles(metadata_ref, user_id, tenant_id)
        self._get_user_group_project_roles(metadata_ref, user_id, tenant_id)
        return list(set(metadata_ref.get('roles', [])))

    def get_roles_for_user_and_domain(self, user_id, domain_id):
        self.get_user(user_id)
        self.get_domain(domain_id)
        metadata_ref = {}
        self._get_user_domain_roles(metadata_ref, user_id, domain_id)
        self._get_user_group_domain_roles(metadata_ref, user_id, domain_id)
        return list(set(metadata_ref.get('roles', [])))

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.get_user(user_id)
        self.get_project(tenant_id)
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

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        try:
            metadata_ref = self.get_metadata(user_id, tenant_id)
            roles = set(metadata_ref.get('roles', []))
            if role_id not in roles:
                msg = _('Cannot remove role that has not been granted, %s' %
                        role_id)
                raise exception.RoleNotFound(message=msg)
            roles.remove(role_id)
            metadata_ref['roles'] = list(roles)
            if len(roles):
                self.update_metadata(user_id, tenant_id, metadata_ref)
            else:
                session = self.get_session()
                q = session.query(UserProjectGrant)
                q = q.filter_by(project_id=tenant_id)
                q.delete()
        except exception.MetadataNotFound:
            msg = 'Cannot remove role that has not been granted, %s' % role_id
            raise exception.RoleNotFound(message=msg)

    # CRUD
    @sql.handle_conflicts(type='project')
    def create_project(self, tenant_id, tenant):
        tenant['name'] = clean.project_name(tenant['name'])
        session = self.get_session()
        with session.begin():
            tenant_ref = Project.from_dict(tenant)
            session.add(tenant_ref)
            session.flush()
        return tenant_ref.to_dict()

    @sql.handle_conflicts(type='project')
    def update_project(self, tenant_id, tenant):
        session = self.get_session()

        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        try:
            tenant_ref = session.query(Project).filter_by(id=tenant_id).one()
        except sql.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_id)

        with session.begin():
            old_project_dict = tenant_ref.to_dict()
            for k in tenant:
                old_project_dict[k] = tenant[k]
            new_project = Project.from_dict(old_project_dict)
            for attr in Project.attributes:
                if attr != 'id':
                    setattr(tenant_ref, attr, getattr(new_project, attr))
            tenant_ref.extra = new_project.extra
            session.flush()
        return tenant_ref.to_dict(include_extra_dict=True)

    @sql.handle_conflicts(type='project')
    def delete_project(self, tenant_id):
        session = self.get_session()

        try:
            tenant_ref = session.query(Project).filter_by(id=tenant_id).one()
        except sql.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_id)

        with session.begin():
            q = session.query(UserProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            q = session.query(UserProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            q = session.query(GroupProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            delete_query = session.query(Project).filter_by(id=tenant_id)
            if not delete_query.delete(False):
                raise exception.ProjectNotFound(project_id=tenant_id)

            session.delete(tenant_ref)
            session.flush()

    @sql.handle_conflicts(type='metadata')
    def create_metadata(self, user_id, tenant_id, metadata,
                        domain_id=None, group_id=None):
        session = self.get_session()
        with session.begin():
            if user_id:
                if tenant_id:
                    session.add(UserProjectGrant(user_id=user_id,
                                                 project_id=tenant_id,
                                                 data=metadata))
                elif domain_id:
                    session.add(UserDomainGrant(user_id=user_id,
                                                domain_id=domain_id,
                                                data=metadata))
            elif group_id:
                if tenant_id:
                    session.add(GroupProjectGrant(group_id=group_id,
                                                  project_id=tenant_id,
                                                  data=metadata))
                elif domain_id:
                    session.add(GroupDomainGrant(group_id=group_id,
                                                 domain_id=domain_id,
                                                 data=metadata))
            session.flush()
        return metadata

    @sql.handle_conflicts(type='metadata')
    def update_metadata(self, user_id, tenant_id, metadata,
                        domain_id=None, group_id=None):
        session = self.get_session()
        with session.begin():
            if user_id:
                if tenant_id:
                    q = session.query(UserProjectGrant)
                    q = q.filter_by(user_id=user_id)
                    q = q.filter_by(project_id=tenant_id)
                elif domain_id:
                    q = session.query(UserDomainGrant)
                    q = q.filter_by(user_id=user_id)
                    q = q.filter_by(domain_id=domain_id)
            elif group_id:
                if tenant_id:
                    q = session.query(GroupProjectGrant)
                    q = q.filter_by(group_id=group_id)
                    q = q.filter_by(project_id=tenant_id)
                elif domain_id:
                    q = session.query(GroupDomainGrant)
                    q = q.filter_by(group_id=group_id)
                    q = q.filter_by(domain_id=domain_id)
            metadata_ref = q.first()
            data = metadata_ref.data.copy()
            data.update(metadata)
            metadata_ref.data = data
            session.flush()
        return metadata_ref

    # domain crud

    @sql.handle_conflicts(type='domain')
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

    @sql.handle_conflicts(type='domain')
    def get_domain_by_name(self, domain_name):
        session = self.get_session()
        try:
            ref = session.query(Domain).filter_by(name=domain_name).one()
        except sql.NotFound:
            raise exception.DomainNotFound(domain_id=domain_name)
        return ref.to_dict()

    @sql.handle_conflicts(type='domain')
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

    def list_user_projects(self, user_id):
        session = self.get_session()
        user = self.get_user(user_id)
        metadata_refs = session\
            .query(UserProjectGrant)\
            .filter_by(user_id=user_id)
        project_ids = set([x.project_id for x in metadata_refs
                           if x.data.get('roles')])
        if user.get('project_id'):
            project_ids.add(user['project_id'])

        # FIXME(dolph): this should be removed with proper migrations
        if user.get('tenant_id'):
            project_ids.add(user['tenant_id'])

        return [self.get_project(x) for x in project_ids]

    # user crud

    @sql.handle_conflicts(type='user')
    def create_user(self, user_id, user):
        user['name'] = clean.user_name(user['name'])
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

    def _get_user_by_name(self, user_name, domain_id):
        session = self.get_session()
        query = session.query(User)
        query = query.filter_by(name=user_name)
        query = query.filter_by(domain_id=domain_id)
        try:
            user_ref = query.one()
        except sql.NotFound:
            raise exception.UserNotFound(user_id=user_name)
        return user_ref.to_dict()

    def get_user(self, user_id):
        return identity.filter_user(self._get_user(user_id))

    def get_user_by_name(self, user_name, domain_id):
        return identity.filter_user(
            self._get_user_by_name(user_name, domain_id))

    @sql.handle_conflicts(type='user')
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

    def add_user_to_group(self, user_id, group_id):
        session = self.get_session()
        self.get_group(group_id)
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        rv = query.first()
        if rv:
            return

        with session.begin():
            session.add(UserGroupMembership(user_id=user_id,
                                            group_id=group_id))
            session.flush()

    def check_user_in_group(self, user_id, group_id):
        session = self.get_session()
        self.get_group(group_id)
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        if not query.first():
            raise exception.NotFound('User not found in group')

    def remove_user_from_group(self, user_id, group_id):
        session = self.get_session()
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        membership_ref = query.first()
        if membership_ref is None:
            raise exception.NotFound('User not found in group')
        with session.begin():
            session.delete(membership_ref)
            session.flush()

    def list_groups_for_user(self, user_id):
        session = self.get_session()
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        membership_refs = query.all()
        return [self.get_group(x.group_id) for x in membership_refs]

    def list_users_in_group(self, group_id):
        session = self.get_session()
        self.get_group(group_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(group_id=group_id)
        membership_refs = query.all()
        return [self.get_user(x.user_id) for x in membership_refs]

    def delete_user(self, user_id):
        session = self.get_session()

        try:
            ref = session.query(User).filter_by(id=user_id).one()
        except sql.NotFound:
            raise exception.UserNotFound(user_id=user_id)

        with session.begin():

            q = session.query(UserProjectGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserDomainGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserGroupMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            if not session.query(User).filter_by(id=user_id).delete(False):
                raise exception.UserNotFound(user_id=user_id)

            session.delete(ref)
            session.flush()

    # group crud

    @sql.handle_conflicts(type='group')
    def create_group(self, group_id, group):
        session = self.get_session()
        with session.begin():
            ref = Group.from_dict(group)
            session.add(ref)
            session.flush()
        return ref.to_dict()

    def list_groups(self):
        session = self.get_session()
        refs = session.query(Group).all()
        return [ref.to_dict() for ref in refs]

    def _get_group(self, group_id):
        session = self.get_session()
        ref = session.query(Group).filter_by(id=group_id).first()
        if not ref:
            raise exception.GroupNotFound(group_id=group_id)
        return ref.to_dict()

    def get_group(self, group_id):
        return self._get_group(group_id)

    @sql.handle_conflicts(type='group')
    def update_group(self, group_id, group):
        session = self.get_session()

        with session.begin():
            ref = session.query(Group).filter_by(id=group_id).first()
            if ref is None:
                raise exception.GroupNotFound(group_id=group_id)
            old_dict = ref.to_dict()
            for k in group:
                old_dict[k] = group[k]
            new_group = Group.from_dict(old_dict)
            for attr in Group.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_group, attr))
            ref.extra = new_group.extra
            session.flush()
        return ref.to_dict()

    def delete_group(self, group_id):
        session = self.get_session()

        try:
            ref = session.query(Group).filter_by(id=group_id).one()
        except sql.NotFound:
            raise exception.GroupNotFound(group_id=group_id)

        with session.begin():
            q = session.query(GroupProjectGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            q = session.query(GroupDomainGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            q = session.query(UserGroupMembership)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            if not session.query(Group).filter_by(id=group_id).delete(False):
                raise exception.GroupNotFound(group_id=group_id)

            session.delete(ref)
            session.flush()

    # credential crud

    @sql.handle_conflicts(type='credential')
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

    @sql.handle_conflicts(type='credential')
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

    @sql.handle_conflicts(type='role')
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

    @sql.handle_conflicts(type='role')
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
            for metadata_ref in session.query(UserProjectGrant):
                metadata = metadata_ref.to_dict()
                try:
                    self.remove_role_from_user_and_project(
                        metadata['user_id'], metadata['project_id'], role_id)
                except exception.RoleNotFound:
                    pass

            # FIXME(dolph): user-domain metadata needs to be updated

            if not session.query(Role).filter_by(id=role_id).delete():
                raise exception.RoleNotFound(role_id=role_id)

            session.delete(ref)
            session.flush()
