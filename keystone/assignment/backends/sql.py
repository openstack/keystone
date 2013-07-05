# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-13 OpenStack LLC
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

from keystone import assignment
from keystone import clean
from keystone.common import sql
from keystone.common.sql import migration
from keystone import exception


class Assignment(sql.Base, assignment.Driver):
    def __init__(self):
        super(Assignment, self).__init__()
        self.identity_api = None

    # Internal interface to manage the database
    def db_sync(self, version=None):
        migration.db_sync(version=version)

    def _get_project(self, session, project_id):
        project_ref = session.query(Project).get(project_id)
        if project_ref is None:
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, tenant_id):
        session = self.get_session()
        return self._get_project(session, tenant_id).to_dict()

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

    def get_project_user_ids(self, tenant_id):
        session = self.get_session()
        self.get_project(tenant_id)
        query = session.query(UserProjectGrant)
        query = query.filter(UserProjectGrant.project_id ==
                             tenant_id)
        project_refs = query.all()
        return [project_ref.user_id for project_ref in project_refs]

    def get_project_users(self, tenant_id):
        self.get_session()
        self.get_project(tenant_id)
        user_refs = []
        #TODO(ayoung): Move to controller or manager
        for user_id in self.get_project_user_ids(tenant_id):
            user_ref = self.identity_api.get_user(user_id)
            user_refs.append(user_ref)
        return user_refs

    def _get_metadata(self, user_id=None, tenant_id=None,
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
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)

        session = self.get_session()
        self._get_role(session, role_id)

        if domain_id:
            self._get_domain(session, domain_id)
        if project_id:
            self._get_project(session, project_id)

        if project_id and inherited_to_projects:
            msg = _('Inherited roles can only be assigned to domains')
            raise exception.Conflict(type='role grant', details=msg)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True

        metadata_ref['roles'] = self._add_role_to_role_dicts(
            role_id, inherited_to_projects, metadata_ref.get('roles', []))

        if is_new:
            self._create_metadata(user_id, project_id, metadata_ref,
                                  domain_id, group_id)
        else:
            self._update_metadata(user_id, project_id, metadata_ref,
                                  domain_id, group_id)

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)
        session = self.get_session()
        if domain_id:
            self._get_domain(session, domain_id)
        if project_id:
            self._get_project(session, project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        return [self.get_role(x) for x in
                self._roles_from_role_dicts(metadata_ref.get('roles', []),
                                            inherited_to_projects)]

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)

        session = self.get_session()
        role_ref = self._get_role(session, role_id)

        if domain_id:
            self._get_domain(session, domain_id)
        if project_id:
            self._get_project(session, project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}
        role_ids = set(self._roles_from_role_dicts(
            metadata_ref.get('roles', []), inherited_to_projects))
        if role_id not in role_ids:
            raise exception.RoleNotFound(role_id=role_id)
        return role_ref.to_dict()

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        if user_id:
            self.identity_api.get_user(user_id)
        if group_id:
            self.identity_api.get_group(group_id)

        session = self.get_session()
        self._get_role(session, role_id)

        if domain_id:
            self._get_domain(session, domain_id)
        if project_id:
            self._get_project(session, project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True

        try:
            metadata_ref['roles'] = self._remove_role_from_role_dicts(
                role_id, inherited_to_projects, metadata_ref.get('roles', []))
        except KeyError:
            raise exception.RoleNotFound(role_id=role_id)

        if is_new:
            # TODO(henry-nash) It seems odd that you would create a new
            # entry in response to trying to delete a role that was not
            # assigned.  Although benign, this should probably be removed.
            self._create_metadata(user_id, project_id, metadata_ref,
                                  domain_id, group_id)
        else:
            self._update_metadata(user_id, project_id, metadata_ref,
                                  domain_id, group_id)

    def list_projects(self, domain_id=None):
        session = self.get_session()
        if domain_id:
            self._get_domain(session, domain_id)

        query = session.query(Project)
        if domain_id:
            query = query.filter_by(domain_id=domain_id)
        project_refs = query.all()
        return [project_ref.to_dict() for project_ref in project_refs]

    def get_projects_for_user(self, user_id):

        # FIXME(henry-nash) The following should take into account
        # both group and inherited roles. In fact, I don't see why this
        # call can't be handled at the controller level like we do
        # with 'get_roles_for_user_and_project()'.  Further, this
        # call seems essentially the same as 'list_user_projects()'
        # later in this driver.  Both should be removed.

        self.identity_api.get_user(user_id)
        session = self.get_session()
        query = session.query(UserProjectGrant)
        query = query.filter_by(user_id=user_id)
        membership_refs = query.all()
        return [x.project_id for x in membership_refs]

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.identity_api.get_user(user_id)
        session = self.get_session()
        self._get_project(session, tenant_id)
        self._get_role(session, role_id)
        try:
            metadata_ref = self._get_metadata(user_id, tenant_id)
            is_new = False
        except exception.MetadataNotFound:
            metadata_ref = {}
            is_new = True

        try:
            metadata_ref['roles'] = self._add_role_to_role_dicts(
                role_id, False, metadata_ref.get('roles', []),
                allow_existing=False)
        except KeyError:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, tenant_id))
            raise exception.Conflict(type='role grant', details=msg)

        if is_new:
            self._create_metadata(user_id, tenant_id, metadata_ref)
        else:
            self._update_metadata(user_id, tenant_id, metadata_ref)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        try:
            metadata_ref = self._get_metadata(user_id, tenant_id)
            try:
                metadata_ref['roles'] = self._remove_role_from_role_dicts(
                    role_id, False, metadata_ref.get('roles', []))
            except KeyError:
                raise exception.RoleNotFound(message=_(
                    'Cannot remove role that has not been granted, %s') %
                    role_id)

            if len(metadata_ref['roles']):
                self._update_metadata(user_id, tenant_id, metadata_ref)
            else:
                session = self.get_session()
                q = session.query(UserProjectGrant)
                q = q.filter_by(user_id=user_id)
                q = q.filter_by(project_id=tenant_id)
                q.delete()
        except exception.MetadataNotFound:
            msg = 'Cannot remove role that has not been granted, %s' % role_id
            raise exception.RoleNotFound(message=msg)

    def list_role_assignments(self):

        # TODO(henry-nash): The current implementation is really simulating
        # us having a common role assignment table, rather than having the
        # four different grant tables we have today.  When we move to role
        # assignment as a first class entity, we should create the single
        # assignment table, simplifying the logic of this (and many other)
        # functions.

        session = self.get_session()
        assignment_list = []
        refs = session.query(UserDomainGrant).all()
        for x in refs:
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), False):
                        assignment_list.append({'user_id': x.user_id,
                                                'domain_id': x.domain_id,
                                                'role_id': r})
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), True):
                        assignment_list.append({'user_id': x.user_id,
                                                'domain_id': x.domain_id,
                                                'role_id': r,
                                                'inherited_to_projects': True})
        refs = session.query(UserProjectGrant).all()
        for x in refs:
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), False):
                        assignment_list.append({'user_id': x.user_id,
                                                'project_id': x.project_id,
                                                'role_id': r})
        refs = session.query(GroupDomainGrant).all()
        for x in refs:
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), False):
                        assignment_list.append({'group_id': x.group_id,
                                                'domain_id': x.domain_id,
                                                'role_id': r})
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), True):
                        assignment_list.append({'group_id': x.group_id,
                                                'domain_id': x.domain_id,
                                                'role_id': r,
                                                'inherited_to_projects': True})
        refs = session.query(GroupProjectGrant).all()
        for x in refs:
            for r in self._roles_from_role_dicts(
                    x.data.get('roles', {}), False):
                        assignment_list.append({'group_id': x.group_id,
                                                'project_id': x.project_id,
                                                'role_id': r})
        return assignment_list

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

        with session.begin():
            tenant_ref = self._get_project(session, tenant_id)
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

        with session.begin():
            tenant_ref = self._get_project(session, tenant_id)

            q = session.query(UserProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            q = session.query(UserProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            q = session.query(GroupProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            session.delete(tenant_ref)
            session.flush()

    @sql.handle_conflicts(type='metadata')
    def _create_metadata(self, user_id, tenant_id, metadata,
                         domain_id=None, group_id=None):
        session = self.get_session()
        with session.begin():
            if user_id:
                if tenant_id:
                    session.add(UserProjectGrant
                                (user_id=user_id,
                                 project_id=tenant_id,
                                 data=metadata))
                elif domain_id:
                    session.add(UserDomainGrant
                                (user_id=user_id,
                                 domain_id=domain_id,
                                 data=metadata))
            elif group_id:
                if tenant_id:
                    session.add(GroupProjectGrant
                                (group_id=group_id,
                                 project_id=tenant_id,
                                 data=metadata))
                elif domain_id:
                    session.add(GroupDomainGrant
                                (group_id=group_id,
                                 domain_id=domain_id,
                                 data=metadata))
            session.flush()
        return metadata

    @sql.handle_conflicts(type='metadata')
    def _update_metadata(self, user_id, tenant_id, metadata,
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

    def _get_domain(self, session, domain_id):
        ref = session.query(Domain).get(domain_id)
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def get_domain(self, domain_id):
        session = self.get_session()
        return self._get_domain(session, domain_id).to_dict()

    def get_domain_by_name(self, domain_name):
        session = self.get_session()
        try:
            ref = (session.query(Domain).
                   filter_by(name=domain_name).one())
        except sql.NotFound:
            raise exception.DomainNotFound(domain_id=domain_name)
        return ref.to_dict()

    @sql.handle_conflicts(type='domain')
    def update_domain(self, domain_id, domain):
        session = self.get_session()
        with session.begin():
            ref = self._get_domain(session, domain_id)
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
        with session.begin():
            ref = self._get_domain(session, domain_id)
            session.delete(ref)
            session.flush()

    def list_user_projects(self, user_id):

        # FIXME(henry-nash) The following should take into account
        # both group and inherited roles. In fact, I don't see why this
        # call can't be handled at the controller level like we do
        # with 'get_roles_for_user_and_project()'.  Further, this
        # call seems essentially the same as 'get_projects_for_user()'
        # earlier in this driver.  Both should be removed.

        session = self.get_session()
        user = self.identity_api.get_user(user_id)
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

    def _get_role(self, session, role_id):
        ref = session.query(Role).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def get_role(self, role_id):
        session = self.get_session()
        return self._get_role(session, role_id).to_dict()

    @sql.handle_conflicts(type='role')
    def update_role(self, role_id, role):
        session = self.get_session()
        with session.begin():
            ref = self._get_role(session, role_id)
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

        with session.begin():
            ref = self._get_role(session, role_id)
            for metadata_ref in session.query(UserProjectGrant):
                try:
                    self.delete_grant(role_id, user_id=metadata_ref.user_id,
                                      project_id=metadata_ref.project_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(UserDomainGrant):
                try:
                    self.delete_grant(role_id, user_id=metadata_ref.user_id,
                                      domain_id=metadata_ref.domain_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(GroupProjectGrant):
                try:
                    self.delete_grant(role_id, group_id=metadata_ref.group_id,
                                      project_id=metadata_ref.project_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(GroupDomainGrant):
                try:
                    self.delete_grant(role_id, group_id=metadata_ref.group_id,
                                      domain_id=metadata_ref.domain_id)
                except exception.RoleNotFound:
                    pass

            session.delete(ref)
            session.flush()

    def delete_user(self, user_id):
        session = self.get_session()

        with session.begin():
            q = session.query(UserProjectGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserDomainGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            session.flush()

    def delete_group(self, group_id):
        session = self.get_session()

        with session.begin():

            q = session.query(GroupProjectGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            q = session.query(GroupDomainGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            session.flush()


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
    """Base Grant class.

    There are four grant tables in the current implementation, one for
    each type of grant:

    - User for Project
    - User for Domain
    - Group for Project
    - Group for Domain

    Each is a table with the two attributes above as a combined primary key,
    with the data field holding all roles for that combination.  The data
    field is a list of dicts.  For regular role assignments each dict in
    the list of of the form:

    {'id': role_id}

    If the OS-INHERIT extension is enabled and the role on a domain is an
    inherited role, the dict will be of the form:

    {'id': role_id, 'inherited_to': 'projects'}

    """
    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        Grant tables don't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(self.iteritems())


class UserProjectGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'user_project_metadata'
    user_id = sql.Column(sql.String(64),
                         primary_key=True)
    project_id = sql.Column(sql.String(64),
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
