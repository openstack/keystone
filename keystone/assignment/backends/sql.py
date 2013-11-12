# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-13 OpenStack Foundation
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
from keystone.common import dependency
from keystone.common import sql
from keystone.common.sql import migration
from keystone import config
from keystone import exception


CONF = config.CONF


@dependency.requires('identity_api')
class Assignment(sql.Base, assignment.Driver):

    # Internal interface to manage the database
    def db_sync(self, version=None):
        migration.db_sync(version=version)

    def _get_project(self, session, project_id):
        project_ref = session.query(Project).get(project_id)
        if project_ref is None:
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, tenant_id):
        with self.transaction() as session:
            return self._get_project(session, tenant_id).to_dict()

    def get_project_by_name(self, tenant_name, domain_id):
        with self.transaction() as session:
            query = session.query(Project)
            query = query.filter_by(name=tenant_name)
            query = query.filter_by(domain_id=domain_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=tenant_name)
            return project_ref.to_dict()

    def list_user_ids_for_project(self, tenant_id):
        with self.transaction() as session:
            self._get_project(session, tenant_id)
            query = session.query(UserProjectGrant)
            query = query.filter(UserProjectGrant.project_id ==
                                 tenant_id)
            project_refs = query.all()
            return [project_ref.user_id for project_ref in project_refs]

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None, session=None):
        # We aren't given a session when called by the manager directly.
        if session is None:
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
        with self.transaction() as session:
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
                                                  domain_id, group_id,
                                                  session=session)
                is_new = False
            except exception.MetadataNotFound:
                metadata_ref = {}
                is_new = True

            metadata_ref['roles'] = self._add_role_to_role_dicts(
                role_id, inherited_to_projects, metadata_ref.get('roles', []))

            if is_new:
                self._create_metadata(session, user_id, project_id,
                                      metadata_ref, domain_id, group_id)
            else:
                self._update_metadata(session, user_id, project_id,
                                      metadata_ref, domain_id, group_id)

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        with self.transaction() as session:
            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            try:
                metadata_ref = self._get_metadata(user_id, project_id,
                                                  domain_id, group_id,
                                                  session=session)
            except exception.MetadataNotFound:
                metadata_ref = {}

            return [self.get_role(x) for x in
                    self._roles_from_role_dicts(metadata_ref.get('roles', []),
                                                inherited_to_projects)]

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        with self.transaction() as session:
            role_ref = self._get_role(session, role_id)
            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            try:
                metadata_ref = self._get_metadata(user_id, project_id,
                                                  domain_id, group_id,
                                                  session=session)
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
        with self.transaction() as session:
            self._delete_grant(session=session, role_id=role_id,
                               user_id=user_id, group_id=group_id,
                               domain_id=domain_id, project_id=project_id,
                               inherited_to_projects=inherited_to_projects)

    def _delete_grant(self, session, role_id, user_id=None, group_id=None,
                      domain_id=None, project_id=None,
                      inherited_to_projects=False):
        self._get_role(session, role_id)
        if domain_id:
            self._get_domain(session, domain_id)
        if project_id:
            self._get_project(session, project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id,
                                              session=session)
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
            self._create_metadata(session, user_id, project_id, metadata_ref,
                                  domain_id, group_id)
        else:
            self._update_metadata(session, user_id, project_id, metadata_ref,
                                  domain_id, group_id)

    def list_projects(self, domain_id=None):
        with self.transaction() as session:
            if domain_id:
                self._get_domain(session, domain_id)

            query = session.query(Project)
            if domain_id:
                query = query.filter_by(domain_id=domain_id)
            project_refs = query.all()
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_for_user(self, user_id, group_ids):
        # NOTE(henry-nash): This method is written as a series of code blocks,
        # rather than broken down into too many sub-functions, to prepare for
        # SQL optimization when we rationalize the grant tables in the
        # future.

        def _list_domains_with_inherited_grants(query):
            domain_ids = set()
            domain_grants = query.all()
            for domain_grant in domain_grants:
                for grant in domain_grant.data.get('roles', []):
                    if 'inherited_to' in grant:
                        domain_ids.add(domain_grant.domain_id)
            return domain_ids

        def _project_ids_to_dicts(session, ids):
            return [self._get_project(session, project_id).to_dict()
                    for project_id in ids]

        # NOTE(henry-nash): The metadata management code doesn't always clean
        # up table entries when the last role is deleted - so when checking
        # grant entries, only include this project if there are actually roles
        # present.

        with self.transaction() as session:
            # First get a list of the projects for which the user has a direct
            # role assigned
            query = session.query(UserProjectGrant)
            query = query.filter_by(user_id=user_id)
            project_grants_for_user = query.all()
            project_ids = set(x.project_id for x in project_grants_for_user
                              if x.data.get('roles'))

            # Now find any projects with group roles and add them in
            for group_id in group_ids:
                query = session.query(GroupProjectGrant)
                query = query.filter_by(group_id=group_id)
                project_grants_for_group = query.all()
                for project_grant in project_grants_for_group:
                    if project_grant.data.get('roles'):
                        project_ids.add(project_grant.project_id)

            if not CONF.os_inherit.enabled:
                return _project_ids_to_dicts(session, project_ids)

            # Inherited roles are enabled, so check to see if this user has any
            # such roles (direct or group) on any domain, in which case we must
            # add in all the projects in that domain.

            domain_ids = set()

            # First check for user roles on any domains
            query = session.query(UserDomainGrant)
            query = query.filter_by(user_id=user_id)
            domain_ids.update(_list_domains_with_inherited_grants(query))

            # Now for group roles on any domains
            for group_id in group_ids:
                query = session.query(GroupDomainGrant)
                query = query.filter_by(group_id=group_id)
                domain_ids.update(_list_domains_with_inherited_grants(query))

            # For each domain on which the user has an inherited role, get the
            # list of projects in that domain and add them in to the
            # project id list

            for domain_id in domain_ids:
                query = session.query(Project)
                query = query.filter_by(domain_id=domain_id)
                project_refs = query.all()
                for project_ref in project_refs:
                    project_ids.add(project_ref.id)

            return _project_ids_to_dicts(session, project_ids)

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.identity_api.get_user(user_id)

        with self.transaction() as session:
            self._get_project(session, tenant_id)
            self._get_role(session, role_id)
            try:
                metadata_ref = self._get_metadata(user_id, tenant_id,
                                                  session=session)
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
                self._create_metadata(session, user_id, tenant_id,
                                      metadata_ref)
            else:
                self._update_metadata(session, user_id, tenant_id,
                                      metadata_ref)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        with self.transaction() as session:
            try:
                metadata_ref = self._get_metadata(user_id, tenant_id,
                                                  session=session)
            except exception.MetadataNotFound:
                raise exception.RoleNotFound(message=_(
                    'Cannot remove role that has not been granted, %s') %
                    role_id)
            try:
                metadata_ref['roles'] = self._remove_role_from_role_dicts(
                    role_id, False, metadata_ref.get('roles', []))
            except KeyError:
                raise exception.RoleNotFound(message=_(
                    'Cannot remove role that has not been granted, %s') %
                    role_id)

            if len(metadata_ref['roles']):
                self._update_metadata(session, user_id, tenant_id,
                                      metadata_ref)
            else:
                q = session.query(UserProjectGrant)
                q = q.filter_by(user_id=user_id)
                q = q.filter_by(project_id=tenant_id)
                q.delete()

    def list_role_assignments(self):

        # TODO(henry-nash): The current implementation is really simulating
        # us having a common role assignment table, rather than having the
        # four different grant tables we have today.  When we move to role
        # assignment as a first class entity, we should create the single
        # assignment table, simplifying the logic of this (and many other)
        # functions.

        with self.transaction() as session:
            assignment_list = []
            refs = session.query(UserDomainGrant).all()
            for x in refs:
                roles = x.data.get('roles', {})
                for r in self._roles_from_role_dicts(roles, False):
                    assignment_list.append({'user_id': x.user_id,
                                            'domain_id': x.domain_id,
                                            'role_id': r})
                for r in self._roles_from_role_dicts(roles, True):
                    assignment_list.append({'user_id': x.user_id,
                                            'domain_id': x.domain_id,
                                            'role_id': r,
                                            'inherited_to_projects': True})
            refs = session.query(UserProjectGrant).all()
            for x in refs:
                roles = x.data.get('roles', {})
                for r in self._roles_from_role_dicts(roles, False):
                    assignment_list.append({'user_id': x.user_id,
                                            'project_id': x.project_id,
                                            'role_id': r})
            refs = session.query(GroupDomainGrant).all()
            for x in refs:
                roles = x.data.get('roles', {})
                for r in self._roles_from_role_dicts(roles, False):
                    assignment_list.append({'group_id': x.group_id,
                                            'domain_id': x.domain_id,
                                            'role_id': r})
                for r in self._roles_from_role_dicts(roles, True):
                    assignment_list.append({'group_id': x.group_id,
                                            'domain_id': x.domain_id,
                                            'role_id': r,
                                            'inherited_to_projects': True})
            refs = session.query(GroupProjectGrant).all()
            for x in refs:
                roles = x.data.get('roles', {})
                for r in self._roles_from_role_dicts(roles, False):
                    assignment_list.append({'group_id': x.group_id,
                                            'project_id': x.project_id,
                                            'role_id': r})
            return assignment_list

    # CRUD
    @sql.handle_conflicts(conflict_type='project')
    def create_project(self, tenant_id, tenant):
        tenant['name'] = clean.project_name(tenant['name'])
        with self.transaction() as session:
            tenant_ref = Project.from_dict(tenant)
            session.add(tenant_ref)
            return tenant_ref.to_dict()

    @sql.handle_conflicts(conflict_type='project')
    def update_project(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])

        with self.transaction() as session:
            tenant_ref = self._get_project(session, tenant_id)
            old_project_dict = tenant_ref.to_dict()
            for k in tenant:
                old_project_dict[k] = tenant[k]
            new_project = Project.from_dict(old_project_dict)
            for attr in Project.attributes:
                if attr != 'id':
                    setattr(tenant_ref, attr, getattr(new_project, attr))
            tenant_ref.extra = new_project.extra
            return tenant_ref.to_dict(include_extra_dict=True)

    @sql.handle_conflicts(conflict_type='project')
    def delete_project(self, tenant_id):
        with self.transaction() as session:
            tenant_ref = self._get_project(session, tenant_id)

            q = session.query(UserProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            q = session.query(GroupProjectGrant)
            q = q.filter_by(project_id=tenant_id)
            q.delete(False)

            session.delete(tenant_ref)

    @sql.handle_conflicts(conflict_type='metadata')
    def _create_metadata(self, session, user_id, tenant_id, metadata,
                         domain_id=None, group_id=None):
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

    @sql.handle_conflicts(conflict_type='metadata')
    def _update_metadata(self, session, user_id, tenant_id, metadata,
                         domain_id=None, group_id=None):
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
        metadata_ref.data.update(metadata)

        # NOTE(pete5): We manually mark metadata_ref.data as modified since
        # SQLAlchemy may not automatically detect the change. Why not? Well...
        # SQLAlchemy knows that an attribute has changed either if (1) somebody
        # has marked it as mutated, or (2) the attribute's value at load-time
        # != the flush-time value. Since we don't track mutations to JsonBlob
        # columns (see "Mutation Tracking" in SQLAlchemy's documentation at
        # http://docs.sqlalchemy.org/en/rel_0_7/orm/extensions/mutable.html),
        # we can't count on (1). Since metadata_ref.data is often the same
        # object as metadata (i.e., we return metadata_ref.data in
        # self._get_metadata, manipulate it, then pass it to
        # self._update_metadata), the check in (2) determines that the value
        # hasn't changed.
        sql.flag_modified(metadata_ref, 'data')

        session.flush()
        return metadata_ref

    # domain crud

    @sql.handle_conflicts(conflict_type='domain')
    def create_domain(self, domain_id, domain):
        with self.transaction() as session:
            ref = Domain.from_dict(domain)
            session.add(ref)
        return ref.to_dict()

    def list_domains(self):
        with self.transaction() as session:
            refs = session.query(Domain).all()
            return [ref.to_dict() for ref in refs]

    def _get_domain(self, session, domain_id):
        ref = session.query(Domain).get(domain_id)
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def get_domain(self, domain_id):
        with self.transaction() as session:
            return self._get_domain(session, domain_id).to_dict()

    def get_domain_by_name(self, domain_name):
        with self.transaction() as session:
            try:
                ref = (session.query(Domain).
                       filter_by(name=domain_name).one())
            except sql.NotFound:
                raise exception.DomainNotFound(domain_id=domain_name)
            return ref.to_dict()

    @sql.handle_conflicts(conflict_type='domain')
    def update_domain(self, domain_id, domain):
        with self.transaction() as session:
            ref = self._get_domain(session, domain_id)
            old_dict = ref.to_dict()
            for k in domain:
                old_dict[k] = domain[k]
            new_domain = Domain.from_dict(old_dict)
            for attr in Domain.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_domain, attr))
            ref.extra = new_domain.extra
            return ref.to_dict()

    def delete_domain(self, domain_id):
        with self.transaction() as session:
            ref = self._get_domain(session, domain_id)
            session.delete(ref)

    # role crud

    @sql.handle_conflicts(conflict_type='role')
    def create_role(self, role_id, role):
        with self.transaction() as session:
            ref = Role.from_dict(role)
            session.add(ref)
            return ref.to_dict()

    def list_roles(self):
        with self.transaction() as session:
            refs = session.query(Role).all()
            return [ref.to_dict() for ref in refs]

    def _get_role(self, session, role_id):
        ref = session.query(Role).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def get_role(self, role_id):
        with self.transaction() as session:
            return self._get_role(session, role_id).to_dict()

    @sql.handle_conflicts(conflict_type='role')
    def update_role(self, role_id, role):
        with self.transaction() as session:
            ref = self._get_role(session, role_id)
            old_dict = ref.to_dict()
            for k in role:
                old_dict[k] = role[k]
            new_role = Role.from_dict(old_dict)
            for attr in Role.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_role, attr))
            ref.extra = new_role.extra
            return ref.to_dict()

    def delete_role(self, role_id):
        with self.transaction() as session:
            ref = self._get_role(session, role_id)
            for metadata_ref in session.query(UserProjectGrant):
                try:
                    self._delete_grant(session, role_id,
                                       user_id=metadata_ref.user_id,
                                       project_id=metadata_ref.project_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(UserDomainGrant):
                try:
                    self._delete_grant(session, role_id,
                                       user_id=metadata_ref.user_id,
                                       domain_id=metadata_ref.domain_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(GroupProjectGrant):
                try:
                    self._delete_grant(session, role_id,
                                       group_id=metadata_ref.group_id,
                                       project_id=metadata_ref.project_id)
                except exception.RoleNotFound:
                    pass
            for metadata_ref in session.query(GroupDomainGrant):
                try:
                    self._delete_grant(session, role_id,
                                       group_id=metadata_ref.group_id,
                                       domain_id=metadata_ref.domain_id)
                except exception.RoleNotFound:
                    pass

            session.delete(ref)

    def delete_user(self, user_id):
        with self.transaction() as session:
            q = session.query(UserProjectGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserDomainGrant)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

    def delete_group(self, group_id):
        with self.transaction() as session:
            q = session.query(GroupProjectGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            q = session.query(GroupDomainGrant)
            q = q.filter_by(group_id=group_id)
            q.delete(False)


class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name'), {})


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
    name = sql.Column(sql.String(255), nullable=False)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name'), {})


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
    user_id = sql.Column(sql.String(64), primary_key=True)
    project_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'),
                            primary_key=True)
    data = sql.Column(sql.JsonBlob())


class UserDomainGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'user_domain_metadata'
    user_id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           primary_key=True)
    data = sql.Column(sql.JsonBlob())


class GroupProjectGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'group_project_metadata'
    group_id = sql.Column(sql.String(64), primary_key=True)
    project_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'),
                            primary_key=True)
    data = sql.Column(sql.JsonBlob())


class GroupDomainGrant(sql.ModelBase, BaseGrant):
    __tablename__ = 'group_domain_metadata'
    group_id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           primary_key=True)
    data = sql.Column(sql.JsonBlob())
