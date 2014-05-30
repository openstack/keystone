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

import six
import sqlalchemy

from keystone import assignment
from keystone import clean
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone import config
from keystone import exception
from keystone.openstack.common.db.sqlalchemy import migration
from keystone.openstack.common.gettextutils import _


CONF = config.CONF


class AssignmentType:
    USER_PROJECT = 'UserProject'
    GROUP_PROJECT = 'GroupProject'
    USER_DOMAIN = 'UserDomain'
    GROUP_DOMAIN = 'GroupDomain'


class Assignment(assignment.Driver):

    # Internal interface to manage the database
    def db_sync(self, version=None):
        migration.db_sync(
            sql.get_engine(), migration_helpers.find_migrate_repo(),
            version=version)

    def _get_project(self, session, project_id):
        project_ref = session.query(Project).get(project_id)
        if project_ref is None:
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, tenant_id):
        with sql.transaction() as session:
            return self._get_project(session, tenant_id).to_dict()

    def get_project_by_name(self, tenant_name, domain_id):
        with sql.transaction() as session:
            query = session.query(Project)
            query = query.filter_by(name=tenant_name)
            query = query.filter_by(domain_id=domain_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=tenant_name)
            return project_ref.to_dict()

    def list_user_ids_for_project(self, tenant_id):
        with sql.transaction() as session:
            self._get_project(session, tenant_id)
            query = session.query(RoleAssignment.actor_id)
            query = query.filter_by(type=AssignmentType.USER_PROJECT)
            query = query.filter_by(target_id=tenant_id)
            query = query.distinct('actor_id', 'target_id')
            assignments = query.all()
            return [assignment.actor_id for assignment in assignments]

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None, session=None):
        # TODO(henry-nash): This method represents the last vestiges of the old
        # metadata concept in this driver.  Although we no longer need it here,
        # since the Manager layer uses the metadata concept across all
        # assignment drivers, we need to remove it from all of them in order to
        # finally remove this method.

        # We aren't given a session when called by the manager directly.
        if session is None:
            session = sql.get_session()

        q = session.query(RoleAssignment)

        def _calc_assignment_type():
            # Figure out the assignment type we're checking for from the args.
            if user_id:
                if tenant_id:
                    return AssignmentType.USER_PROJECT
                else:
                    return AssignmentType.USER_DOMAIN
            else:
                if tenant_id:
                    return AssignmentType.GROUP_PROJECT
                else:
                    return AssignmentType.GROUP_DOMAIN

        q = q.filter_by(type=_calc_assignment_type())
        q = q.filter_by(actor_id=user_id or group_id)
        q = q.filter_by(target_id=tenant_id or domain_id)
        refs = q.all()
        if not refs:
            raise exception.MetadataNotFound()

        metadata_ref = {}
        metadata_ref['roles'] = []
        for assignment in refs:
            role_ref = {}
            role_ref['id'] = assignment.role_id
            if assignment.inherited and (
                    assignment.type == AssignmentType.USER_DOMAIN or
                    assignment.type == AssignmentType.GROUP_DOMAIN):
                role_ref['inherited_to'] = 'projects'
            metadata_ref['roles'].append(role_ref)

        return metadata_ref

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):

        def calculate_type(user_id, group_id, project_id, domain_id):
            if user_id and project_id:
                return AssignmentType.USER_PROJECT
            elif user_id and domain_id:
                return AssignmentType.USER_DOMAIN
            elif group_id and project_id:
                return AssignmentType.GROUP_PROJECT
            elif group_id and domain_id:
                return AssignmentType.GROUP_DOMAIN
            else:
                message_data = ', '.join(
                    [user_id, group_id, project_id, domain_id])
                raise exception.Error(message=_(
                    'Unexpected combination of grant attributes - '
                    'User, Group, Project, Domain: %s') % message_data)

        with sql.transaction() as session:
            self._get_role(session, role_id)

            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            if project_id and inherited_to_projects:
                msg = _('Inherited roles can only be assigned to domains')
                raise exception.Conflict(type='role grant', details=msg)

        type = calculate_type(user_id, group_id, project_id, domain_id)
        try:
            with sql.transaction() as session:
                session.add(RoleAssignment(
                    type=type,
                    actor_id=user_id or group_id,
                    target_id=project_id or domain_id,
                    role_id=role_id,
                    inherited=inherited_to_projects))
        except sql.DBDuplicateEntry:
            # The v3 grant APIs are silent if the assignment already exists
            pass

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        with sql.transaction() as session:
            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            q = session.query(Role).join(RoleAssignment)
            q = q.filter(RoleAssignment.actor_id == (user_id or group_id))
            q = q.filter(RoleAssignment.target_id == (project_id or domain_id))
            q = q.filter(RoleAssignment.inherited == inherited_to_projects)
            q = q.filter(Role.id == RoleAssignment.role_id)
            return [x.to_dict() for x in q.all()]

    def _build_grant_filter(self, session, role_id, user_id, group_id,
                            domain_id, project_id, inherited_to_projects):
        q = session.query(RoleAssignment)
        q = q.filter_by(actor_id=user_id or group_id)
        q = q.filter_by(target_id=project_id or domain_id)
        q = q.filter_by(role_id=role_id)
        q = q.filter_by(inherited=inherited_to_projects)
        return q

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        with sql.transaction() as session:
            role_ref = self._get_role(session, role_id)
            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            try:
                q = self._build_grant_filter(
                    session, role_id, user_id, group_id, domain_id, project_id,
                    inherited_to_projects)
                q.one()
            except sql.NotFound:
                raise exception.RoleNotFound(role_id=role_id)

            return role_ref.to_dict()

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        with sql.transaction() as session:
            self._get_role(session, role_id)
            if domain_id:
                self._get_domain(session, domain_id)
            if project_id:
                self._get_project(session, project_id)

            q = self._build_grant_filter(
                session, role_id, user_id, group_id, domain_id, project_id,
                inherited_to_projects)
            if not q.delete(False):
                raise exception.RoleNotFound(role_id=role_id)

    @sql.truncated
    def list_projects(self, hints):
        with sql.transaction() as session:
            query = session.query(Project)
            project_refs = sql.filter_limit_query(Project, query, hints)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_in_domain(self, domain_id):
        with sql.transaction() as session:
            self._get_domain(session, domain_id)
            query = session.query(Project)
            project_refs = query.filter_by(domain_id=domain_id)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_for_user(self, user_id, group_ids, hints):
        # TODO(henry-nash): Now that we have a single assignment table, we
        # should be able to honor the hints list that is provided.

        def _project_ids_to_dicts(session, ids):
            if not ids:
                return []
            else:
                query = session.query(Project)
                query = query.filter(Project.id.in_(ids))
                project_refs = query.all()
                return [project_ref.to_dict() for project_ref in project_refs]

        with sql.transaction() as session:
            # First get a list of the projects and domains for which the user
            # has any kind of role assigned

            actor_list = [user_id]
            if group_ids:
                actor_list = actor_list + group_ids

            query = session.query(RoleAssignment)
            query = query.filter(RoleAssignment.actor_id.in_(actor_list))
            assignments = query.all()

            project_ids = set()
            for assignment in assignments:
                if (assignment.type == AssignmentType.USER_PROJECT or
                        assignment.type == AssignmentType.GROUP_PROJECT):
                    project_ids.add(assignment.target_id)

            if not CONF.os_inherit.enabled:
                return _project_ids_to_dicts(session, project_ids)

            # Inherited roles are enabled, so check to see if this user has any
            # such roles (direct or group) on any domain, in which case we must
            # add in all the projects in that domain.

            domain_ids = set()
            for assignment in assignments:
                if ((assignment.type == AssignmentType.USER_DOMAIN or
                    assignment.type == AssignmentType.GROUP_DOMAIN) and
                        assignment.inherited):
                    domain_ids.add(assignment.target_id)

            # Get the projects that are owned by all of these domains and
            # add them in to the project id list

            if domain_ids:
                query = session.query(Project.id)
                query = query.filter(Project.domain_id.in_(domain_ids))
                for project_ref in query.all():
                    project_ids.add(project_ref.id)

            return _project_ids_to_dicts(session, project_ids)

    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):

        if project_id is not None:
            assignment_type = AssignmentType.GROUP_PROJECT
            target_id = project_id
        elif domain_id is not None:
            assignment_type = AssignmentType.GROUP_DOMAIN
            target_id = domain_id
        else:
            raise AttributeError(_("Must specify either domain or project"))

        sql_constraints = sqlalchemy.and_(
            RoleAssignment.type == assignment_type,
            RoleAssignment.target_id == target_id,
            Role.id == RoleAssignment.role_id,
            RoleAssignment.actor_id.in_(group_ids))

        session = sql.get_session()
        with session.begin():
            query = session.query(Role).filter(
                sql_constraints).distinct()
        return [role.to_dict() for role in query.all()]

    def _list_entities_for_groups(self, group_ids, entity):
        if entity == Domain:
            assignment_type = AssignmentType.GROUP_DOMAIN
        else:
            assignment_type = AssignmentType.GROUP_PROJECT

        group_sql_conditions = sqlalchemy.and_(
            RoleAssignment.type == assignment_type,
            entity.id == RoleAssignment.target_id,
            RoleAssignment.actor_id.in_(group_ids))

        session = sql.get_session()
        with session.begin():
            query = session.query(entity).filter(
                group_sql_conditions)
        return [x.to_dict() for x in query.all()]

    def list_projects_for_groups(self, group_ids):
        return self._list_entities_for_groups(group_ids, Project)

    def list_domains_for_groups(self, group_ids):
        return self._list_entities_for_groups(group_ids, Domain)

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        with sql.transaction() as session:
            self._get_project(session, tenant_id)
            self._get_role(session, role_id)

        try:
            with sql.transaction() as session:
                session.add(RoleAssignment(
                    type=AssignmentType.USER_PROJECT,
                    actor_id=user_id, target_id=tenant_id,
                    role_id=role_id, inherited=False))
        except sql.DBDuplicateEntry:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, tenant_id))
            raise exception.Conflict(type='role grant', details=msg)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=user_id)
            q = q.filter_by(target_id=tenant_id)
            q = q.filter_by(role_id=role_id)
            if q.delete() == 0:
                raise exception.RoleNotFound(message=_(
                    'Cannot remove role that has not been granted, %s') %
                    role_id)

    def list_role_assignments(self):

        def denormalize_role(ref):
            assignment = {}
            if ref.type == AssignmentType.USER_PROJECT:
                assignment['user_id'] = ref.actor_id
                assignment['project_id'] = ref.target_id
            elif ref.type == AssignmentType.USER_DOMAIN:
                assignment['user_id'] = ref.actor_id
                assignment['domain_id'] = ref.target_id
            elif ref.type == AssignmentType.GROUP_PROJECT:
                assignment['group_id'] = ref.actor_id
                assignment['project_id'] = ref.target_id
            elif ref.type == AssignmentType.GROUP_DOMAIN:
                assignment['group_id'] = ref.actor_id
                assignment['domain_id'] = ref.target_id
            else:
                raise exception.Error(message=_(
                    'Unexpected assignment type encountered, %s') %
                    ref.type)
            assignment['role_id'] = ref.role_id
            if ref.inherited and (ref.type == AssignmentType.USER_DOMAIN or
                                  ref.type == AssignmentType.GROUP_DOMAIN):
                assignment['inherited_to_projects'] = 'projects'
            return assignment

        with sql.transaction() as session:
            refs = session.query(RoleAssignment).all()
            return [denormalize_role(ref) for ref in refs]

    # CRUD
    @sql.handle_conflicts(conflict_type='project')
    def create_project(self, tenant_id, tenant):
        tenant['name'] = clean.project_name(tenant['name'])
        with sql.transaction() as session:
            tenant_ref = Project.from_dict(tenant)
            session.add(tenant_ref)
            return tenant_ref.to_dict()

    @sql.handle_conflicts(conflict_type='project')
    def update_project(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])

        with sql.transaction() as session:
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
        with sql.transaction() as session:
            tenant_ref = self._get_project(session, tenant_id)

            q = session.query(RoleAssignment)
            q = q.filter_by(target_id=tenant_id)
            q.delete(False)

            session.delete(tenant_ref)

    # domain crud

    @sql.handle_conflicts(conflict_type='domain')
    def create_domain(self, domain_id, domain):
        with sql.transaction() as session:
            ref = Domain.from_dict(domain)
            session.add(ref)
        return ref.to_dict()

    @sql.truncated
    def list_domains(self, hints):
        with sql.transaction() as session:
            query = session.query(Domain)
            refs = sql.filter_limit_query(Domain, query, hints)
            return [ref.to_dict() for ref in refs]

    def _get_domain(self, session, domain_id):
        ref = session.query(Domain).get(domain_id)
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def get_domain(self, domain_id):
        with sql.transaction() as session:
            return self._get_domain(session, domain_id).to_dict()

    def get_domain_by_name(self, domain_name):
        with sql.transaction() as session:
            try:
                ref = (session.query(Domain).
                       filter_by(name=domain_name).one())
            except sql.NotFound:
                raise exception.DomainNotFound(domain_id=domain_name)
            return ref.to_dict()

    @sql.handle_conflicts(conflict_type='domain')
    def update_domain(self, domain_id, domain):
        with sql.transaction() as session:
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
        with sql.transaction() as session:
            ref = self._get_domain(session, domain_id)

            # TODO(henry-nash): Although the controller will ensure deletion of
            # all users & groups within the domain (which will cause all
            # assignments for those users/groups to also be deleted), there
            # could still be assignments on this domain for users/groups in
            # other domains - so we should delete these here (see Bug #1277847)

            session.delete(ref)

    # role crud

    @sql.handle_conflicts(conflict_type='role')
    def create_role(self, role_id, role):
        with sql.transaction() as session:
            ref = Role.from_dict(role)
            session.add(ref)
            return ref.to_dict()

    @sql.truncated
    def list_roles(self, hints):
        with sql.transaction() as session:
            query = session.query(Role)
            refs = sql.filter_limit_query(Role, query, hints)
            return [ref.to_dict() for ref in refs]

    def _get_role(self, session, role_id):
        ref = session.query(Role).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def get_role(self, role_id):
        with sql.transaction() as session:
            return self._get_role(session, role_id).to_dict()

    @sql.handle_conflicts(conflict_type='role')
    def update_role(self, role_id, role):
        with sql.transaction() as session:
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
        with sql.transaction() as session:
            ref = self._get_role(session, role_id)
            q = session.query(RoleAssignment)
            q = q.filter_by(role_id=role_id)
            q.delete(False)
            session.delete(ref)

    def delete_user(self, user_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=user_id)
            q.delete(False)

    def delete_group(self, group_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=group_id)
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


class RoleAssignment(sql.ModelBase, sql.DictBase):
    __tablename__ = 'assignment'
    attributes = ['type', 'actor_id', 'target_id', 'role_id', 'inherited']
    # NOTE(henry-nash); Postgres requires a name to be defined for an Enum
    type = sql.Column(
        sql.Enum(AssignmentType.USER_PROJECT, AssignmentType.GROUP_PROJECT,
                 AssignmentType.USER_DOMAIN, AssignmentType.GROUP_DOMAIN,
                 name='type'),
        nullable=False)
    actor_id = sql.Column(sql.String(64), nullable=False)
    target_id = sql.Column(sql.String(64), nullable=False)
    role_id = sql.Column(sql.String(64), sql.ForeignKey('role.id'),
                         nullable=False)
    inherited = sql.Column(sql.Boolean, default=False, nullable=False)
    __table_args__ = (sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id',
                                               'role_id'), {})

    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        RoleAssignment doesn't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(six.iteritems(self))
