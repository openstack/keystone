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
from sqlalchemy.sql.expression import false

from keystone import assignment as keystone_assignment
from keystone import clean
from keystone.common import sql
from keystone import config
from keystone import exception
from keystone.i18n import _, _LE
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)


class AssignmentType(object):
    USER_PROJECT = 'UserProject'
    GROUP_PROJECT = 'GroupProject'
    USER_DOMAIN = 'UserDomain'
    GROUP_DOMAIN = 'GroupDomain'


class Assignment(keystone_assignment.Driver):

    def default_role_driver(self):
        return "keystone.assignment.role_backends.sql.Role"

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
            query = session.query(RoleAssignment.actor_id)
            query = query.filter_by(type=AssignmentType.USER_PROJECT)
            query = query.filter_by(target_id=tenant_id)
            query = query.distinct('actor_id')
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
            if assignment.inherited:
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

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        with sql.transaction() as session:
            q = session.query(RoleAssignment.role_id)
            q = q.filter(RoleAssignment.actor_id == (user_id or group_id))
            q = q.filter(RoleAssignment.target_id == (project_id or domain_id))
            q = q.filter(RoleAssignment.inherited == inherited_to_projects)
            return [x.role_id for x in q.all()]

    def _build_grant_filter(self, session, role_id, user_id, group_id,
                            domain_id, project_id, inherited_to_projects):
        q = session.query(RoleAssignment)
        q = q.filter_by(actor_id=user_id or group_id)
        q = q.filter_by(target_id=project_id or domain_id)
        q = q.filter_by(role_id=role_id)
        q = q.filter_by(inherited=inherited_to_projects)
        return q

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        with sql.transaction() as session:
            try:
                q = self._build_grant_filter(
                    session, role_id, user_id, group_id, domain_id, project_id,
                    inherited_to_projects)
                q.one()
            except sql.NotFound:
                raise exception.RoleNotFound(role_id=role_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        with sql.transaction() as session:
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

    def list_projects_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Project)
                query = query.filter(Project.id.in_(ids))
                return [project_ref.to_dict() for project_ref in query.all()]

    def list_project_ids_from_domain_ids(self, domain_ids):
        if not domain_ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Project.id)
                query = (
                    query.filter(Project.domain_id.in_(domain_ids)))
                return [x.id for x in query.all()]

    def list_projects_in_domain(self, domain_id):
        with sql.transaction() as session:
            self._get_domain(session, domain_id)
            query = session.query(Project)
            project_refs = query.filter_by(domain_id=domain_id)
            return [project_ref.to_dict() for project_ref in project_refs]

    def _list_project_ids_for_actor(self, actors, hints, inherited,
                                    group_only=False):
        # TODO(henry-nash): Now that we have a single assignment table, we
        # should be able to honor the hints list that is provided.

        assignment_type = [AssignmentType.GROUP_PROJECT]
        if not group_only:
            assignment_type.append(AssignmentType.USER_PROJECT)

        sql_constraints = sqlalchemy.and_(
            RoleAssignment.type.in_(assignment_type),
            RoleAssignment.inherited == inherited,
            RoleAssignment.actor_id.in_(actors))

        with sql.transaction() as session:
            query = session.query(RoleAssignment.target_id).filter(
                sql_constraints).distinct()

        return [x.target_id for x in query.all()]

    def list_project_ids_for_user(self, user_id, group_ids, hints,
                                  inherited=False):
        actor_list = [user_id]
        if group_ids:
            actor_list = actor_list + group_ids

        return self._list_project_ids_for_actor(actor_list, hints, inherited)

    def list_domain_ids_for_user(self, user_id, group_ids, hints,
                                 inherited=False):
        with sql.transaction() as session:
            query = session.query(RoleAssignment.target_id)
            filters = []

            if user_id:
                sql_constraints = sqlalchemy.and_(
                    RoleAssignment.actor_id == user_id,
                    RoleAssignment.inherited == inherited,
                    RoleAssignment.type == AssignmentType.USER_DOMAIN)
                filters.append(sql_constraints)

            if group_ids:
                sql_constraints = sqlalchemy.and_(
                    RoleAssignment.actor_id.in_(group_ids),
                    RoleAssignment.inherited == inherited,
                    RoleAssignment.type == AssignmentType.GROUP_DOMAIN)
                filters.append(sql_constraints)

            if not filters:
                return []

            query = query.filter(sqlalchemy.or_(*filters)).distinct()

            return [assignment.target_id for assignment in query.all()]

    def _get_children(self, session, project_ids):
        query = session.query(Project)
        query = query.filter(Project.parent_id.in_(project_ids))
        project_refs = query.all()
        return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_in_subtree(self, project_id):
        with sql.transaction() as session:
            project = self._get_project(session, project_id).to_dict()
            children = self._get_children(session, [project['id']])
            subtree = []
            examined = set(project['id'])
            while children:
                children_ids = set()
                for ref in children:
                    if ref['id'] in examined:
                        msg = _LE('Circular reference or a repeated '
                                  'entry found in projects hierarchy - '
                                  '%(project_id)s.')
                        LOG.error(msg, {'project_id': ref['id']})
                        return
                    children_ids.add(ref['id'])

                examined.union(children_ids)
                subtree += children
                children = self._get_children(session, children_ids)
            return subtree

    def list_project_parents(self, project_id):
        with sql.transaction() as session:
            project = self._get_project(session, project_id).to_dict()
            parents = []
            examined = set()
            while project.get('parent_id') is not None:
                if project['id'] in examined:
                    msg = _LE('Circular reference or a repeated '
                              'entry found in projects hierarchy - '
                              '%(project_id)s.')
                    LOG.error(msg, {'project_id': project['id']})
                    return

                examined.add(project['id'])
                parent_project = self._get_project(
                    session, project['parent_id']).to_dict()
                parents.append(parent_project)
                project = parent_project
            return parents

    def is_leaf_project(self, project_id):
        with sql.transaction() as session:
            project_refs = self._get_children(session, [project_id])
            return not project_refs

    def list_role_ids_for_groups_on_domain(self, group_ids, domain_id):
        if not group_ids:
            # If there's no groups then there will be no domain roles.
            return []

        sql_constraints = sqlalchemy.and_(
            RoleAssignment.type == AssignmentType.GROUP_DOMAIN,
            RoleAssignment.target_id == domain_id,
            RoleAssignment.inherited == false(),
            RoleAssignment.actor_id.in_(group_ids))

        with sql.transaction() as session:
            query = session.query(RoleAssignment.role_id).filter(
                sql_constraints).distinct()
        return [role.role_id for role in query.all()]

    def list_role_ids_for_groups_on_project(
            self, group_ids, project_id, project_domain_id, project_parents):

        if not group_ids:
            # If there's no groups then there will be no project roles.
            return []

        # NOTE(rodrigods): First, we always include projects with
        # non-inherited assignments
        sql_constraints = sqlalchemy.and_(
            RoleAssignment.type == AssignmentType.GROUP_PROJECT,
            RoleAssignment.inherited == false(),
            RoleAssignment.target_id == project_id)

        if CONF.os_inherit.enabled:
            # Inherited roles from domains
            sql_constraints = sqlalchemy.or_(
                sql_constraints,
                sqlalchemy.and_(
                    RoleAssignment.type == AssignmentType.GROUP_DOMAIN,
                    RoleAssignment.inherited,
                    RoleAssignment.target_id == project_domain_id))

            # Inherited roles from projects
            if project_parents:
                sql_constraints = sqlalchemy.or_(
                    sql_constraints,
                    sqlalchemy.and_(
                        RoleAssignment.type == AssignmentType.GROUP_PROJECT,
                        RoleAssignment.inherited,
                        RoleAssignment.target_id.in_(project_parents)))

        sql_constraints = sqlalchemy.and_(
            sql_constraints, RoleAssignment.actor_id.in_(group_ids))

        with sql.transaction() as session:
            # NOTE(morganfainberg): Only select the columns we actually care
            # about here, in this case role_id.
            query = session.query(RoleAssignment.role_id).filter(
                sql_constraints).distinct()

        return [result.role_id for result in query.all()]

    def list_project_ids_for_groups(self, group_ids, hints,
                                    inherited=False):
        return self._list_project_ids_for_actor(
            group_ids, hints, inherited, group_only=True)

    def list_domain_ids_for_groups(self, group_ids, inherited=False):
        if not group_ids:
            # If there's no groups then there will be no domains.
            return []

        group_sql_conditions = sqlalchemy.and_(
            RoleAssignment.type == AssignmentType.GROUP_DOMAIN,
            RoleAssignment.inherited == inherited,
            RoleAssignment.actor_id.in_(group_ids))

        with sql.transaction() as session:
            query = session.query(RoleAssignment.target_id).filter(
                group_sql_conditions).distinct()
        return [x.target_id for x in query.all()]

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
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
            if ref.inherited:
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

    def list_domains_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Domain)
                query = query.filter(Domain.id.in_(ids))
                domain_refs = query.all()
                return [domain_ref.to_dict() for domain_ref in domain_refs]

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
            session.delete(ref)

    def delete_project_assignments(self, project_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(target_id=project_id)
            q.delete(False)

    def delete_role_assignments(self, role_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(role_id=role_id)
            q.delete(False)

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
    attributes = ['id', 'name', 'domain_id', 'description', 'enabled',
                  'parent_id']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    parent_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class RoleAssignment(sql.ModelBase, sql.DictBase):
    __tablename__ = 'assignment'
    attributes = ['type', 'actor_id', 'target_id', 'role_id', 'inherited']
    # NOTE(henry-nash); Postgres requires a name to be defined for an Enum
    type = sql.Column(
        sql.Enum(AssignmentType.USER_PROJECT, AssignmentType.GROUP_PROJECT,
                 AssignmentType.USER_DOMAIN, AssignmentType.GROUP_DOMAIN,
                 name='type'),
        nullable=False)
    actor_id = sql.Column(sql.String(64), nullable=False, index=True)
    target_id = sql.Column(sql.String(64), nullable=False)
    role_id = sql.Column(sql.String(64), nullable=False)
    inherited = sql.Column(sql.Boolean, default=False, nullable=False)
    __table_args__ = (sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id',
                                               'role_id'), {})

    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        RoleAssignment doesn't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(six.iteritems(self))
