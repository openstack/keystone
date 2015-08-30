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

from oslo_config import cfg
from oslo_log import log
import sqlalchemy
from sqlalchemy.sql.expression import false

from keystone import assignment as keystone_assignment
from keystone.common import sql
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class AssignmentType(object):
    USER_PROJECT = 'UserProject'
    GROUP_PROJECT = 'GroupProject'
    USER_DOMAIN = 'UserDomain'
    GROUP_DOMAIN = 'GroupDomain'

    @classmethod
    def calculate_type(cls, user_id, group_id, project_id, domain_id):
        if user_id:
            if project_id:
                return cls.USER_PROJECT
            if domain_id:
                return cls.USER_DOMAIN
        if group_id:
            if project_id:
                return cls.GROUP_PROJECT
            if domain_id:
                return cls.GROUP_DOMAIN
        # Invalid parameters combination
        raise exception.AssignmentTypeCalculationError(**locals())


class Assignment(keystone_assignment.AssignmentDriverV8):

    def default_role_driver(self):
        return 'sql'

    def default_resource_driver(self):
        return 'sql'

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

        assignment_type = AssignmentType.calculate_type(
            user_id, group_id, project_id, domain_id)
        try:
            with sql.transaction() as session:
                session.add(RoleAssignment(
                    type=assignment_type,
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
                actor_id = user_id or group_id
                target_id = domain_id or project_id
                raise exception.RoleAssignmentNotFound(role_id=role_id,
                                                       actor_id=actor_id,
                                                       target_id=target_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        with sql.transaction() as session:
            q = self._build_grant_filter(
                session, role_id, user_id, group_id, domain_id, project_id,
                inherited_to_projects)
            if not q.delete(False):
                actor_id = user_id or group_id
                target_id = domain_id or project_id
                raise exception.RoleAssignmentNotFound(role_id=role_id,
                                                       actor_id=actor_id,
                                                       target_id=target_id)

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

    def _get_user_assignment_types(self):
        return [AssignmentType.USER_PROJECT, AssignmentType.USER_DOMAIN]

    def _get_group_assignment_types(self):
        return [AssignmentType.GROUP_PROJECT, AssignmentType.GROUP_DOMAIN]

    def _get_project_assignment_types(self):
        return [AssignmentType.USER_PROJECT, AssignmentType.GROUP_PROJECT]

    def _get_domain_assignment_types(self):
        return [AssignmentType.USER_DOMAIN, AssignmentType.GROUP_DOMAIN]

    def _get_assignment_types(self, user, group, project, domain):
        """Returns a list of role assignment types based on provided entities

        If one of user or group (the "actor") as well as one of project or
        domain (the "target") are provided, the list will contain the role
        assignment type for that specific pair of actor and target.

        If only an actor or target is provided, the list will contain the
        role assignment types that satisfy the specified entity.

        For example, if user and project are provided, the return will be:

            [AssignmentType.USER_PROJECT]

        However, if only user was provided, the return would be:

            [AssignmentType.USER_PROJECT, AssignmentType.USER_DOMAIN]

        It is not expected that user and group (or project and domain) are
        specified - but if they are, the most fine-grained value will be
        chosen (i.e. user over group, project over domain).

        """
        actor_types = []
        if user:
            actor_types = self._get_user_assignment_types()
        elif group:
            actor_types = self._get_group_assignment_types()

        target_types = []
        if project:
            target_types = self._get_project_assignment_types()
        elif domain:
            target_types = self._get_domain_assignment_types()

        if actor_types and target_types:
            return list(set(actor_types).intersection(target_types))

        return actor_types or target_types

    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):

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
            assignment_types = self._get_assignment_types(
                user_id, group_ids, project_ids, domain_id)

            targets = None
            if project_ids:
                targets = project_ids
            elif domain_id:
                targets = [domain_id]

            actors = None
            if group_ids:
                actors = group_ids
            elif user_id:
                actors = [user_id]

            query = session.query(RoleAssignment)

            if role_id:
                query = query.filter_by(role_id=role_id)
            if actors:
                query = query.filter(RoleAssignment.actor_id.in_(actors))
            if targets:
                query = query.filter(RoleAssignment.target_id.in_(targets))
            if assignment_types:
                query = query.filter(RoleAssignment.type.in_(assignment_types))
            if inherited_to_projects is not None:
                query = query.filter_by(inherited=inherited_to_projects)

            return [denormalize_role(ref) for ref in query.all()]

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

    def delete_user_assignments(self, user_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=user_id)
            q.delete(False)

    def delete_group_assignments(self, group_id):
        with sql.transaction() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=group_id)
            q.delete(False)


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
    role_id = sql.Column(sql.String(64), nullable=False)
    inherited = sql.Column(sql.Boolean, default=False, nullable=False)
    __table_args__ = (
        sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id', 'role_id',
                                 'inherited'),
        sql.Index('ix_actor_id', 'actor_id'),
    )

    def to_dict(self):
        """Override parent to_dict() method with a simpler implementation.

        RoleAssignment doesn't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(self.items())
