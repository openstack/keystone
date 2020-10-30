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

from keystone.assignment.backends import base
from keystone.common import sql
from keystone import exception
from keystone.i18n import _


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


class Assignment(base.AssignmentDriverBase):

    @classmethod
    def default_role_driver(cls):
        return 'sql'

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):

        assignment_type = AssignmentType.calculate_type(
            user_id, group_id, project_id, domain_id)
        try:
            with sql.session_for_write() as session:
                session.add(RoleAssignment(
                    type=assignment_type,
                    actor_id=user_id or group_id,
                    target_id=project_id or domain_id,
                    role_id=role_id,
                    inherited=inherited_to_projects))
        except sql.DBDuplicateEntry:  # nosec : The v3 grant APIs are silent if
            # the assignment already exists
            pass

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        with sql.session_for_read() as session:
            q = session.query(RoleAssignment.role_id)
            q = q.filter(RoleAssignment.actor_id == (user_id or group_id))
            q = q.filter(RoleAssignment.target_id == (project_id or domain_id))
            q = q.filter(RoleAssignment.inherited == inherited_to_projects)
            return [x.role_id for x in q.all()]

    def _build_grant_filter(self, session, role_id, user_id, group_id,
                            domain_id, project_id, inherited_to_projects):
        q = session.query(RoleAssignment)
        q = q.filter_by(actor_id=user_id or group_id)
        if domain_id:
            q = q.filter_by(target_id=domain_id).filter(
                (RoleAssignment.type == AssignmentType.USER_DOMAIN) |
                (RoleAssignment.type == AssignmentType.GROUP_DOMAIN))
        else:
            q = q.filter_by(target_id=project_id).filter(
                (RoleAssignment.type == AssignmentType.USER_PROJECT) |
                (RoleAssignment.type == AssignmentType.GROUP_PROJECT))
        q = q.filter_by(role_id=role_id)
        q = q.filter_by(inherited=inherited_to_projects)
        return q

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        with sql.session_for_read() as session:
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
        with sql.session_for_write() as session:
            q = self._build_grant_filter(
                session, role_id, user_id, group_id, domain_id, project_id,
                inherited_to_projects)
            if not q.delete(False):
                actor_id = user_id or group_id
                target_id = domain_id or project_id
                raise exception.RoleAssignmentNotFound(role_id=role_id,
                                                       actor_id=actor_id,
                                                       target_id=target_id)

    def add_role_to_user_and_project(self, user_id, project_id, role_id):
        try:
            with sql.session_for_write() as session:
                session.add(RoleAssignment(
                    type=AssignmentType.USER_PROJECT,
                    actor_id=user_id, target_id=project_id,
                    role_id=role_id, inherited=False))
        except sql.DBDuplicateEntry:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, project_id))
            raise exception.Conflict(type='role grant', details=msg)

    def remove_role_from_user_and_project(self, user_id, project_id, role_id):
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=user_id)
            q = q.filter_by(target_id=project_id)
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
        """Return a list of role assignment types based on provided entities.

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

        with sql.session_for_read() as session:
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
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(target_id=project_id).filter(
                RoleAssignment.type.in_((AssignmentType.USER_PROJECT,
                                         AssignmentType.GROUP_PROJECT))
            )
            q.delete(False)

    def delete_role_assignments(self, role_id):
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(role_id=role_id)
            q.delete(False)

        with sql.session_for_write() as session:
            q = session.query(SystemRoleAssignment)
            q = q.filter_by(role_id=role_id)
            q.delete(False)

    def delete_domain_assignments(self, domain_id):
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter(RoleAssignment.target_id == domain_id).filter(
                (RoleAssignment.type == AssignmentType.USER_DOMAIN) |
                (RoleAssignment.type == AssignmentType.GROUP_DOMAIN))
            q.delete(False)

    def delete_user_assignments(self, user_id):
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=user_id).filter(
                RoleAssignment.type.in_((AssignmentType.USER_PROJECT,
                                         AssignmentType.USER_DOMAIN))
            )
            q.delete(False)

    def delete_group_assignments(self, group_id):
        with sql.session_for_write() as session:
            q = session.query(RoleAssignment)
            q = q.filter_by(actor_id=group_id).filter(
                RoleAssignment.type.in_((AssignmentType.GROUP_PROJECT,
                                         AssignmentType.GROUP_DOMAIN))
            )
            q.delete(False)

    def create_system_grant(self, role_id, actor_id, target_id,
                            assignment_type, inherited):
        try:
            with sql.session_for_write() as session:
                session.add(
                    SystemRoleAssignment(
                        type=assignment_type,
                        actor_id=actor_id,
                        target_id=target_id,
                        role_id=role_id,
                        inherited=inherited
                    )
                )
        except sql.DBDuplicateEntry:  # nosec : The v3 grant APIs are silent if
            # the assignment already exists
            pass

    def list_system_grants(self, actor_id, target_id, assignment_type):
        with sql.session_for_read() as session:
            query = session.query(SystemRoleAssignment)
            if actor_id:
                query = query.filter_by(actor_id=actor_id)
            if target_id:
                query = query.filter_by(target_id=target_id)
            if assignment_type:
                query = query.filter_by(type=assignment_type)
            results = query.all()

        return [role.to_dict() for role in results]

    def list_system_grants_by_role(self, role_id):
        with sql.session_for_read() as session:
            query = session.query(SystemRoleAssignment)
            query = query.filter_by(role_id=role_id)
            return query.all()

    def check_system_grant(self, role_id, actor_id, target_id, inherited):
        with sql.session_for_read() as session:
            try:
                q = session.query(SystemRoleAssignment)
                q = q.filter_by(actor_id=actor_id)
                q = q.filter_by(target_id=target_id)
                q = q.filter_by(role_id=role_id)
                q = q.filter_by(inherited=inherited)
                q.one()
            except sql.NotFound:
                raise exception.RoleAssignmentNotFound(
                    role_id=role_id, actor_id=actor_id, target_id=target_id
                )

    def delete_system_grant(self, role_id, actor_id, target_id, inherited):
        with sql.session_for_write() as session:
            q = session.query(SystemRoleAssignment)
            q = q.filter_by(actor_id=actor_id)
            q = q.filter_by(target_id=target_id)
            q = q.filter_by(role_id=role_id)
            q = q.filter_by(inherited=inherited)
            if not q.delete(False):
                raise exception.RoleAssignmentNotFound(
                    role_id=role_id, actor_id=actor_id, target_id=target_id
                )


class RoleAssignment(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'assignment'
    attributes = ['type', 'actor_id', 'target_id', 'role_id', 'inherited']
    # NOTE(henry-nash): Postgres requires a name to be defined for an Enum
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
        """Override parent method with a simpler implementation.

        RoleAssignment doesn't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(self.items())


class SystemRoleAssignment(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'system_assignment'
    attributes = ['type', 'actor_id', 'target_id', 'role_id', 'inherited']
    type = sql.Column(sql.String(64), nullable=False)
    actor_id = sql.Column(sql.String(64), nullable=False)
    target_id = sql.Column(sql.String(64), nullable=False)
    role_id = sql.Column(sql.String(64), nullable=False)
    inherited = sql.Column(sql.Boolean, default=False, nullable=False)
    __table_args__ = (
        sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id', 'role_id',
                                 'inherited'),
        sql.Index('ix_system_actor_id', 'actor_id'),
    )

    def to_dict(self):
        """Override parent method with a simpler implementation.

        RoleAssignment doesn't have non-indexed 'extra' attributes, so the
        parent implementation is not applicable.
        """
        return dict(self.items())
