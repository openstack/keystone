# Copyright 2012 OpenStack Foundation
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

import abc

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


class AssignmentDriverBase(object, metaclass=abc.ABCMeta):

    def _get_list_limit(self):
        return CONF.assignment.list_limit or CONF.list_limit

    @abc.abstractmethod
    def add_role_to_user_and_project(self, user_id, project_id, role_id):
        """Add a role to a user within given project.

        :raises keystone.exception.Conflict: If a duplicate role assignment
            exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_role_from_user_and_project(self, user_id, project_id, role_id):
        """Remove a role from a user within given project.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    # assignment/grant crud

    @abc.abstractmethod
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Create a new assignment/grant.

        If the assignment is to a domain, then optionally it may be
        specified as inherited to owned projects (this requires
        the OS-INHERIT extension to be enabled).

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """List role ids for assignments/grants."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """Check an assignment/grant role id.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.
        :returns: None or raises an exception if grant not found

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Delete assignments/grants.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):
        """Return a list of role assignments for actors on targets.

        Available parameters represent values in which the returned role
        assignments attributes need to be filtered on.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_project_assignments(self, project_id):
        """Delete all assignments for a project.

        :raises keystone.exception.ProjectNotFound: If the project doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role_assignments(self, role_id):
        """Delete all assignments for a role."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user_assignments(self, user_id):
        """Delete all assignments for a user.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group_assignments(self, group_id):
        """Delete all assignments for a group.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_domain_assignments(self, domain_id):
        """Delete all assignments for a domain."""
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_system_grant(self, role_id, actor_id, target_id,
                            assignment_type, inherited):
        """Grant a user or group  a role on the system.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param assignment_type: a string describing the relationship of the
                                assignment
        :param inherited: a boolean denoting if the assignment is inherited or
                          not

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_system_grants(self, actor_id, target_id, assignment_type):
        """Return a list of all system assignments for a specific entity.

        :param actor_id: the unique ID of the actor
        :param target_id: the unique ID of the target
        :param assignment_type: the type of assignment to return

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_system_grants_by_role(self, role_id):
        """Return a list of system assignments associated to a role.

        :param role_id: the unique ID of the role to grant to the user

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_system_grant(self, role_id, actor_id, target_id, inherited):
        """Check if a user or group has a specific role on the system.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
                          not

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_system_grant(self, role_id, actor_id, target_id, inherited):
        """Remove a system assignment from a user or group.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
                          not

        """
        raise exception.NotImplemented()  # pragma: no cover
