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

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
import six

from keystone import exception
from keystone.i18n import _LW


CONF = cfg.CONF
LOG = log.getLogger(__name__)


# The AssignmentDriverBase class is the set of driver methods from earlier
# drivers that we still support, that have not been removed or modified. This
# class is then used to created the augmented V8 and V9 version abstract driver
# classes, without having to duplicate a lot of abstract method signatures.
# If you remove a method from V9, then move the abstract methods from this Base
# class to the V8 class. Do not modify any of the method signatures in the Base
# class - changes should only be made in the V8 and subsequent classes.
@six.add_metaclass(abc.ABCMeta)
class AssignmentDriverBase(object):

    def _get_list_limit(self):
        return CONF.assignment.list_limit or CONF.list_limit

    @abc.abstractmethod
    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises keystone.exception.Conflict: If a duplicate role assignment
            exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

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


class AssignmentDriverV8(AssignmentDriverBase):
    """Removed or redefined methods from V8.

    Move the abstract methods of any methods removed or modified in later
    versions of the driver from AssignmentDriverBase to here. We maintain this
    so that legacy drivers, which will be a subclass of AssignmentDriverV8, can
    still reference them.

    """

    @abc.abstractmethod
    def list_user_ids_for_project(self, tenant_id):
        """List all user IDs with a role assignment in the specified project.

        :returns: a list of user_ids or an empty set.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_ids_for_user(self, user_id, group_ids, hints,
                                  inherited=False):
        """List all project ids associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether assignments marked as inherited should
                          be included.

        :returns: a list of project ids or an empty list.

        This method should not try and expand any inherited assignments,
        just report the projects that have the role for this user. The manager
        method is responsible for expanding out inherited assignments.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domain_ids_for_user(self, user_id, group_ids, hints,
                                 inherited=False):
        """List all domain ids associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether to return domain_ids that have inherited
                          assignments or not.

        :returns: a list of domain ids or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_ids_for_groups(self, group_ids, hints,
                                    inherited=False):
        """List project ids accessible to specified groups.

        :param group_ids: List of group ids.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether assignments marked as inherited should
                          be included.
        :returns: List of project ids accessible to specified groups.

        This method should not try and expand any inherited assignments,
        just report the projects that have the role for this group. The manager
        method is responsible for expanding out inherited assignments.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domain_ids_for_groups(self, group_ids, inherited=False):
        """List domain ids accessible to specified groups.

        :param group_ids: List of group ids.
        :param inherited: whether to return domain_ids that have inherited
                          assignments or not.
        :returns: List of domain ids accessible to specified groups.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_ids_for_groups_on_project(
            self, group_ids, project_id, project_domain_id, project_parents):
        """List the group role ids for a specific project.

        Supports the ``OS-INHERIT`` role inheritance from the project's domain
        if supported by the assignment driver.

        :param group_ids: list of group ids
        :type group_ids: list
        :param project_id: project identifier
        :type project_id: str
        :param project_domain_id: project's domain identifier
        :type project_domain_id: str
        :param project_parents: list of parent ids of this project
        :type project_parents: list
        :returns: list of role ids for the project
        :rtype: list
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_role_ids_for_groups_on_domain(self, group_ids, domain_id):
        """List the group role ids for a specific domain.

        :param group_ids: list of group ids
        :type group_ids: list
        :param domain_id: domain identifier
        :type domain_id: str
        :returns: list of role ids for the project
        :rtype: list
        """
        raise exception.NotImplemented()


class AssignmentDriverV9(AssignmentDriverBase):
    """New or redefined methods from V8.

    Add any new V9 abstract methods (or those with modified signatures) to
    this class.

    """

    @abc.abstractmethod
    def delete_domain_assignments(self, domain_id):
        """Delete all assignments for a domain."""
        raise exception.NotImplemented()


class V9AssignmentWrapperForV8Driver(AssignmentDriverV9):
    """Wrapper class to supported a V8 legacy driver.

    In order to support legacy drivers without having to make the manager code
    driver-version aware, we wrap legacy drivers so that they look like the
    latest version. For the various changes made in a new driver, here are the
    actions needed in this wrapper:

    Method removed from new driver - remove the call-through method from this
                                     class, since the manager will no longer be
                                     calling it.
    Method signature (or meaning) changed - wrap the old method in a new
                                            signature here, and munge the input
                                            and output parameters accordingly.
    New method added to new driver - add a method to implement the new
                                     functionality here if possible. If that is
                                     not possible, then return NotImplemented,
                                     since we do not guarantee to support new
                                     functionality with legacy drivers.

    """

    @versionutils.deprecated(
        as_of=versionutils.deprecated.MITAKA,
        what='keystone.assignment.AssignmentDriverV8',
        in_favor_of='keystone.assignment.AssignmentDriverV9',
        remove_in=+2)
    def __init__(self, wrapped_driver):
        self.driver = wrapped_driver

    def delete_domain_assignments(self, domain_id):
        """Delete all assignments for a domain."""
        msg = _LW('delete_domain_assignments method not found in custom '
                  'assignment driver. Domain assignments for domain (%s) to '
                  'users from other domains will not be removed. This was '
                  'added in V9 of the assignment driver.')
        LOG.warning(msg, domain_id)

    def default_role_driver(self):
        return self.driver.default_role_driver()

    def default_resource_driver(self):
        return self.driver.default_resource_driver()

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.driver.add_role_to_user_and_project(user_id, tenant_id, role_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        self.driver.remove_role_from_user_and_project(
            user_id, tenant_id, role_id)

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        self.driver.create_grant(
            role_id, user_id=user_id, group_id=group_id,
            domain_id=domain_id, project_id=project_id,
            inherited_to_projects=inherited_to_projects)

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        return self.driver.list_grant_role_ids(
            user_id=user_id, group_id=group_id,
            domain_id=domain_id, project_id=project_id,
            inherited_to_projects=inherited_to_projects)

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        self.driver.check_grant_role_id(
            role_id, user_id=user_id, group_id=group_id,
            domain_id=domain_id, project_id=project_id,
            inherited_to_projects=inherited_to_projects)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        self.driver.delete_grant(
            role_id, user_id=user_id, group_id=group_id,
            domain_id=domain_id, project_id=project_id,
            inherited_to_projects=inherited_to_projects)

    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):
        return self.driver.list_role_assignments(
            role_id=role_id,
            user_id=user_id, group_ids=group_ids,
            domain_id=domain_id, project_ids=project_ids,
            inherited_to_projects=inherited_to_projects)

    def delete_project_assignments(self, project_id):
        self.driver.delete_project_assignments(project_id)

    def delete_role_assignments(self, role_id):
        self.driver.delete_role_assignments(role_id)

    def delete_user_assignments(self, user_id):
        self.driver.delete_user_assignments(user_id)

    def delete_group_assignments(self, group_id):
        self.driver.delete_group_assignments(group_id)
