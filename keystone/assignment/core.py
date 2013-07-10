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

"""Main entry point into the assignment service."""

from keystone.common import dependency
from keystone.common import logging
from keystone.common import manager
from keystone import config
from keystone import exception


CONF = config.CONF
LOG = logging.getLogger(__name__)


@dependency.provider('assignment_api')
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.
    assignment.Manager() and identity.Manager() have a circular dependency.
    The late import works around this.  THe if block prevents creation of the
    api object by both managers.
    """

    def __init__(self, identity_api=None):
        if identity_api is None:
            from keystone import identity
            identity_api = identity.Manager(self)

        assignment_driver = CONF.assignment.driver
        if assignment_driver is None:
            assignment_driver = identity_api.default_assignment_driver()
        super(Manager, self).__init__(assignment_driver)
        self.driver.identity_api = identity_api
        self.identity_api = identity_api
        self.identity_api.assignment_api = self

    def get_roles_for_user_and_project(self, user_id, tenant_id):
        def _get_group_project_roles(user_id, tenant_id):
            role_list = []
            group_refs = (self.identity_api.list_groups_for_user
                          (user_id=user_id))
            for x in group_refs:
                try:
                    metadata_ref = self._get_metadata(group_id=x['id'],
                                                      tenant_id=tenant_id)
                    role_list += metadata_ref.get('roles', [])
                except exception.MetadataNotFound:
                    # no group grant, skip
                    pass
            return role_list

        def _get_user_project_roles(user_id, tenant_id):
            metadata_ref = {}
            try:
                metadata_ref = self._get_metadata(user_id=user_id,
                                                  tenant_id=tenant_id)
            except exception.MetadataNotFound:
                pass
            return metadata_ref.get('roles', [])

        self.identity_api.get_user(user_id)
        self.get_project(tenant_id)
        user_role_list = _get_user_project_roles(user_id, tenant_id)
        group_role_list = _get_group_project_roles(user_id, tenant_id)
        # Use set() to process the list to remove any duplicates
        return list(set(user_role_list + group_role_list))

    def get_roles_for_user_and_domain(self, user_id, domain_id):
        """Get the roles associated with a user within given domain.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.DomainNotFound

        """

        def _get_group_domain_roles(user_id, domain_id):
            role_list = []
            group_refs = (self.identity_api.
                          list_groups_for_user(user_id=user_id))
            for x in group_refs:
                try:
                    metadata_ref = self._get_metadata(group_id=x['id'],
                                                      domain_id=domain_id)
                    role_list += metadata_ref.get('roles', [])
                except (exception.MetadataNotFound, exception.NotImplemented):
                    # MetadataNotFound implies no group grant, so skip.
                    # Ignore NotImplemented since not all backends support
                    # domains.                    pass
                    pass
            return role_list

        def _get_user_domain_roles(user_id, domain_id):
            metadata_ref = {}
            try:
                metadata_ref = self._get_metadata(user_id=user_id,
                                                  domain_id=domain_id)
            except (exception.MetadataNotFound, exception.NotImplemented):
                # MetadataNotFound implies no user grants.
                # Ignore NotImplemented since not all backends support
                # domains
                pass
            return metadata_ref.get('roles', [])

        self.identity_api.get_user(user_id)
        self.get_domain(domain_id)
        user_role_list = _get_user_domain_roles(user_id, domain_id)
        group_role_list = _get_group_domain_roles(user_id, domain_id)
        # Use set() to process the list to remove any duplicates
        return list(set(user_role_list + group_role_list))

    def add_user_to_project(self, tenant_id, user_id):
        """Add user to a tenant by creating a default role relationship.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        self.driver.add_role_to_user_and_project(user_id,
                                                 tenant_id,
                                                 config.CONF.member_role_id)

    def remove_user_from_project(self, tenant_id, user_id):
        """Remove user from a tenant

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        roles = self.get_roles_for_user_and_project(user_id, tenant_id)
        if not roles:
            raise exception.NotFound(tenant_id)
        for role_id in roles:
            self.remove_role_from_user_and_project(user_id, tenant_id, role_id)


class Driver(object):

    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def get_project_users(self, tenant_id):
        """Lists all users with a relationship to the specified project.

        :returns: a list of user_refs or an empty set.
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def get_projects_for_user(self, user_id):
        """Get the tenants associated with a given user.

        :returns: a list of tenant_id's.
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound
        """
        raise exception.NotImplemented()

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    # assignment/grant crud

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):
        """Creates a new assignment/grant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def list_role_assignments(self):

        raise exception.NotImplemented()

    # domain crud
    def create_domain(self, domain_id, domain):
        """Creates a new domain.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_domains(self):
        """List all domains in the system.

        :returns: a list of domain_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_domain(self, domain_id):
        """Get a domain by ID.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    def get_domain_by_name(self, domain_name):
        """Get a domain by name.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    def update_domain(self, domain_id, domain):
        """Updates an existing domain.

        :raises: keystone.exception.DomainNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_domain(self, domain_id):
        """Deletes an existing domain.

        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    # project crud
    def create_project(self, project_id, project):
        """Creates a new project.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_projects(self):
        """List all projects in the system.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    def list_user_projects(self, user_id):
        """List all projects associated with a given user.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_project(self, project_id):
        """Get a project by ID.

        :returns: project_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def update_project(self, project_id, project):
        """Updates an existing project.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_project(self, project_id):
        """Deletes an existing project.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    """Interface description for an assignment driver."""
    # role crud

    def create_role(self, role_id, role):
        """Creates a new role.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_roles(self):
        """List all roles in the system.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def update_role(self, role_id, role):
        """Updates an existing role.

        :raises: keystone.exception.RoleNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_role(self, role_id):
        """Deletes an existing role.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

#TODO(ayoung): determine what else these two functions raise
    def delete_user(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def delete_group(self, group_id):
        """Deletes all assignments for a group.

        :raises: keystone.exception.RoleNotFound

        """
