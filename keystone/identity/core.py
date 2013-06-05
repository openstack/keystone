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

"""Main entry point into the Identity service."""

from keystone.common import dependency
from keystone.common import logging
from keystone.common import manager
from keystone import config
from keystone import exception


CONF = config.CONF

LOG = logging.getLogger(__name__)


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        user_ref.pop('groups', None)
        user_ref.pop('domains', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


@dependency.provider('identity_api')
class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)

    def authenticate(self, context, user_id=None,
                     tenant_id=None, password=None):
        """Authenticate a given user and password and
        authorize them for a tenant.
        :returns: (user_ref, tenant_ref, metadata_ref)
        :raises: AssertionError
        """
        user_ref = self.driver.authenticate_user(user_id, password)
        return self.driver.authorize_for_project(user_ref, tenant_id)

    def create_user(self, context, user_id, user_ref):
        user = user_ref.copy()
        if 'enabled' not in user:
            user['enabled'] = True
        return self.driver.create_user(user_id, user)

    def create_group(self, context, group_id, group_ref):
        group = group_ref.copy()
        if 'description' not in group:
            group['description'] = ''
        return self.driver.create_group(group_id, group)

    def create_project(self, context, tenant_id, tenant_ref):
        tenant = tenant_ref.copy()
        if 'enabled' not in tenant:
            tenant['enabled'] = True
        if 'description' not in tenant:
            tenant['description'] = ''
        return self.driver.create_project(tenant_id, tenant)


class Driver(object):
    """Interface description for an Identity driver."""

    def authenticate_user(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
        """
        raise exception.NotImplemented()

    def authorize_for_project(self, tenant_id, user_ref):
        """Authenticate a given user for a tenant.
        :returns: (user_ref, tenant_ref, metadata_ref)
        :raises: AssertionError
        """
        raise exception.NotImplemented()

    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def add_user_to_project(self, tenant_id, user_id):
        """Add user to a tenant by creating a default role relationship.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        self.add_role_to_user_and_project(user_id,
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

    def get_roles_for_user_and_project(self, user_id, tenant_id):
        """Get the roles associated with a user within given tenant.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def get_roles_for_user_and_domain(self, user_id, domain_id):
        """Get the roles associated with a user within given domain.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound

        """

        def update_metadata_for_group_domain_roles(self, metadata_ref,
                                                   user_id, domain_id):
            group_refs = self.list_groups_for_user(user_id=user_id)
            for x in group_refs:
                try:
                    metadata_ref.update(
                        self.get_metadata(group_id=x['id'],
                                          domain_id=domain_id))
                except exception.MetadataNotFound:
                    # no group grant, skip
                    pass

        def update_metadata_for_user_domain_roles(self, metadata_ref,
                                                  user_id, domain_id):
            try:
                metadata_ref.update(self.get_metadata(user_id=user_id,
                                                      domain_id=domain_id))
            except exception.MetadataNotFound:
                pass

        self.get_user(user_id)
        self.get_domain(domain_id)
        metadata_ref = {}
        update_metadata_for_user_domain_roles(self, metadata_ref,
                                              user_id, domain_id)
        update_metadata_for_group_domain_roles(self, metadata_ref,
                                               user_id, domain_id)
        return list(set(metadata_ref.get('roles', [])))

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

    # metadata crud
    def get_metadata(self, user_id=None, tenant_id=None,
                     domain_id=None, group_id=None):
        """Gets the metadata for the specified user/group on project/domain.

        :raises: keystone.exception.MetadataNotFound
        :returns: metadata

        """
        raise exception.NotImplemented()

    def create_metadata(self, user_id, tenant_id, metadata,
                        domain_id=None, group_id=None):
        """Creates the metadata for the specified user/group on project/domain.

        :returns: metadata created

        """
        raise exception.NotImplemented()

    def update_metadata(self, user_id, tenant_id, metadata,
                        domain_id=None, group_id=None):
        """Updates the metadata for the specified user/group on project/domain.

        :returns: metadata updated

        """
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

    # user crud

    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_users(self):
        """List all users in the system.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()

    def list_users_in_group(self, group_id):
        """List all users in a group.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def add_user_to_group(self, user_id, group_id):
        """Adds a user to a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    def check_user_in_group(self, user_id, group_id):
        """Checks if a user is a member of a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    def remove_user_from_group(self, user_id, group_id):
        """Removes a user from a group.

        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()

    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

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

    # group crud

    def create_group(self, group_id, group):
        """Creates a new group.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_groups(self):
        """List all groups in the system.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()

    def list_groups_for_user(self, user_id):
        """List all groups a user is in

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_group(self, group_id):
        """Get a group by ID.

        :returns: group_ref
        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    def update_group(self, group_id, group):
        """Updates an existing group.

        :raises: keystone.exceptionGroupNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_group(self, group_id):
        """Deletes an existing group.

        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()
