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

from keystone import assignment
from keystone import clean
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

    def __init__(self, assignment_api=None):
        super(Manager, self).__init__(CONF.identity.driver)
        if assignment_api is None:
            assignment_api = assignment.Manager(self)
        self.assignment = assignment_api
        self.driver.assignment = assignment_api

    def create_user(self, user_id, user_ref):
        user = user_ref.copy()
        user['name'] = clean.user_name(user['name'])
        user.setdefault('enabled', True)
        user['enabled'] = clean.user_enabled(user['enabled'])
        return self.driver.create_user(user_id, user)

    def update_user(self, user_id, user_ref):
        user = user_ref.copy()
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        if 'enabled' in user:
            user['enabled'] = clean.user_enabled(user['enabled'])
        return self.driver.update_user(user_id, user)

    def create_group(self, group_id, group_ref):
        group = group_ref.copy()
        group.setdefault('description', '')
        return self.driver.create_group(group_id, group)

    def create_project(self, tenant_id, tenant_ref):
        tenant = tenant_ref.copy()
        tenant.setdefault('enabled', True)
        tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        tenant.setdefault('description', '')
        return self.assignment_api.create_project(tenant_id, tenant)

    def update_project(self, tenant_id, tenant_ref):
        tenant = tenant_ref.copy()
        if 'enabled' in tenant:
            tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        return self.assignment_api.update_project(tenant_id, tenant)

    def get_project_by_name(self, tenant_name, domain_id):
        return self.assignment.get_project_by_name(tenant_name, domain_id)

    def get_project(self, tenant_id):
        return self.assignment.get_project(tenant_id)

    def list_projects(self, domain_id=None):
        return self.assignment.list_projects(domain_id)

    def get_role(self, role_id):
        return self.assignment.get_role(role_id)

    def list_roles(self):
        return self.assignment.list_roles()

    def get_projects_for_user(self, user_id):
        return self.assignment.get_projects_for_user(user_id)

    def get_project_users(self, tenant_id):
        return self.assignment.get_project_users(tenant_id)

    def get_roles_for_user_and_project(self, user_id, tenant_id):
        return self.assignment.get_roles_for_user_and_project(user_id,
                                                              tenant_id)

    def get_roles_for_user_and_domain(self, user_id, domain_id):
        return (self.assignment.get_roles_for_user_and_domain
                (user_id, domain_id))

    def _subrole_id_to_dn(self, role_id, tenant_id):
        return self.assignment._subrole_id_to_dn(role_id, tenant_id)

    def add_role_to_user_and_project(self, user_id,
                                     tenant_id, role_id):
        return (self.assignment_api.add_role_to_user_and_project
                (user_id, tenant_id, role_id))

    def create_role(self, role_id, role):
        return self.assignment.create_role(role_id, role)

    def delete_role(self, role_id):
        return self.assignment.delete_role(role_id)

    def delete_project(self, tenant_id):
        return self.assignment.delete_project(tenant_id)

    def remove_role_from_user_and_project(self, user_id,
                                          tenant_id, role_id):
        return (self.assignment_api.remove_role_from_user_and_project
                (user_id, tenant_id, role_id))

    def update_role(self, role_id, role):
        return self.assignment.update_role(role_id, role)

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment.create_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        return (self.assignment.list_grants
                (user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        return (self.assignment.get_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment.delete_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    def create_domain(self, domain_id, domain):
        return self.assignment.create_domain(domain_id, domain)

    def get_domain_by_name(self, domain_name):
        return self.assignment.get_domain_by_name(domain_name)

    def get_domain(self, domain_id):
        return self.assignment.get_domain(domain_id)

    def update_domain(self, domain_id, domain):
        return self.assignment.update_domain(domain_id, domain)

    def delete_domain(self, domain_id):
        return self.assignment.delete_domain(domain_id)

    def list_domains(self):
        return self.assignment.list_domains()

    def list_user_projects(self, user_id):
        return self.assignment.list_user_projects(user_id)

    def add_user_to_project(self, tenant_id, user_id):
        return self.assignment.add_user_to_project(tenant_id, user_id)

    def remove_user_from_project(self, tenant_id, user_id):
        return self.assignment.remove_user_from_project(tenant_id, user_id)

    def list_role_assignments(self):
        return self.assignment_api.list_role_assignments()


class Driver(object):
    """Interface description for an Identity driver."""
    def authenticate_user(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
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

    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

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

    #end of identity

    # Assignments
