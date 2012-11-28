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

import urllib
import urlparse
import uuid

from keystone.common import controller
from keystone.common import logging
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception


CONF = config.CONF

LOG = logging.getLogger(__name__)


def filter_user(user_ref):
    """Filter out private items in a user dict ('password' and 'tenants')

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)


class Driver(object):
    """Interface description for an Identity driver."""

    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate a given user, tenant and password.

        :returns: (user_ref, tenant_ref, metadata_ref)
        :raises: AssertionError

        """
        raise exception.NotImplemented()

    def get_tenant(self, tenant_id):
        """Get a tenant by id.

        :returns: tenant_ref
        :raises: keystone.exception.TenantNotFound

        """
        raise exception.NotImplemented()

    def get_tenant_by_name(self, tenant_name):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.TenantNotFound

        """
        raise exception.NotImplemented()

    def get_user_by_name(self, user_name):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def add_user_to_tenant(self, tenant_id, user_id):
        """Add user to a tenant without an explicit role relationship.

        :raises: keystone.exception.TenantNotFound,
                 keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def remove_user_from_tenant(self, tenant_id, user_id):
        """Remove user from a tenant without an explicit role relationship.

        :raises: keystone.exception.TenantNotFound,
                 keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def get_all_tenants(self):
        """FIXME(dolph): Lists all tenants in the system? I'm not sure how this
                         is different from get_tenants, why get_tenants isn't
                         documented as part of the driver, or why it's called
                         get_tenants instead of list_tenants (i.e. list_roles
                         and list_users)...

        :returns: a list of ... FIXME(dolph): tenant_refs or tenant_id's?

        """
        raise exception.NotImplemented()

    def get_tenant_users(self, tenant_id):
        """FIXME(dolph): Lists all users with a relationship to the specified
                         tenant?

        :returns: a list of ... FIXME(dolph): user_refs or user_id's?
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def get_tenants_for_user(self, user_id):
        """Get the tenants associated with a given user.

        :returns: a list of tenant_id's.
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        """Get the roles associated with a user within given tenant.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.TenantNotFound

        """
        raise exception.NotImplemented()

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.TenantNotFound,
                 keystone.exception.RoleNotFound
        """
        raise exception.NotImplemented()

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.TenantNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    # tenant crud
    def create_tenant(self, tenant_id, tenant):
        """Creates a new tenant.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def update_tenant(self, tenant_id, tenant):
        """Updates an existing tenant.

        :raises: keystone.exception.TenantNotFound, keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_tenant(self, tenant_id):
        """Deletes an existing tenant.

        :raises: keystone.exception.TenantNotFound

        """
        raise exception.NotImplemented()

    # metadata crud
    def get_metadata(self, user_id, tenant_id):
        raise exception.NotImplemented()

    def create_metadata(self, user_id, tenant_id, metadata):
        raise exception.NotImplemented()

    def update_metadata(self, user_id, tenant_id, metadata):
        raise exception.NotImplemented()

    def delete_metadata(self, user_id, tenant_id):
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

        :returns: user_ref
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

    def get_project(self):
        """Get a project by ID.

        :returns: user_ref
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

    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    # credential crud

    def create_credential(self, credential_id, credential):
        """Creates a new credential.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_credentials(self):
        """List all credentials in the system.

        :returns: a list of credential_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_credential(self, credential_id):
        """Get a credential by ID.

        :returns: credential_ref
        :raises: keystone.exception.CredentialNotFound

        """
        raise exception.NotImplemented()

    def update_credential(self, credential_id, credential):
        """Updates an existing credential.

        :raises: keystone.exception.CredentialNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_credential(self, credential_id):
        """Deletes an existing credential.

        :raises: keystone.exception.CredentialNotFound

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
