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

from keystone.common import logging
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import policy
from keystone import token


CONF = config.CONF

LOG = logging.getLogger(__name__)


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

    def get_user(self, user_id):
        """Get a user by id.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def get_user_by_name(self, user_name):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    def get_role(self, role_id):
        """Get a role by id.

        :returns: role_ref
        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def list_users(self):
        """List all users in the system.

        NOTE(termie): I'd prefer if this listed only the users for a given
                      tenant.

        :returns: a list of user_refs or an empty list

        """
        raise exception.NotImplemented()

    def list_roles(self):
        """List all roles in the system.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()

    # NOTE(termie): seven calls below should probably be exposed by the api
    #               more clearly when the api redesign happens
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

    # user crud
    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound, keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

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

    # role crud
    def create_role(self, role_id, role):
        """Creates a new role.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def update_role(self, role_id, role):
        """Updates an existing role.

        :raises: keystone.exception.RoleNotFound, keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_role(self, role_id):
        """Deletes an existing role.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()


class PublicRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        tenant_controller = TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
                       conditions=dict(method=['GET']))


class AdminRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Tenant Operations
        tenant_controller = TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_all_tenants',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants/{tenant_id}',
                       controller=tenant_controller,
                       action='get_tenant',
                       conditions=dict(method=['GET']))

        # User Operations
        user_controller = UserController()
        mapper.connect('/users/{user_id}',
                       controller=user_controller,
                       action='get_user',
                       conditions=dict(method=['GET']))

        # Role Operations
        roles_controller = RoleController()
        mapper.connect('/tenants/{tenant_id}/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))


class TenantController(wsgi.Application):
    def __init__(self):
        self.identity_api = Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(TenantController, self).__init__()

    def get_all_tenants(self, context, **kw):
        """Gets a list of all tenants for an admin user."""
        self.assert_admin(context)
        tenant_refs = self.identity_api.get_tenants(context)
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_tenant_list(tenant_refs, **params)

    def get_tenants_for_token(self, context, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        try:
            token_ref = self.token_api.get_token(context=context,
                                                 token_id=context['token_id'])
        except exception.NotFound:
            LOG.warning("Authentication failed. Could not find token " +
                        str(context['token_id']))
            raise exception.Unauthorized()

        user_ref = token_ref['user']
        tenant_ids = self.identity_api.get_tenants_for_user(
            context, user_ref['id'])
        tenant_refs = []
        for tenant_id in tenant_ids:
            tenant_refs.append(self.identity_api.get_tenant(
                context=context,
                tenant_id=tenant_id))
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self._format_tenant_list(tenant_refs, **params)

    def get_tenant(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        return {'tenant': self.identity_api.get_tenant(context, tenant_id)}

    # CRUD Extension
    def create_tenant(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if not 'name' in tenant_ref or not tenant_ref['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.identity_api.create_tenant(
            context, tenant_ref['id'], tenant_ref)
        return {'tenant': tenant}

    def update_tenant(self, context, tenant_id, tenant):
        self.assert_admin(context)
        tenant_ref = self.identity_api.update_tenant(
            context, tenant_id, tenant)
        return {'tenant': tenant_ref}

    def delete_tenant(self, context, tenant_id):
        self.assert_admin(context)
        self.identity_api.delete_tenant(context, tenant_id)

    def get_tenant_users(self, context, tenant_id, **kw):
        self.assert_admin(context)
        user_refs = self.identity_api.get_tenant_users(context, tenant_id)
        return {'users': user_refs}

    def _format_tenant_list(self, tenant_refs, **kwargs):
        marker = kwargs.get('marker')
        first_index = 0
        if marker is not None:
            for (marker_index, tenant) in enumerate(tenant_refs):
                if tenant['id'] == marker:
                    # we start pagination after the marker
                    first_index = marker_index + 1
                    break
            else:
                msg = 'Marker could not be found'
                raise exception.ValidationError(message=msg)

        limit = kwargs.get('limit')
        last_index = None
        if limit is not None:
            try:
                limit = int(limit)
                if limit < 0:
                    raise AssertionError()
            except (ValueError, AssertionError):
                msg = 'Invalid limit value'
                raise exception.ValidationError(message=msg)
            last_index = first_index + limit

        tenant_refs = tenant_refs[first_index:last_index]

        for x in tenant_refs:
            if 'enabled' not in x:
                x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


class UserController(wsgi.Application):
    def __init__(self):
        self.identity_api = Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(UserController, self).__init__()

    def get_user(self, context, user_id):
        self.assert_admin(context)
        return {'user': self.identity_api.get_user(context, user_id)}

    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        self.assert_admin(context)
        return {'users': self.identity_api.list_users(context)}

    # CRUD extension
    def create_user(self, context, user):
        user = self._normalize_dict(user)
        self.assert_admin(context)

        if not 'name' in user or not user['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        tenant_id = user.get('tenantId', None)
        if (tenant_id is not None
                and self.identity_api.get_tenant(context, tenant_id) is None):
            raise exception.TenantNotFound(tenant_id=tenant_id)
        user_id = uuid.uuid4().hex
        user_ref = user.copy()
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.create_user(
            context, user_id, user_ref)
        if tenant_id:
            self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return {'user': new_user_ref}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)
        user_ref = self.identity_api.update_user(context, user_id, user)

        # If the password was changed or the user was disabled we clear tokens
        if user.get('password') or not user.get('enabled', True):
            try:
                for token_id in self.token_api.list_tokens(context, user_id):
                    self.token_api.delete_token(context, token_id)
            except exception.NotImplemented:
                # The users status has been changed but tokens remain valid for
                # backends that can't list tokens for users
                LOG.warning('User %s status has changed, but existing tokens '
                            'remain valid' % user_id)
        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        self.identity_api.delete_user(context, user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def update_user_tenant(self, context, user_id, user):
        """Update the default tenant."""
        self.assert_admin(context)
        # ensure that we're a member of that tenant
        tenant_id = user.get('tenantId')
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return self.update_user(context, user_id, user)


class RoleController(wsgi.Application):
    def __init__(self):
        self.identity_api = Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(RoleController, self).__init__()

    # COMPAT(essex-3)
    def get_user_roles(self, context, user_id, tenant_id=None):
        """Get the roles for a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant ID required')

        roles = self.identity_api.get_roles_for_user_and_tenant(
            context, user_id, tenant_id)
        return {'roles': [self.identity_api.get_role(context, x)
                          for x in roles]}

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        return {'role': self.identity_api.get_role(context, role_id)}

    def create_role(self, context, role):
        role = self._normalize_dict(role)
        self.assert_admin(context)

        if not 'name' in role or not role['name']:
            msg = 'Name field is required and cannot be empty'
            raise exception.ValidationError(message=msg)

        role_id = uuid.uuid4().hex
        role['id'] = role_id
        role_ref = self.identity_api.create_role(context, role_id, role)
        return {'role': role_ref}

    def delete_role(self, context, role_id):
        self.assert_admin(context)
        self.identity_api.delete_role(context, role_id)

    def get_roles(self, context):
        self.assert_admin(context)
        return {'roles': self.identity_api.list_roles(context)}

    def add_role_to_user(self, context, user_id, role_id, tenant_id=None):
        """Add a role to a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant_id required')

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        self.identity_api.add_role_to_user_and_tenant(
            context, user_id, tenant_id, role_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

        role_ref = self.identity_api.get_role(context, role_id)
        return {'role': role_ref}

    def remove_role_from_user(self, context, user_id, role_id, tenant_id=None):
        """Remove a role from a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant_id required')

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant, so we must follow up on that
        self.identity_api.remove_role_from_user_and_tenant(
            context, user_id, tenant_id, role_id)
        roles = self.identity_api.get_roles_for_user_and_tenant(
            context, user_id, tenant_id)
        if not roles:
            self.identity_api.remove_user_from_tenant(
                context, tenant_id, user_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

    # COMPAT(diablo): CRUD extension
    def get_role_refs(self, context, user_id):
        """Ultimate hack to get around having to make role_refs first-class.

        This will basically iterate over the various roles the user has in
        all tenants the user is a member of and create fake role_refs where
        the id encodes the user-tenant-role information so we can look
        up the appropriate data when we need to delete them.

        """
        self.assert_admin(context)
        # Ensure user exists by getting it first.
        self.identity_api.get_user(context, user_id)
        tenant_ids = self.identity_api.get_tenants_for_user(context, user_id)
        o = []
        for tenant_id in tenant_ids:
            role_ids = self.identity_api.get_roles_for_user_and_tenant(
                context, user_id, tenant_id)
            for role_id in role_ids:
                ref = {'roleId': role_id,
                       'tenantId': tenant_id,
                       'userId': user_id}
                ref['id'] = urllib.urlencode(ref)
                o.append(ref)
        return {'roles': o}

    # COMPAT(diablo): CRUD extension
    def create_role_ref(self, context, user_id, role):
        """This is actually used for adding a user to a tenant.

        In the legacy data model adding a user to a tenant required setting
        a role.

        """
        self.assert_admin(context)
        # TODO(termie): for now we're ignoring the actual role
        tenant_id = role.get('tenantId')
        role_id = role.get('roleId')
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        self.identity_api.add_role_to_user_and_tenant(
            context, user_id, tenant_id, role_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)

        role_ref = self.identity_api.get_role(context, role_id)
        return {'role': role_ref}

    # COMPAT(diablo): CRUD extension
    def delete_role_ref(self, context, user_id, role_ref_id):
        """This is actually used for deleting a user from a tenant.

        In the legacy data model removing a user from a tenant required
        deleting a role.

        To emulate this, we encode the tenant and role in the role_ref_id,
        and if this happens to be the last role for the user-tenant pair,
        we remove the user from the tenant.

        """
        self.assert_admin(context)
        # TODO(termie): for now we're ignoring the actual role
        role_ref_ref = urlparse.parse_qs(role_ref_id)
        tenant_id = role_ref_ref.get('tenantId')[0]
        role_id = role_ref_ref.get('roleId')[0]
        self.identity_api.remove_role_from_user_and_tenant(
            context, user_id, tenant_id, role_id)
        roles = self.identity_api.get_roles_for_user_and_tenant(
            context, user_id, tenant_id)
        if not roles:
            self.identity_api.remove_user_from_tenant(
                context, tenant_id, user_id)
        self.token_api.revoke_tokens(context, user_id, tenant_id)
