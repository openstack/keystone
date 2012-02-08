# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the Identity service."""

import uuid
import urllib
import urlparse

import webob.exc

from keystone import catalog
from keystone import config
from keystone import exception
from keystone import policy
from keystone import token
from keystone.common import manager
from keystone.common import wsgi


CONF = config.CONF


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

        Returns: (user, tenant, metadata).

        """
        raise NotImplementedError()

    def get_tenant(self, tenant_id):
        """Get a tenant by id.

        Returns: tenant_ref or None.

        """
        raise NotImplementedError()

    def get_tenant_by_name(self, tenant_name):
        """Get a tenant by name.

        Returns: tenant_ref or None.

        """
        raise NotImplementedError()

    def get_user(self, user_id):
        """Get a user by id.

        Returns: user_ref or None.

        """
        raise NotImplementedError()

    def get_user_by_name(self, user_name):
        """Get a user by name.

        Returns: user_ref or None.

        """
        raise NotImplementedError()

    def get_role(self, role_id):
        """Get a role by id.

        Returns: role_ref or None.

        """
        raise NotImplementedError()

    def list_users(self):
        """List all users in the system.

        NOTE(termie): I'd prefer if this listed only the users for a given
                      tenant.

        Returns: a list of user_refs or an empty list.

        """
        raise NotImplementedError()

    def list_roles(self):
        """List all roles in the system.

        Returns: a list of role_refs or an empty list.

        """
        raise NotImplementedError()

    # NOTE(termie): six calls below should probably be exposed by the api
    #               more clearly when the api redesign happens
    def add_user_to_tenant(self, tenant_id, user_id):
        raise NotImplementedError()

    def remove_user_from_tenant(self, tenant_id, user_id):
        raise NotImplementedError()

    def get_tenants_for_user(self, user_id):
        """Get the tenants associated with a given user.

        Returns: a list of tenant ids.

        """
        raise NotImplementedError()

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        """Get the roles associated with a user within given tenant.

        Returns: a list of role ids.

        """
        raise NotImplementedError()

    def add_role_for_user_and_tenant(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant."""
        raise NotImplementedError()

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant."""
        raise NotImplementedError()

    # user crud
    def create_user(self, user_id, user):
        raise NotImplementedError()

    def update_user(self, user_id, user):
        raise NotImplementedError()

    def delete_user(self, user_id):
        raise NotImplementedError()

    # tenant crud
    def create_tenant(self, tenant_id, tenant):
        raise NotImplementedError()

    def update_tenant(self, tenant_id, tenant):
        raise NotImplementedError()

    def delete_tenant(self, tenant_id, tenant):
        raise NotImplementedError()

    # metadata crud
    def create_metadata(self, user_id, tenant_id, metadata):
        raise NotImplementedError()

    def update_metadata(self, user_id, tenant_id, metadata):
        raise NotImplementedError()

    def delete_metadata(self, user_id, tenant_id, metadata):
        raise NotImplementedError()

    # role crud
    def create_role(self, role_id, role):
        raise NotImplementedError()

    def update_role(self, role_id, role):
        raise NotImplementedError()

    def delete_role(self, role_id):
        raise NotImplementedError()


class PublicRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        tenant_controller = TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
                       conditions=dict(methods=['GET']))


class AdminRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Tenant Operations
        tenant_controller = TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
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
                       controller=user_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))


class TenantController(wsgi.Application):
    def __init__(self):
        self.identity_api = Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(TenantController, self).__init__()

    def get_tenants_for_token(self, context, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        token_ref = self.token_api.get_token(context=context,
                                             token_id=context['token_id'])

        if token_ref is None:
            raise exception.Unauthorized()

        user_ref = token_ref['user']
        tenant_ids = self.identity_api.get_tenants_for_user(
                context, user_ref['id'])
        tenant_refs = []
        for tenant_id in tenant_ids:
            tenant_refs.append(self.identity_api.get_tenant(
                    context=context,
                    tenant_id=tenant_id))
        return self._format_tenants_for_token(tenant_refs)

    def get_tenant(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        if not context['is_admin']:
            user_token_ref = self.token_api.get_token(
                    context=context, token_id=context['token_id'])
            creds = user_token_ref['metadata'].copy()
            creds['user_id'] = user_token_ref['user'].get('id')
            creds['tenant_id'] = user_token_ref['tenant'].get('id')
            # Accept either is_admin or the admin role
            assert self.policy_api.can_haz(context,
                                           ('is_admin:1', 'roles:admin'),
                                           creds)

        tenant = self.identity_api.get_tenant(context, tenant_id)
        if not tenant:
            return webob.exc.HTTPNotFound()
        return {'tenant': tenant}

    # CRUD Extension
    def create_tenant(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)
        self.assert_admin(context)
        tenant_id = (tenant_ref.get('id')
                     and tenant_ref.get('id')
                     or uuid.uuid4().hex)
        tenant_ref['id'] = tenant_id

        tenant = self.identity_api.create_tenant(
                context, tenant_id, tenant_ref)
        return {'tenant': tenant}

    def update_tenant(self, context, tenant_id, tenant):
        self.assert_admin(context)
        tenant_ref = self.identity_api.update_tenant(
                context, tenant_id, tenant)
        return {'tenant': tenant_ref}

    def delete_tenant(self, context, tenant_id, **kw):
        self.assert_admin(context)
        self.identity_api.delete_tenant(context, tenant_id)

    def get_tenant_users(self, context, **kw):
        self.assert_admin(context)
        raise NotImplementedError()

    def _format_tenants_for_token(self, tenant_refs):
        for x in tenant_refs:
            x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


class UserController(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(UserController, self).__init__()

    def get_user(self, context, user_id):
        self.assert_admin(context)
        user_ref = self.identity_api.get_user(context, user_id)
        if not user_ref:
            raise webob.exc.HTTPNotFound()
        return {'user': user_ref}

    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        self.assert_admin(context)
        user_refs = self.identity_api.list_users(context)
        return {'users': user_refs}

    # CRUD extension
    def create_user(self, context, user):
        user = self._normalize_dict(user)
        self.assert_admin(context)
        tenant_id = user.get('tenantId', None)
        user_id = uuid.uuid4().hex
        user_ref = user.copy()
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.create_user(
                context, user_id, user_ref)
        if tenant_id:
            self.identity_api.add_user_to_tenant(tenant_id, user_id)
        return {'user': new_user_ref}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)
        user_ref = self.identity_api.update_user(context, user_id, user)
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
        # ensure that we're a member of that tenant
        tenant_id = user.get('tenantId')
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return self.update_user(context, user_id, user)


class RoleController(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
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
        if tenant_id is None:
            raise Exception('User roles not supported: tenant_id required')
        roles = self.identity_api.get_roles_for_user_and_tenant(
                context, user_id, tenant_id)
        return {'roles': [self.identity_api.get_role(context, x)
                          for x in roles]}

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        role_ref = self.identity_api.get_role(context, role_id)
        if not role_ref:
            raise webob.exc.HTTPNotFound()
        return {'role': role_ref}

    def create_role(self, context, role):
        role = self._normalize_dict(role)
        self.assert_admin(context)
        role_id = uuid.uuid4().hex
        role['id'] = role_id
        role_ref = self.identity_api.create_role(context, role_id, role)
        return {'role': role_ref}

    def delete_role(self, context, role_id):
        self.assert_admin(context)
        role_ref = self.identity_api.delete_role(context, role_id)

    def get_roles(self, context):
        self.assert_admin(context)
        roles = self.identity_api.list_roles(context)
        # TODO(termie): probably inefficient at some point
        return {'roles': roles}

    def add_role_to_user(self, context, user_id, role_id, tenant_id=None):
        """Add a role to a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise Exception('User roles not supported: tenant_id required')

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        self.identity_api.add_role_to_user_and_tenant(
                context, user_id, tenant_id, role_id)
        role_ref = self.identity_api.get_role(context, role_id)
        return {'role': role_ref}

    def remove_role_from_user(self, context, user_id, role_id, tenant_id=None):
        """Remove a role from a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
        self.assert_admin(context)
        if tenant_id is None:
            raise Exception('User roles not supported: tenant_id required')

        # This still has the weird legacy semantics that adding a role to
        # a user also adds them to a tenant
        self.identity_api.remove_role_from_user_and_tenant(
                context, user_id, tenant_id, role_id)
        roles = self.identity_api.get_roles_for_user_and_tenant(
                context, user_id, tenant_id)
        if not roles:
            self.identity_api.remove_user_from_tenant(
                    context, tenant_id, user_id)
        return

    # COMPAT(diablo): CRUD extension
    def get_role_refs(self, context, user_id):
        """Ultimate hack to get around having to make role_refs first-class.

        This will basically iterate over the various roles the user has in
        all tenants the user is a member of and create fake role_refs where
        the id encodes the user-tenant-role information so we can look
        up the appropriate data when we need to delete them.

        """
        self.assert_admin(context)
        user_ref = self.identity_api.get_user(context, user_id)
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
