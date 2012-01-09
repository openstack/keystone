# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend that emulates keystone
import logging
import urllib
import urlparse
import uuid

import routes
from webob import exc

from keystone import catalog
from keystone import identity
from keystone import policy
from keystone import service
from keystone import token
from keystone import wsgi


class KeystoneAdminRouter(wsgi.Router):
    def __init__(self):
        mapper = routes.Mapper()

        # Token Operations
        auth_controller = KeystoneTokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))

        # Tenant Operations
        tenant_controller = KeystoneTenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants/{tenant_id}',
                       controller=tenant_controller,
                       action='get_tenant',
                       conditions=dict(method=['GET']))

        # User Operations
        user_controller = KeystoneUserController()
        mapper.connect('/users/{user_id}',
                       controller=user_controller,
                       action='get_user',
                       conditions=dict(method=['GET']))

        # Role Operations
        roles_controller = KeystoneRoleController()
        mapper.connect('/tenants/{tenant_id}/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/roles',
                       controller=user_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))

        # Miscellaneous Operations
        version_controller = KeystoneVersionController()
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_info', module='admin/version',
                       conditions=dict(method=['GET']))

        extensions_controller = KeystoneExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))

        super(KeystoneAdminRouter, self).__init__(mapper)


class KeystoneServiceRouter(wsgi.Router):
    def __init__(self):
        mapper = routes.Mapper()

        # Token Operations
        auth_controller = KeystoneTokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/ec2tokens',
                       controller=auth_controller,
                       action='authenticate_ec2',
                       conditions=dict(methods=['POST']))

        # Tenant Operations
        tenant_controller = KeystoneTenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
                       conditions=dict(methods=['GET']))

        # Miscellaneous
        version_controller = KeystoneVersionController()
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_info',
                       module='service/version',
                       conditions=dict(method=['GET']))

        extensions_controller = KeystoneExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))

        super(KeystoneServiceRouter, self).__init__(mapper)


class KeystoneAdminCrudExtension(wsgi.ExtensionRouter):
    """Previously known as the OS-KSADM extension.

    Provides a bunch of CRUD operations for internal data types.

    """

    def __init__(self, application):
        mapper = routes.Mapper()
        tenant_controller = KeystoneTenantController()
        user_controller = KeystoneUserController()
        role_controller = KeystoneRoleController()
        service_controller = KeystoneServiceController()

        # Tenant Operations
        mapper.connect("/tenants", controller=tenant_controller,
                    action="create_tenant",
                    conditions=dict(method=["POST"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="update_tenant",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="delete_tenant",
                    conditions=dict(method=["DELETE"]))
        mapper.connect("/tenants/{tenant_id}/users",
                    controller=user_controller,
                    action="get_tenant_users",
                    conditions=dict(method=["GET"]))

        # User Operations
        mapper.connect("/users",
                    controller=user_controller,
                    action="get_users",
                    conditions=dict(method=["GET"]))
        mapper.connect("/users",
                    controller=user_controller,
                    action="create_user",
                    conditions=dict(method=["POST"]))
        # NOTE(termie): not in diablo
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="update_user",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="delete_user",
                    conditions=dict(method=["DELETE"]))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect("/users/{user_id}/password",
                    controller=user_controller,
                    action="set_user_password",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/OS-KSADM/password",
                    controller=user_controller,
                    action="set_user_password",
                    conditions=dict(method=["PUT"]))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect("/users/{user_id}/tenant",
                    controller=user_controller,
                    action="update_user_tenant",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/OS-KSADM/tenant",
                    controller=user_controller,
                    action="update_user_tenant",
                    conditions=dict(method=["PUT"]))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect("/users/{user_id}/enabled",
                    controller=user_controller,
                    action="set_user_enabled",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/OS-KSADM/enabled",
                    controller=user_controller,
                    action="set_user_enabled",
                    conditions=dict(method=["PUT"]))

        # User Roles
        mapper.connect("/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=role_controller, action="add_role_to_user",
            conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=role_controller, action="delete_role_from_user",
            conditions=dict(method=["DELETE"]))

        # COMPAT(diablo): User Roles
        mapper.connect("/users/{user_id}/roleRefs",
            controller=role_controller, action="get_role_refs",
            conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/roleRefs",
            controller=role_controller, action="create_role_ref",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/roleRefs/{role_ref_id}",
            controller=role_controller, action="delete_role_ref",
            conditions=dict(method=["DELETE"]))

        # User-Tenant Roles
        mapper.connect(
            "/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=role_controller, action="add_role_to_user",
            conditions=dict(method=["PUT"]))
        mapper.connect(
            "/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=role_controller, action="delete_role_from_user",
            conditions=dict(method=["DELETE"]))

        # Service Operations
        mapper.connect("/OS-KSADM/services",
                       controller=service_controller,
                       action="get_services",
                       conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/services",
                       controller=service_controller,
                       action="create_service",
                       conditions=dict(method=["POST"]))
        mapper.connect("/OS-KSADM/services/{service_id}",
                       controller=service_controller,
                       action="delete_service",
                       conditions=dict(method=["DELETE"]))
        mapper.connect("/OS-KSADM/services/{service_id}",
                       controller=service_controller,
                       action="get_service",
                       conditions=dict(method=["GET"]))

        # Role Operations
        mapper.connect("/OS-KSADM/roles",
                       controller=role_controller,
                       action="create_role",
                       conditions=dict(method=["POST"]))
        mapper.connect("/OS-KSADM/roles",
                       controller=role_controller,
                       action="get_roles",
                       conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/roles/{role_id}",
                       controller=role_controller,
                       action="get_role",
                       conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/roles/{role_id}",
                       controller=role_controller,
                       action="delete_role",
                       conditions=dict(method=["DELETE"]))

        super(KeystoneAdminCrudExtension, self).__init__(
                application, mapper)


class KeystoneTokenController(service.BaseApplication):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(KeystoneTokenController, self).__init__()

    def authenticate(self, context, auth=None):
        """Authenticate credentials and return a token.

        Keystone accepts auth as a dict that looks like:

        {
            "auth":{
                "passwordCredentials":{
                    "username":"test_user",
                    "password":"mypass"
                },
                "tenantName":"customer-x"
            }
        }

        In this case, tenant is optional, if not provided the token will be
        considered "unscoped" and can later be used to get a scoped token.

        Alternatively, this call accepts auth with only a token and tenant
        that will return a token that is scoped to that tenant.
        """

        if 'passwordCredentials' in auth:
            username = auth['passwordCredentials'].get('username', '')
            password = auth['passwordCredentials'].get('password', '')
            tenant_name = auth.get('tenantName', None)

            if username:
                user_ref = self.identity_api.get_user_by_name(
                        context=context, user_name=username)
                user_id = user_ref['id']
            else:
                user_id = auth['passwordCredentials'].get('userId', None)

            # more compat
            if tenant_name:
                tenant_ref = self.identity_api.get_tenant_by_name(
                        context=context, tenant_name=tenant_name)
                tenant_id = tenant_ref['id']
            else:
                tenant_id = auth.get('tenantId', None)

            (user_ref, tenant_ref, extras_ref) = \
                    self.identity_api.authenticate(context=context,
                                                   user_id=user_id,
                                                   password=password,
                                                   tenant_id=tenant_id)
            token_ref = self.token_api.create_token(context,
                                                    dict(expires='',
                                                         user=user_ref,
                                                         tenant=tenant_ref,
                                                         extras=extras_ref))
            if tenant_ref:
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        extras=extras_ref)
            else:
                catalog_ref = {}

        elif 'token' in auth:
            token = auth['token'].get('id', None)

            tenant_name = auth.get('tenantName')

            # more compat
            if tenant_name:
                tenant_ref = self.identity_api.get_tenant_by_name(
                        context=context, tenant_name=tenant_name)
                tenant_id = tenant_ref['id']
            else:
                tenant_id = auth.get('tenantId', None)

            old_token_ref = self.token_api.get_token(context=context,
                                                     token_id=token)
            user_ref = old_token_ref['user']

            assert tenant_id in user_ref['tenants']

            tenant_ref = self.identity_api.get_tenant(context=context,
                                                      tenant_id=tenant_id)
            extras_ref = self.identity_api.get_extras(
                    context=context,
                    user_id=user_ref['id'],
                    tenant_id=tenant_ref['id'])
            token_ref = self.token_api.create_token(context,
                                                    dict(expires='',
                                                         user=user_ref,
                                                         tenant=tenant_ref,
                                                         extras=extras_ref))
            catalog_ref = self.catalog_api.get_catalog(
                    context=context,
                    user_id=user_ref['id'],
                    tenant_id=tenant_ref['id'],
                    extras=extras_ref)

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for extras
        # fill out the roles in the extras
        roles_ref = []
        for role_id in extras_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))
        logging.debug('TOKEN_REF %s', token_ref)
        return self._format_authenticate(token_ref, roles_ref, catalog_ref)

    def authenticate_ec2(self, context):
        raise NotImplemented()

    # admin only
    def validate_token(self, context, token_id, belongs_to=None):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        """
        # TODO(termie): this stuff should probably be moved to middleware
        if not context['is_admin']:
            user_token_ref = self.token_api.get_token(
                    context=context, token_id=context['token_id'])
            creds = user_token_ref['extras'].copy()
            creds['user_id'] = user_token_ref['user'].get('id')
            creds['tenant_id'] = user_token_ref['tenant'].get('id')
            # Accept either is_admin or the admin role
            assert self.policy_api.can_haz(context,
                                           ('is_admin:1', 'roles:admin'),
                                           creds)

        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)
        if belongs_to:
            assert token_ref['tenant']['id'] == belongs_to
        return self._format_token(token_ref)

    def endpoints(self, context, token_id):
        """Return service catalog endpoints."""
        token_ref = self.token_api.get_token(context=context,
                                             token_id=token_id)
        catalog_ref = self.catalog_api.get_catalog(context,
                                                   token_ref['user']['id'],
                                                   token_ref['tenant']['id'])
        return {'token': {'serviceCatalog': self._format_catalog(catalog_ref)}}

    def _format_authenticate(self, token_ref, roles_ref, catalog_ref):
        o = self._format_token(token_ref, roles_ref)
        o['access']['serviceCatalog'] = self._format_catalog(catalog_ref)
        return o

    def _format_token(self, token_ref, roles_ref):
        user_ref = token_ref['user']
        extras_ref = token_ref['extras']
        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': token_ref['expires']
                                  },
                        'user': {'id': user_ref['id'],
                                 'name': user_ref['name'],
                                 'username': user_ref['name'],
                                 'roles': roles_ref,
                                 'roles_links': extras_ref.get('roles_links',
                                                               [])
                                 }
                        }
             }
        if 'tenant' in token_ref and token_ref['tenant']:
            token_ref['tenant']['enabled'] = True
            o['access']['token']['tenant'] = token_ref['tenant']
        return o

    def _format_catalog(self, catalog_ref):
        """KeystoneLight catalogs look like:

        {$REGION: {
            {$SERVICE: {
                $key1: $value1,
                ...
                }
            }
        }

        Keystone's look like

        [{'name': $SERVICE[name],
          'type': $SERVICE,
          'endpoints': [{
              'tenantId': $tenant_id,
              ...
              'region': $REGION,
              }],
          'endpoints_links': [],
         }]

        """
        if not catalog_ref:
            return {}

        services = {}
        for region, region_ref in catalog_ref.iteritems():
            for service, service_ref in region_ref.iteritems():
                new_service_ref = services.get(service, {})
                new_service_ref['name'] = service_ref.pop('name')
                new_service_ref['type'] = service
                new_service_ref['endpoints_links'] = []
                service_ref['region'] = region

                endpoints_ref = new_service_ref.get('endpoints', [])
                endpoints_ref.append(service_ref)

                new_service_ref['endpoints'] = endpoints_ref
                services[service] = new_service_ref

        return services.values()


class KeystoneTenantController(service.BaseApplication):
    def __init__(self):
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(KeystoneTenantController, self).__init__()

    def get_tenants_for_token(self, context, **kw):
        """Get valid tenants for token based on token used to authenticate.

        Pulls the token from the context, validates it and gets the valid
        tenants for the user in the token.

        Doesn't care about token scopedness.

        """
        token_ref = self.token_api.get_token(context=context,
                                             token_id=context['token_id'])
        assert token_ref is not None

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
            creds = user_token_ref['extras'].copy()
            creds['user_id'] = user_token_ref['user'].get('id')
            creds['tenant_id'] = user_token_ref['tenant'].get('id')
            # Accept either is_admin or the admin role
            assert self.policy_api.can_haz(context,
                                           ('is_admin:1', 'roles:admin'),
                                           creds)

        tenant = self.identity_api.get_tenant(context, tenant_id)
        if not tenant:
            return exc.HTTPNotFound()
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
                context, tenant_id=tenant_id, data=tenant_ref)
        return {'tenant': tenant}

    def update_tenant(self, context, tenant_id, tenant):
        self.assert_admin(context)
        tenant_ref = self.identity_api.update_tenant(
                context, tenant_id=tenant_id, data=tenant)
        return {'tenant': tenant_ref}

    def delete_tenant(self, context, tenant_id, **kw):
        self.assert_admin(context)
        self.identity_api.delete_tenant(context, tenant_id=tenant_id)

    def get_tenant_users(self, context, **kw):
        self.assert_admin(context)
        raise NotImplementedError()

    def _format_tenants_for_token(self, tenant_refs):
        for x in tenant_refs:
            x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


class KeystoneUserController(service.BaseApplication):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(KeystoneUserController, self).__init__()

    def get_user(self, context, user_id):
        self.assert_admin(context)
        user_ref = self.identity_api.get_user(context, user_id)
        if not user_ref:
            raise exc.HTTPNotFound()
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

    # NOTE(termie): this is really more of a patch than a put
    def update_user(self, context, user_id, user):
        self.assert_admin(context)
        user_ref = self.identity_api.get_user(context, user_id)
        del user['id']
        user_ref.update(user)
        self.identity_api.update_user(context, user_id, user_ref)
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


class KeystoneRoleController(service.BaseApplication):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(KeystoneRoleController, self).__init__()

    def get_user_roles(self, context, user_id, tenant_id=None):
        raise NotImplemented()

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        role_ref = self.identity_api.get_role(context, role_id)
        if not role_ref:
            raise exc.HTTPNotFound()
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


class KeystoneServiceController(service.BaseApplication):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(KeystoneServiceController, self).__init__()

    # CRUD extensions
    # NOTE(termie): this OS-KSADM stuff is about the lamest ever
    def get_services(self, context):
        service_list = self.catalog_api.list_services(context)
        service_refs = [self.catalog_api.get_service(context, x)
                        for x in service_list]
        return {'OS-KSADM:services': service_refs}

    def get_service(self, context, service_id):
        service_ref = self.catalog_api.get_service(context, service_id)
        if not service_ref:
            raise exc.HTTPNotFound()
        return {'OS-KSADM:service': service_ref}

    def delete_service(self, context, service_id):
        service_ref = self.catalog_api.delete_service(context, service_id)

    def create_service(self, context, OS_KSADM_service):
        service_id = uuid.uuid4().hex
        service_ref = OS_KSADM_service.copy()
        service_ref['id'] = service_id
        new_service_ref = self.catalog_api.create_service(
                context, service_id, service_ref)
        return {'OS-KSADM:service': new_service_ref}


class KeystoneVersionController(service.BaseApplication):
    def __init__(self):
        super(KeystoneVersionController, self).__init__()

    def get_version_info(self, context, module='version'):
        raise NotImplemented()


class KeystoneExtensionsController(service.BaseApplication):
    def __init__(self):
        super(KeystoneExtensionsController, self).__init__()

    def get_extensions_info(self, context):
        raise NotImplemented()


def service_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return KeystoneServiceRouter()


def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return KeystoneAdminRouter()
