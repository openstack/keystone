# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import catalog
from keystone import identity
from keystone.common import wsgi


class CrudExtension(wsgi.ExtensionRouter):
    """Previously known as the OS-KSADM extension.

    Provides a bunch of CRUD operations for internal data types.

    """

    def add_routes(self, mapper):
        tenant_controller = identity.TenantController()
        user_controller = identity.UserController()
        role_controller = identity.RoleController()
        service_controller = catalog.ServiceController()

        # Tenant Operations
        mapper.connect('/tenants', controller=tenant_controller,
                    action='create_tenant',
                    conditions=dict(method=['POST']))
        mapper.connect('/tenants/{tenant_id}',
                    controller=tenant_controller,
                    action='update_tenant',
                    conditions=dict(method=['PUT', 'POST']))
        mapper.connect('/tenants/{tenant_id}',
                    controller=tenant_controller,
                    action='delete_tenant',
                    conditions=dict(method=['DELETE']))
        mapper.connect('/tenants/{tenant_id}/users',
                    controller=user_controller,
                    action='get_tenant_users',
                    conditions=dict(method=['GET']))

        # User Operations
        mapper.connect('/users',
                    controller=user_controller,
                    action='get_users',
                    conditions=dict(method=['GET']))
        mapper.connect('/users',
                    controller=user_controller,
                    action='create_user',
                    conditions=dict(method=['POST']))
        # NOTE(termie): not in diablo
        mapper.connect('/users/{user_id}',
                    controller=user_controller,
                    action='update_user',
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}',
                    controller=user_controller,
                    action='delete_user',
                    conditions=dict(method=['DELETE']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect('/users/{user_id}/password',
                    controller=user_controller,
                    action='set_user_password',
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/OS-KSADM/password',
                    controller=user_controller,
                    action='set_user_password',
                    conditions=dict(method=['PUT']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect('/users/{user_id}/tenant',
                    controller=user_controller,
                    action='update_user_tenant',
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/OS-KSADM/tenant',
                    controller=user_controller,
                    action='update_user_tenant',
                    conditions=dict(method=['PUT']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect('/users/{user_id}/enabled',
                    controller=user_controller,
                    action='set_user_enabled',
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/OS-KSADM/enabled',
                    controller=user_controller,
                    action='set_user_enabled',
                    conditions=dict(method=['PUT']))

        # User Roles
        mapper.connect('/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=role_controller, action='add_role_to_user',
            conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=role_controller, action='delete_role_from_user',
            conditions=dict(method=['DELETE']))

        # COMPAT(diablo): User Roles
        mapper.connect('/users/{user_id}/roleRefs',
            controller=role_controller, action='get_role_refs',
            conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/roleRefs',
            controller=role_controller, action='create_role_ref',
            conditions=dict(method=['POST']))
        mapper.connect('/users/{user_id}/roleRefs/{role_ref_id}',
            controller=role_controller, action='delete_role_ref',
            conditions=dict(method=['DELETE']))

        # User-Tenant Roles
        mapper.connect(
            '/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=role_controller, action='add_role_to_user',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=role_controller, action='remove_role_from_user',
            conditions=dict(method=['DELETE']))

        # Service Operations
        mapper.connect('/OS-KSADM/services',
                       controller=service_controller,
                       action='get_services',
                       conditions=dict(method=['GET']))
        mapper.connect('/OS-KSADM/services',
                       controller=service_controller,
                       action='create_service',
                       conditions=dict(method=['POST']))
        mapper.connect('/OS-KSADM/services/{service_id}',
                       controller=service_controller,
                       action='delete_service',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/OS-KSADM/services/{service_id}',
                       controller=service_controller,
                       action='get_service',
                       conditions=dict(method=['GET']))

        # Role Operations
        mapper.connect('/OS-KSADM/roles',
                       controller=role_controller,
                       action='create_role',
                       conditions=dict(method=['POST']))
        mapper.connect('/OS-KSADM/roles',
                       controller=role_controller,
                       action='get_roles',
                       conditions=dict(method=['GET']))
        mapper.connect('/OS-KSADM/roles/{role_id}',
                       controller=role_controller,
                       action='get_role',
                       conditions=dict(method=['GET']))
        mapper.connect('/OS-KSADM/roles/{role_id}',
                       controller=role_controller,
                       action='delete_role',
                       conditions=dict(method=['DELETE']))
