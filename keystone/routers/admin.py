import routes

from keystone.common import wsgi
import keystone.backends as db
from keystone.controllers.auth import AuthController
from keystone.controllers.endpointtemplates import EndpointTemplatesController
from keystone.controllers.groups import GroupsController
from keystone.controllers.roles import RolesController
from keystone.controllers.staticfiles import StaticFilesController
from keystone.controllers.tenant import TenantController
from keystone.controllers.user import UserController
from keystone.controllers.version import VersionController


class AdminApi(wsgi.Router):
    """WSGI entry point for admin Keystone API requests."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()

        db.configure_backends(options)
        
        # Token Operations
        auth_controller = AuthController(options)
        mapper.connect("/v2.0/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/v2.0/tokens/{token_id}", controller=auth_controller,
                        action="validate_token",
                        conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tokens/{token_id}", controller=auth_controller,
                        action="delete_token",
                        conditions=dict(method=["DELETE"]))

        # Tenant Operations
        tenant_controller = TenantController(options)
        mapper.connect("/v2.0/tenants", controller=tenant_controller,
                    action="create_tenant",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/v2.0/tenants", controller=tenant_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="get_tenant", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="update_tenant", conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="delete_tenant", conditions=dict(method=["DELETE"]))

        # Tenant Group Operations
        mapper.connect("/v2.0/tenants/{tenant_id}/groups",
                    controller=tenant_controller,
                    action="create_tenant_group",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/groups",
                    controller=tenant_controller,
                    action="get_tenant_groups",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/groups/{group_id}",
                    controller=tenant_controller,
                    action="get_tenant_group",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/groups/{group_id}",
                    controller=tenant_controller,
                    action="update_tenant_group",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/groups/{group_id}",
                    controller=tenant_controller,
                    action="delete_tenant_group",
                    conditions=dict(method=["DELETE"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/groups/{group_id}/users",
                    controller=tenant_controller,
                    action="get_users_tenant_group",
                    conditions=dict(method=["GET"]))
        mapper.connect(
                "/v2.0/tenants/{tenant_id}/groups/{group_id}/users/{user_id}",
                    controller=tenant_controller,
                    action="add_user_tenant_group",
                    conditions=dict(method=["PUT"]))
        mapper.connect(
                 "/v2.0/tenants/{tenant_id}/groups/{group_id}/users/{user_id}",
                    controller=tenant_controller,
                    action="delete_user_tenant_group",
                    conditions=dict(method=["DELETE"]))

        # User Operations
        user_controller = UserController(options)
        mapper.connect("/v2.0/users",
                    controller=user_controller,
                    action="create_user",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/v2.0/users",
                    controller=user_controller,
                    action="get_users",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/users/{user_id}",
                    controller=user_controller,
                    action="get_user",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/users/{user_id}",
                    controller=user_controller,
                    action="update_user",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/users/{user_id}",
                    controller=user_controller,
                    action="delete_user",
                    conditions=dict(method=["DELETE"]))
        mapper.connect("/v2.0/users/{user_id}/password",
                    controller=user_controller,
                    action="set_user_password",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/users/{user_id}/tenant",
                    controller=user_controller,
                    action="update_user_tenant",
                    conditions=dict(method=["PUT"]))
        # Test this, test failed
        mapper.connect("/v2.0/users/{user_id}/enabled",
                    controller=user_controller,
                    action="set_user_enabled",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/users/{user_id}/groups",
                    controller=user_controller,
                    action="get_user_groups",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/users",
                    controller=user_controller,
                    action="get_tenant_users",
                    conditions=dict(method=["GET"]))
        #Global Groups
        groups_controller = GroupsController(options)
        mapper.connect("/v2.0/groups", controller=groups_controller,
                    action="create_group",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/v2.0/groups", controller=groups_controller,
                    action="get_groups", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/groups/{group_id}", controller=groups_controller,
                    action="get_group", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/groups/{group_id}", controller=groups_controller,
                    action="update_group", conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/groups/{group_id}", controller=groups_controller,
                    action="delete_group", conditions=dict(method=["DELETE"]))
        mapper.connect("/v2.0/groups/{group_id}/users",
                    controller=groups_controller,
                    action="get_users_global_group",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/groups/{group_id}/users/{user_id}",
                    controller=groups_controller,
                    action="add_user_global_group",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/v2.0/groups/{group_id}/users/{user_id}",
                    controller=groups_controller,
                    action="delete_user_global_group",
                    conditions=dict(method=["DELETE"]))

        #Roles and RoleRefs
        roles_controller = RolesController(options)
        mapper.connect("/v2.0/roles", controller=roles_controller,
                    action="get_roles", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/roles/{role_id}", controller=roles_controller,
                    action="get_role", conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/users/{user_id}/roleRefs",
            controller=roles_controller, action="get_role_refs",
            conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/users/{user_id}/roleRefs",
            controller=roles_controller, action="create_role_ref",
            conditions=dict(method=["POST"]))
        mapper.connect("/v2.0/users/{user_id}/roleRefs/{role_ref_id}",
            controller=roles_controller, action="delete_role_ref",
            conditions=dict(method=["DELETE"]))
        #EndpointTemplatesControllers and Endpoints
        endpoint_templates_controller = EndpointTemplatesController(options)
        mapper.connect("/v2.0/endpointTemplates",
            controller=endpoint_templates_controller,
                action="get_endpoint_templates",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/endpointTemplates/{endpoint_templates_id}",
                controller=endpoint_templates_controller,
                    action="get_endpoint_template",
                        conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/endpoints",
                       controller=endpoint_templates_controller,
                    action="get_endpoints_for_tenant",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/tenants/{tenant_id}/endpoints",
                       controller=endpoint_templates_controller,
                     action="add_endpoint_to_tenant",
                     conditions=dict(method=["POST"]))
        mapper.connect(
                "/v2.0/tenants/{tenant_id}/endpoints/{endpoints_id}",
                controller=endpoint_templates_controller,
                action="remove_endpoint_from_tenant",
                conditions=dict(method=["DELETE"]))

        # Miscellaneous Operations
        version_controller = VersionController(options)
        mapper.connect("/v2.0", controller=version_controller,
                    action="get_version_info",
                    conditions=dict(method=["GET"]))

        # Static Files Controller
        static_files_controller = StaticFilesController(options)
        mapper.connect("/v2.0/identitydevguide.pdf",
                    controller=static_files_controller,
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/identity.wadl",
                    controller=static_files_controller,
                    action="get_wadl_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/xsd/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/xsd/atom/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_atom_contract",
                    conditions=dict(method=["GET"]))

        super(AdminApi, self).__init__(mapper)
