import routes

from keystone.common import wsgi
import keystone.backends as db
from keystone.controllers.auth import AuthController
from keystone.controllers.endpointtemplates import EndpointTemplatesController
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
        mapper.connect("/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/tokens/{token_id}", controller=auth_controller,
                        action="validate_token",
                        conditions=dict(method=["GET"]))
        mapper.connect("/tokens/{token_id}", controller=auth_controller,
                        action="delete_token",
                        conditions=dict(method=["DELETE"]))

        # Tenant Operations
        tenant_controller = TenantController(options)
        mapper.connect("/tenants", controller=tenant_controller,
                    action="create_tenant",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/tenants", controller=tenant_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="get_tenant", conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="update_tenant", conditions=dict(method=["PUT"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="delete_tenant", conditions=dict(method=["DELETE"]))

        # User Operations
        user_controller = UserController(options)
        mapper.connect("/users",
                    controller=user_controller,
                    action="create_user",
                    conditions=dict(method=["PUT", "POST"]))
        mapper.connect("/users",
                    controller=user_controller,
                    action="get_users",
                    conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="get_user",
                    conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="update_user",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="delete_user",
                    conditions=dict(method=["DELETE"]))
        mapper.connect("/users/{user_id}/password",
                    controller=user_controller,
                    action="set_user_password",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/tenant",
                    controller=user_controller,
                    action="update_user_tenant",
                    conditions=dict(method=["PUT"]))
        # Test this, test failed
        mapper.connect("/users/{user_id}/enabled",
                    controller=user_controller,
                    action="set_user_enabled",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/tenants/{tenant_id}/users",
                    controller=user_controller,
                    action="get_tenant_users",
                    conditions=dict(method=["GET"]))

        #Roles and RoleRefs
        roles_controller = RolesController(options)
        mapper.connect("/roles", controller=roles_controller,
                    action="get_roles", conditions=dict(method=["GET"]))
        mapper.connect("/roles/{role_id}", controller=roles_controller,
                    action="get_role", conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/roleRefs",
            controller=roles_controller, action="get_role_refs",
            conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/roleRefs",
            controller=roles_controller, action="create_role_ref",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/roleRefs/{role_ref_id}",
            controller=roles_controller, action="delete_role_ref",
            conditions=dict(method=["DELETE"]))
        #EndpointTemplatesControllers and Endpoints
        endpoint_templates_controller = EndpointTemplatesController(options)
        mapper.connect("/endpointTemplates",
            controller=endpoint_templates_controller,
                action="get_endpoint_templates",
                    conditions=dict(method=["GET"]))
        mapper.connect("/endpointTemplates/{endpoint_templates_id}",
                controller=endpoint_templates_controller,
                    action="get_endpoint_template",
                        conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}/endpoints",
                       controller=endpoint_templates_controller,
                    action="get_endpoints_for_tenant",
                    conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}/endpoints",
                       controller=endpoint_templates_controller,
                     action="add_endpoint_to_tenant",
                     conditions=dict(method=["POST"]))
        mapper.connect(
                "/tenants/{tenant_id}/endpoints/{endpoints_id}",
                controller=endpoint_templates_controller,
                action="remove_endpoint_from_tenant",
                conditions=dict(method=["DELETE"]))

        # Miscellaneous Operations
        version_controller = VersionController(options)
        mapper.connect("/", controller=version_controller,
                    action="get_version_info",
                    conditions=dict(method=["GET"]))

        # Static Files Controller
        static_files_controller = StaticFilesController(options)
        mapper.connect("/identitydevguide.pdf",
                    controller=static_files_controller,
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/identity.wadl",
                    controller=static_files_controller,
                    action="get_wadl_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xsd/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xsd/atom/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_atom_contract",
                    conditions=dict(method=["GET"]))

        super(AdminApi, self).__init__(mapper)
