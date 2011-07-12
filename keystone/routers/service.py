import routes

from keystone.common import wsgi
import keystone.backends as db
from keystone.controllers.auth import AuthController
from keystone.controllers.tenant import TenantController
from keystone.controllers.version import VersionController
from keystone.controllers.staticfiles import StaticFilesController

class ServiceApi(wsgi.Router):
    """WSGI entry point for public Keystone API requests."""
    
    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()
        
        db.configure_backends(options)
        
        # Token Operations
        auth_controller = AuthController(options)
        mapper.connect("/v2.0/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))

        # Tenant Operations
        tenant_controller = TenantController(options)
        mapper.connect("/v2.0/tenants", controller=tenant_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))

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
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/v2.0/xsd/atom/{xsd}",
                    controller=static_files_controller,
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))

        super(ServiceApi, self).__init__(mapper)
