import routes

from keystone.common import wsgi
import keystone.backends as db
from keystone.controllers.auth import AuthController
from keystone.controllers.tenant import TenantController
from keystone.controllers.version import VersionController
from keystone.controllers.staticfiles import StaticFilesController


class ServiceApi(wsgi.Router):
    """WSGI entry point for Keystone Service API requests."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()

        db.configure_backends(options)

        # Token Operations
        auth_controller = AuthController(options)
        mapper.connect("/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/v2.0/ec2tokens", controller=auth_controller,
                       action="authenticate_ec2",
                       conditions=dict(method=["POST"]))

        # Tenant Operations
        tenant_controller = TenantController(options)
        mapper.connect("/tenants", controller=tenant_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))

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
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xsd/atom/{xsd}",
                    controller=static_files_controller,
                    action="get_pdf_contract",
                    conditions=dict(method=["GET"]))

        super(ServiceApi, self).__init__(mapper)
