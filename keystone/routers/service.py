# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import routes

from keystone.common import wsgi
import keystone.backends as db
from keystone.controllers.token import TokenController
from keystone.controllers.tenant import TenantController
from keystone.controllers.version import VersionController
from keystone.controllers.staticfiles import StaticFilesController
from keystone.controllers.extensions import ExtensionsController


class ServiceApi(wsgi.Router):
    """WSGI entry point for Keystone Service API requests."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()

        db.configure_backends(options)

        # Token Operations
        auth_controller = TokenController(options)
        mapper.connect("/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/ec2tokens", controller=auth_controller,
                       action="authenticate_ec2",
                       conditions=dict(method=["POST"]))
        tenant_controller = TenantController(options, True)
        mapper.connect("/tenants",
                        controller=tenant_controller,
                        action="get_tenants",
                        conditions=dict(method=["GET"]))

        # Miscellaneous Operations
        version_controller = VersionController(options)
        mapper.connect("/",
                        controller=version_controller,
                        action="get_version_info", file="service/version",
                        conditions=dict(method=["GET"]))

        extensions_controller = ExtensionsController(options, True)
        mapper.connect("/extensions",
                        controller=extensions_controller,
                        action="get_extensions_info",
                        conditions=dict(method=["GET"]))

        # Static Files Controller
        static_files_controller = StaticFilesController(options)
        mapper.connect("/identitydevguide.pdf",
                        controller=static_files_controller,
                        action="get_pdf_contract",
                        root="content/service/", pdf="identitydevguide.pdf",
                        conditions=dict(method=["GET"]))
        mapper.connect("/identity.wadl",
                        controller=static_files_controller,
                        action="get_wadl_contract",
                        root="content/service/", wadl="identity.wadl",
                        conditions=dict(method=["GET"]))
        mapper.connect("/common.ent",
                        controller=static_files_controller,
                        action="get_wadl_contract",
                        wadl="common.ent", root="content/common/",
                        conditions=dict(method=["GET"]))
        mapper.connect("/xslt/{file:.*}",
                        controller=static_files_controller,
                        action="get_static_file", path="common/xslt/",
                        mimetype="application/xml",
                        conditions=dict(method=["GET"]))
        mapper.connect("/style/{file:.*}",
                        controller=static_files_controller,
                        action="get_static_file", path="common/style/",
                        mimetype="application/css",
                        conditions=dict(method=["GET"]))
        mapper.connect("/js/{file:.*}",
                        controller=static_files_controller,
                        action="get_static_file", path="common/js/",
                        mimetype="application/javascript",
                        conditions=dict(method=["GET"]))
        mapper.connect("/samples/{file:.*}",
                        controller=static_files_controller,
                        action="get_static_file", path="common/samples/",
                        conditions=dict(method=["GET"]))
        mapper.connect("/xsd/{xsd:.*}",
                        controller=static_files_controller,
                        action="get_xsd_contract", root="content/common/",
                        conditions=dict(method=["GET"]))
        mapper.connect("/xsd/atom/{xsd}",
                        controller=static_files_controller,
                        action="get_xsd_atom_contract",
                        root="content/common/",
                        conditions=dict(method=["GET"]))
        mapper.connect("/xsd/atom/{xsd}",
                        controller=static_files_controller,
                        action="get_xsd_atom_contract",
                        root="content/common/",
                        conditions=dict(method=["GET"]))

        super(ServiceApi, self).__init__(mapper)
