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

import logging
import routes

from keystone.common import wsgi
from keystone.controllers.token import TokenController
from keystone.controllers.roles import RolesController
from keystone.controllers.staticfiles import StaticFilesController
from keystone.controllers.tenant import TenantController
from keystone.controllers.user import UserController
from keystone.controllers.version import VersionController
from keystone.controllers.extensions import ExtensionsController
import keystone.contrib.extensions.admin as extension

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class AdminApi(wsgi.Router):
    """WSGI entry point for admin Keystone API requests."""

    def __init__(self):
        mapper = routes.Mapper()

        # Load extensions first so they can override core if they need to
        extension.get_extension_configurer().configure(mapper)

        # Token Operations
        auth_controller = TokenController()
        mapper.connect("/tokens", controller=auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/tokens/{token_id}", controller=auth_controller,
                        action="validate_token",
                        conditions=dict(method=["GET"]))
        mapper.connect("/tokens/{token_id}", controller=auth_controller,
                        action="check_token",
                        conditions=dict(method=["HEAD"]))
        # Do we need this. API doesn't have delete token.
        mapper.connect("/tokens/{token_id}", controller=auth_controller,
                        action="delete_token",
                        conditions=dict(method=["DELETE"]))
        mapper.connect("/tokens/{token_id}/endpoints",
                        controller=auth_controller,
                        action="endpoints",
                        conditions=dict(method=["GET"]))

        # Tenant Operations
        tenant_controller = TenantController()
        mapper.connect("/tenants", controller=tenant_controller,
                    action="get_tenants", conditions=dict(method=["GET"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="get_tenant", conditions=dict(method=["GET"]))
        roles_controller = RolesController()
        mapper.connect("/tenants/{tenant_id}/users/{user_id}/roles",
            controller=roles_controller, action="get_user_roles",
            conditions=dict(method=["GET"]))
        # User Operations
        user_controller = UserController()
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="get_user",
                    conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/roles",
            controller=roles_controller, action="get_user_roles",
            conditions=dict(method=["GET"]))
        # Miscellaneous Operations
        version_controller = VersionController()
        mapper.connect("/", controller=version_controller,
                    action="get_version_info", file="admin/version",
                    conditions=dict(method=["GET"]))

        extensions_controller = ExtensionsController()
        mapper.connect("/extensions",
                        controller=extensions_controller,
                        action="get_extensions_info",
                        conditions=dict(method=["GET"]))

        # Static Files Controller
        static_files_controller = StaticFilesController()
        mapper.connect("/identityadminguide.pdf",
                    controller=static_files_controller,
                    action="get_pdf_contract",
                    root="content/admin/", pdf="identityadminguide.pdf",
                    conditions=dict(method=["GET"]))
        mapper.connect("/identity-admin.wadl",
                    controller=static_files_controller,
                    action="get_wadl_contract",
                    root="content/admin/", wadl="identity-admin.wadl",
                    conditions=dict(method=["GET"]))
        mapper.connect("/common.ent",
                    controller=static_files_controller,
                    action="get_wadl_contract",
                    root="content/common/", wadl="common.ent",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xsd/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_contract",
                    root="content/common/",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xsd/atom/{xsd}",
                    controller=static_files_controller,
                    action="get_xsd_atom_contract",
                    root="content/common/",
                    conditions=dict(method=["GET"]))
        mapper.connect("/xslt/{file:.*}",
                    controller=static_files_controller,
                    action="get_static_file",
                    root="content/common/", path="xslt/",
                    mimetype="application/xml",
                    conditions=dict(method=["GET"]))
        mapper.connect("/js/{file:.*}",
                    controller=static_files_controller,
                    action="get_static_file",
                    root="content/common/", path="js/",
                    mimetype="application/javascript",
                    conditions=dict(method=["GET"]))
        mapper.connect("/style/{file:.*}",
                    controller=static_files_controller,
                    action="get_static_file",
                    root="content/common/", path="style/",
                    mimetype="application/css",
                    conditions=dict(method=["GET"]))
        mapper.connect("/samples/{file:.*}",
                    controller=static_files_controller,
                    action="get_static_file",
                    root="content/common/", path="samples/",
                    conditions=dict(method=["GET"]))
        super(AdminApi, self).__init__(mapper)
