# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Service that stores identities and issues and manages tokens

HEADERS
-------
HTTP_ is a standard http header
HTTP_X is an extended http header

> Coming in from initial call
HTTP_X_AUTH_TOKEN   : the client token being passed in
HTTP_X_STORAGE_TOKEN: the client token being passed in (legacy Rackspace use)
                      to support cloud files
> Used for communication between components
www-authenticate    : only used if this component is being used remotely
HTTP_AUTHORIZATION  : basic auth password used to validate the connection

> What we add to the request for use by the OpenStack service
HTTP_X_AUTHORIZATION: the client identity being passed in

"""
import logging
import os
import routes
import sys
from webob import Response

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)


from keystone.common import wsgi
import keystone.backends as db
import keystone.backends.alterdb
import keystone.logic.service as serv
import keystone.logic.types.tenant as tenants
import keystone.logic.types.role as roles
import keystone.logic.types.endpoint as endpoints
import keystone.logic.types.auth as auth
import keystone.logic.types.user as users
import keystone.common.template as template
import keystone.utils as utils

logger = logging.getLogger('keystone.server')

VERSION_STATUS = "ALPHA"
VERSION_DATE = "2011-04-23T00:00:00Z"


service = serv.IdentityService()


class StaticFilesController(wsgi.Controller):
    """
        Static Files Controller -
        Controller for contract documents
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_pdf_contract(self, req):
        resp = Response()
        return template.static_file(resp, req, "content/identitydevguide.pdf",
                                  root=utils.get_app_root(),
                                  mimetype="application/pdf")

    @utils.wrap_error
    def get_wadl_contract(self, req):
        resp = Response()
        return template.static_file(resp, req, "identity.wadl",
                              root=utils.get_app_root(),
                              mimetype="application/vnd.sun.wadl+xml")

    @utils.wrap_error
    def get_xsd_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "/xsd/" + xsd,
                              root=utils.get_app_root(),
                              mimetype="application/xml")

    @utils.wrap_error
    def get_xsd_atom_contract(self, req, xsd):
        resp = Response()
        return template.static_file(resp, req, "/xsd/atom/" + xsd,
                              root=utils.get_app_root(),
                              mimetype="application/xml")


class VersionController(wsgi.Controller):
    """
        Version Controller -
        Controller for version related methods
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def  get_version_info(self, req):

        resp = Response()
        resp.charset = 'UTF-8'
        if utils.is_xml_response(req):
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                                     "keystone/content/version.xml.tpl")
            resp.content_type = "application/xml"
        else:
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                                 "keystone/content/version.json.tpl")
            resp.content_type = "application/json"

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")

        resp.unicode_body = template.template(resp_file, HOST=hostname,
                               PORT=port, VERSION_STATUS=VERSION_STATUS,
                               VERSION_DATE=VERSION_DATE)
        return resp


class AuthController(wsgi.Controller):
    """
        Auth Controller -
        Controller for token related operations
    """

    def __init__(self, options):
        self.options = options
        self.request = None

    @utils.wrap_error
    def authenticate(self, req):
        self.request = req

        creds = utils.get_normalized_request_content(auth.PasswordCredentials,
                                                    req)
        return utils.send_result(200, req, service.authenticate(creds))

    @utils.wrap_error
    def validate_token(self, req, token_id):

        belongs_to = None
        if "belongsTo" in req.GET:
            belongs_to = req.GET["belongsTo"]
        rval = service.validate_token(utils.get_auth_token(req),
                                      token_id, belongs_to)

        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_token(self, req, token_id):
        return utils.send_result(204, req,
                     service.revoke_token(utils.get_auth_token(req), token_id))


class TenantController(wsgi.Controller):
    """
        Tenant Controller -
        Controller for Tenant and Tenant Group related operations
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_tenant(self, req):
        tenant = utils.get_normalized_request_content(tenants.Tenant, req)
        return utils.send_result(201, req,
                    service.create_tenant(utils.get_auth_token(req), tenant))

    @utils.wrap_error
    def get_tenants(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        tenants = service.get_tenants(utils.get_auth_token(req), marker,
                                    limit, url)
        return utils.send_result(200, req, tenants)

    @utils.wrap_error
    def get_tenant(self, req, tenant_id):
        tenant = service.get_tenant(utils.get_auth_token(req), tenant_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_tenant(self, req, tenant_id):
        tenant = utils.get_normalized_request_content(tenants.Tenant, req)
        rval = service.update_tenant(utils.get_auth_token(req), tenant_id,
                                    tenant)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_tenant(self, req, tenant_id):
        rval = service.delete_tenant(utils.get_auth_token(req), tenant_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def create_tenant_group(self, req, tenant_id):
        group = utils.get_normalized_request_content(tenants.Group, req)
        return utils.send_result(201, req,
                       service.create_tenant_group(utils.get_auth_token(req),
                                                   tenant_id, group))

    @utils.wrap_error
    def get_tenant_groups(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        groups = service.get_tenant_groups(utils.get_auth_token(req),
                                        tenant_id, marker, limit, url)
        return utils.send_result(200, req, groups)

    @utils.wrap_error
    def get_tenant_group(self, req, tenant_id, group_id):
        tenant = service.get_tenant_group(utils.get_auth_token(req), tenant_id,
                                            group_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_tenant_group(self, req, tenant_id, group_id):
        group = utils.get_normalized_request_content(tenants.Group, req)
        rval = service.update_tenant_group(utils.get_auth_token(req),
                                        tenant_id, group_id, group)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_tenant_group(self, req, tenant_id, group_id):
        rval = service.delete_tenant_group(utils.get_auth_token(req),
                                        tenant_id, group_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_users_tenant_group(self, req, tenant_id, group_id):
        marker, limit, url = get_marker_limit_and_url(req)
        users = service.get_users_tenant_group(utils.get_auth_token(req),
                                              tenant_id, group_id, marker,
                                              limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def add_user_tenant_group(self, req, tenant_id, group_id, user_id):
        return utils.send_result(201, req, service.add_user_tenant_group(\
                                utils.get_auth_token(req), tenant_id, group_id,
                                user_id))

    @utils.wrap_error
    def delete_user_tenant_group(self, req, tenant_id, group_id, user_id):
        return utils.send_result(204, req, service.delete_user_tenant_group(\
                                utils.get_auth_token(req), tenant_id, group_id,
                                user_id))


class UserController(wsgi.Controller):
    """
        User Controller -
        Controller for User related operations
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_user(self, req):
        user = utils.get_normalized_request_content(users.User, req)
        return utils.send_result(201, req,
                       service.create_user(utils.get_auth_token(req), \
                                        user))

    @utils.wrap_error
    def get_users(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        users = service.get_users(utils.get_auth_token(req), marker,
                                    limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def get_user(self, req, user_id):
        user = service.get_user(utils.get_auth_token(req), user_id)
        return utils.send_result(200, req, user)

    @utils.wrap_error
    def update_user(self, req, user_id):
        user = utils.get_normalized_request_content(users.User_Update, req)
        rval = service.update_user(utils.get_auth_token(req),
                user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_user(self, req, user_id):
        rval = service.delete_user(utils.get_auth_token(req), user_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def set_user_password(self, req, user_id):
        user = utils.get_normalized_request_content(users.User_Update, req)
        rval = service.set_user_password(utils.get_auth_token(req), user_id,
                                        user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def set_user_enabled(self, req, user_id):
        user = utils.get_normalized_request_content(users.User_Update, req)
        rval = service.enable_disable_user(utils.get_auth_token(req), user_id,
                                           user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def update_user_tenant(self, req, user_id):
        user = utils.get_normalized_request_content(users.User_Update, req)
        rval = service.set_user_tenant(utils.get_auth_token(req), user_id,
                                           user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def get_tenant_users(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        users = service.get_tenant_users(utils.get_auth_token(req), \
                                    tenant_id, marker, limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def get_user_groups(self, req, user_id):
        marker, limit, url = get_marker_limit_and_url(req)
        groups = service.get_user_groups(utils.get_auth_token(req),
                                        user_id, marker, limit, url)
        return utils.send_result(200, req, groups)


class GroupsController(wsgi.Controller):
    """
        Groups Controller -
        Controller for Group related operations
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_group(self, req):
        group = utils.get_normalized_request_content(tenants.GlobalGroup, req)
        return utils.send_result(201, req,
                       service.create_global_group(utils.get_auth_token(req),
                                                   group))

    @utils.wrap_error
    def get_groups(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        groups = service.get_global_groups(utils.get_auth_token(req),
                                         marker, limit, url)

        return utils.send_result(200, req, groups)

    @utils.wrap_error
    def get_group(self, req, group_id):
        tenant = service.get_global_group(utils.get_auth_token(req), group_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_group(self, req, group_id):
        group = utils.get_normalized_request_content(tenants.GlobalGroup, req)
        rval = service.update_global_group(utils.get_auth_token(req),
                                        group_id, group)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_group(self, req, group_id):
        rval = service.delete_global_group(utils.get_auth_token(req), group_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_users_global_group(self, req, group_id):
        marker, limit, url = get_marker_limit_and_url(req)
        users = service.get_users_global_group(utils.get_auth_token(req),
                                             group_id, marker, limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def add_user_global_group(self, req, group_id, user_id):

        return utils.send_result(201, req, service.add_user_global_group(\
                                utils.get_auth_token(req), group_id, user_id))

    @utils.wrap_error
    def delete_user_global_group(self, req, group_id, user_id):

        return utils.send_result(204, req, service.delete_user_global_group(\
                                utils.get_auth_token(req), group_id, user_id))


class RolesController(wsgi.Controller):
    """
        Roles Controller -
        Controller for Role related operations
    """

    def __init__(self, options):
        self.options = options

    # Not exposed yet.
    @utils.wrap_error
    def create_role(self, req):
        role = utils.get_normalized_request_content(roles.Role, req)
        return utils.send_result(201, req,
                       service.create_role(utils.get_auth_token(req),
                                                   role))

    @utils.wrap_error
    def get_roles(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        roles = service.get_roles(utils.get_auth_token(req),
                                         marker, limit, url)
        return utils.send_result(200, req, roles)

    @utils.wrap_error
    def get_role(self, req, role_id):
        role = service.get_role(utils.get_auth_token(req), role_id)
        return utils.send_result(200, req, role)

    @utils.wrap_error
    def create_role_ref(self, req, user_id):
        roleRef = utils.get_normalized_request_content(roles.RoleRef, req)
        return utils.send_result(201, req, service.create_role_ref(
            utils.get_auth_token(req), user_id, roleRef))

    @utils.wrap_error
    def get_role_refs(self, req, user_id):
        marker, limit, url = get_marker_limit_and_url(req)
        roleRefs = service.get_user_roles(utils.get_auth_token(req),
                                         marker, limit, url, user_id)

        return utils.send_result(200, req, roleRefs)

    @utils.wrap_error
    def delete_role_ref(self, req, user_id, role_ref_id):
        rval = service.delete_role_ref(utils.get_auth_token(req),
                                        role_ref_id)
        return utils.send_result(204, req, rval)


class EndpointTemplatesController(wsgi.Controller):
    """
        EndpointTemplatesController Controller -
        Controller for EndpointTemplates related operations
    """

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_endpoint_templates(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        endpoint_templates = service.get_endpoint_templates(\
            utils.get_auth_token(req), marker, limit, url)
        return utils.send_result(200, req, endpoint_templates)

    @utils.wrap_error
    def get_endpoint_template(self, req, endpoint_templates_id):
        endpoint_template = service.get_endpoint_template(\
            utils.get_auth_token(req), endpoint_templates_id)
        return utils.send_result(200, req, endpoint_template)

    @utils.wrap_error
    def get_endpoints_for_tenant(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        endpoints = service.get_tenant_endpoints(utils.get_auth_token(req),
                                         marker, limit, url, tenant_id)
        return utils.send_result(200, req, endpoints)

    @utils.wrap_error
    def add_endpoint_to_tenant(self, req, tenant_id):
        endpoint = utils.get_normalized_request_content(\
            endpoints.EndpointTemplate, req)
        return utils.send_result(201, req,
                       service.create_endpoint_for_tenant(
                                            utils.get_auth_token(req),
                                            tenant_id, endpoint, get_url(req)))

    @utils.wrap_error
    def remove_endpoint_from_tenant(self, req, tenant_id, endpoints_id):
        rval = service.delete_endpoint(utils.get_auth_token(req),
                                        endpoints_id)
        return utils.send_result(204, req, rval)


def get_marker_limit_and_url(req):
    marker = None
    limit = 10

    if "marker" in req.GET:
        marker = req.GET["marker"]

    if "limit" in req.GET:
        limit = req.GET["limit"]
    url = get_url(req)
    return (marker, limit, url)


def get_marker_and_limit(req):
    marker = None
    limit = 10

    if "marker" in req.GET:
        marker = req.GET["marker"]

    if "limit" in req.GET:
        limit = req.GET["limit"]


def get_url(req):
    url = '%s://%s:%s%s' % (req.environ['wsgi.url_scheme'],
                     req.environ.get("SERVER_NAME"),
                     req.environ.get("SERVER_PORT"),
                     req.environ['PATH_INFO'])
    return url


class KeystoneAPI(wsgi.Router):

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
        mapper.connect("/v2.0/", controller=version_controller,
                    action="get_version_info",
                    conditions=dict(method=["GET"]))
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

        super(KeystoneAPI, self).__init__(mapper)


class KeystoneAdminAPI(wsgi.Router):
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
        mapper.connect("/v2.0/", controller=version_controller,
                    action="get_version_info",
                    conditions=dict(method=["GET"]))
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

        super(KeystoneAdminAPI, self).__init__(mapper)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    try:
        conf = global_conf.copy()
        conf.update(local_conf)
    except Exception as err:
        print err
    return KeystoneAPI(conf)


def admin_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    try:
        conf = global_conf.copy()
        conf.update(local_conf)
    except Exception as err:
        print err
    return KeystoneAdminAPI(conf)
