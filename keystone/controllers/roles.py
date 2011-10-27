from keystone import utils
from keystone.common import wsgi
from keystone.logic.types.role import Role
import keystone.config as config
from . import get_marker_limit_and_url


class RolesController(wsgi.Controller):
    """Controller for Role related operations"""

    def __init__(self, options):
        self.options = options

    # Not exposed yet.
    @utils.wrap_error
    def create_role(self, req):
        role = utils.get_normalized_request_content(Role, req)
        return utils.send_result(201, req,
            config.SERVICE.create_role(utils.get_auth_token(req), role))

    @utils.wrap_error
    def delete_role(self, req, role_id):
        rval = config.SERVICE.delete_role(utils.get_auth_token(req), role_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_roles(self, req):
        role_name = req.GET["name"] if "name" in req.GET else None
        if role_name:
            tenant = config.SERVICE.get_role_by_name(
                utils.get_auth_token(req), role_name)
            return utils.send_result(200, req, tenant)
        else:
            marker, limit, url = get_marker_limit_and_url(req)
            roles = config.SERVICE.get_roles(
                utils.get_auth_token(req), marker, limit, url)
            return utils.send_result(200, req, roles)

    @utils.wrap_error
    def get_role(self, req, role_id):
        role = config.SERVICE.get_role(utils.get_auth_token(req), role_id)
        return utils.send_result(200, req, role)

    @utils.wrap_error
    def add_role_to_user(self, req, user_id, role_id, tenant_id=None):
        config.SERVICE.add_role_to_user(utils.get_auth_token(req),
            user_id, role_id, tenant_id)
        return utils.send_result(201, None)

    @utils.wrap_error
    def delete_role_from_user(self, req, user_id, role_id, tenant_id=None):
        config.SERVICE.remove_role_from_user(utils.get_auth_token(req),
            user_id, role_id, tenant_id)
        return utils.send_result(204, req, None)

    @utils.wrap_error
    def get_user_roles(self, req, user_id, tenant_id=None):
        marker, limit, url = get_marker_limit_and_url(req)
        roles = config.SERVICE.get_user_roles(
            utils.get_auth_token(req), marker, limit, url, user_id, tenant_id)
        return utils.send_result(200, req, roles)
