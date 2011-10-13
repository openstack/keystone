from keystone import utils
from keystone.common import wsgi
from keystone.logic.types.role import Role, RoleRef
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
        marker, limit, url = get_marker_limit_and_url(req)
        roles = config.SERVICE.get_roles(
            utils.get_auth_token(req), marker, limit, url)
        return utils.send_result(200, req, roles)

    @utils.wrap_error
    def get_role(self, req, role_id):
        role = config.SERVICE.get_role(utils.get_auth_token(req), role_id)
        return utils.send_result(200, req, role)

    @utils.wrap_error
    def create_role_ref(self, req, user_id):
        roleRef = utils.get_normalized_request_content(RoleRef, req)
        return utils.send_result(201, req, config.SERVICE.create_role_ref(
            utils.get_auth_token(req), user_id, roleRef))

    @utils.wrap_error
    def get_role_refs(self, req, user_id):
        marker, limit, url = get_marker_limit_and_url(req)
        roleRefs = config.SERVICE.get_user_roles(
            utils.get_auth_token(req), marker, limit, url, user_id)

        return utils.send_result(200, req, roleRefs)

    @utils.wrap_error
    def delete_role_ref(self, req, user_id, role_ref_id):
        rval = config.SERVICE.delete_role_ref(utils.get_auth_token(req),
            role_ref_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def add_global_role_to_user(self, req, user_id, role_id):
        config.SERVICE.add_global_role_to_user(utils.get_auth_token(req),
            user_id, role_id)
        return utils.send_result(201, None)
