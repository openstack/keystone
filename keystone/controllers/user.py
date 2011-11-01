from keystone import utils
from keystone.common import wsgi
import keystone.config as config
from keystone.logic.types.user import User, User_Update
from . import get_marker_limit_and_url


class UserController(wsgi.Controller):
    """Controller for User related operations"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_user(self, req):
        u = utils.get_normalized_request_content(User, req)
        return utils.send_result(201, req, config.SERVICE.create_user(
            utils.get_auth_token(req), u))

    @utils.wrap_error
    def get_users(self, req):
        user_name = req.GET["name"] if "name" in req.GET else None
        if user_name:
            tenant = config.SERVICE.get_user_by_name(
                utils.get_auth_token(req),
                user_name)
            return utils.send_result(200, req, tenant)
        else:
            marker, limit, url = get_marker_limit_and_url(req)
            users = config.SERVICE.get_users(utils.get_auth_token(req), marker,
                limit, url)
            return utils.send_result(200, req, users)

    @utils.wrap_error
    def get_user(self, req, user_id):
        user = config.SERVICE.get_user(utils.get_auth_token(req), user_id)
        return utils.send_result(200, req, user)

    @utils.wrap_error
    def update_user(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = config.SERVICE.update_user(utils.get_auth_token(req), user_id,
            user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_user(self, req, user_id):
        rval = config.SERVICE.delete_user(utils.get_auth_token(req), user_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def set_user_password(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = config.SERVICE.set_user_password(utils.get_auth_token(req),
            user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def set_user_enabled(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = config.SERVICE.enable_disable_user(utils.get_auth_token(req),
            user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def update_user_tenant(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = config.SERVICE.set_user_tenant(utils.get_auth_token(req),
            user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def get_tenant_users(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        role_id = req.GET["roleId"] if "roleId" in req.GET else None
        users = config.SERVICE.get_tenant_users(utils.get_auth_token(req),
            tenant_id, role_id, marker, limit, url)
        return utils.send_result(200, req, users)
