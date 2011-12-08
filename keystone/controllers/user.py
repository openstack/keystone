from keystone import utils
from keystone.common import wsgi
from keystone.logic import service
from keystone.logic.types.user import User, User_Update
from . import get_marker_limit_and_url


class UserController(wsgi.Controller):
    """Controller for User related operations"""

    def __init__(self, options):
        self.options = options
        self.identity_service = service.IdentityService(options)

    @utils.wrap_error
    def create_user(self, req):
        u = utils.get_normalized_request_content(User, req)
        return utils.send_result(201, req, self.identity_service.create_user(
            utils.get_auth_token(req), u))

    @utils.wrap_error
    def get_users(self, req):
        user_name = req.GET["name"] if "name" in req.GET else None
        if user_name:
            tenant = self.identity_service.get_user_by_name(
                utils.get_auth_token(req),
                user_name)
            return utils.send_result(200, req, tenant)
        else:
            marker, limit, url = get_marker_limit_and_url(req)
            users = self.identity_service.get_users(utils.get_auth_token(req),
                marker, limit, url)
            return utils.send_result(200, req, users)

    @utils.wrap_error
    def get_user(self, req, user_id):
        user = self.identity_service.get_user(utils.get_auth_token(req),
            user_id)
        return utils.send_result(200, req, user)

    @utils.wrap_error
    def update_user(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = self.identity_service.update_user(utils.get_auth_token(req),
            user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_user(self, req, user_id):
        rval = self.identity_service.delete_user(utils.get_auth_token(req),
            user_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def set_user_password(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = self.identity_service.set_user_password(
            utils.get_auth_token(req), user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def set_user_enabled(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = self.identity_service.enable_disable_user(
            utils.get_auth_token(req), user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def update_user_tenant(self, req, user_id):
        user = utils.get_normalized_request_content(User_Update, req)
        rval = self.identity_service.set_user_tenant(utils.get_auth_token(req),
            user_id, user)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def get_tenant_users(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        role_id = req.GET["roleId"] if "roleId" in req.GET else None
        users = self.identity_service.get_tenant_users(
            utils.get_auth_token(req), tenant_id, role_id, marker, limit, url)
        return utils.send_result(200, req, users)
