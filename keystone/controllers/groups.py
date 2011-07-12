from keystone import utils
from keystone.common import wsgi
import keystone.config as config
from keystone.logic.types.tenant import GlobalGroup
from . import get_marker_limit_and_url

class GroupsController(wsgi.Controller):
    """Controller for Group related operations"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_group(self, req):
        group = utils.get_normalized_request_content(GlobalGroup, req)
        return utils.send_result(201, req,
            config.SERVICE.create_global_group(utils.get_auth_token(req),
                group))

    @utils.wrap_error
    def get_groups(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        groups = config.SERVICE.get_global_groups(
            utils.get_auth_token(req), marker, limit, url)

        return utils.send_result(200, req, groups)

    @utils.wrap_error
    def get_group(self, req, group_id):
        tenant = config.SERVICE.get_global_group(utils.get_auth_token(req),
            group_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_group(self, req, group_id):
        group = utils.get_normalized_request_content(GlobalGroup, req)
        rval = config.SERVICE.update_global_group(
            utils.get_auth_token(req), group_id, group)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_group(self, req, group_id):
        rval = config.SERVICE.delete_global_group(utils.get_auth_token(req),
            group_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_users_global_group(self, req, group_id):
        marker, limit, url = get_marker_limit_and_url(req)
        users = config.SERVICE.get_users_global_group(
            utils.get_auth_token(req), group_id, marker, limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def add_user_global_group(self, req, group_id, user_id):

        return utils.send_result(201, req,
            config.SERVICE.add_user_global_group(utils.get_auth_token(req),
                group_id, user_id))

    @utils.wrap_error
    def delete_user_global_group(self, req, group_id, user_id):

        return utils.send_result(204, req,
            config.SERVICE.delete_user_global_group(utils.get_auth_token(req),
                group_id, user_id))
