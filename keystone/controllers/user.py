# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
User Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic import service
from keystone.logic.types.user import User, User_Update

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class UserController(BaseController):
    """Controller for User related operations"""

    def __init__(self):
        self.identity_service = service.IdentityService()

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
            marker, limit, url = self.get_marker_limit_and_url(req)
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
        marker, limit, url = self.get_marker_limit_and_url(req)
        role_id = req.GET["roleId"] if "roleId" in req.GET else None
        users = self.identity_service.get_tenant_users(
            utils.get_auth_token(req), tenant_id, role_id, marker, limit, url)
        return utils.send_result(200, req, users)
