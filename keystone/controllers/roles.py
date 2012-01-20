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
Roles Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.models import Role
from keystone.logic import service

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class RolesController(BaseController):
    """Controller for Role related operations"""

    def __init__(self):
        self.identity_service = service.IdentityService()

    # Not exposed yet.
    @utils.wrap_error
    def create_role(self, req):
        role = utils.get_normalized_request_content(Role, req)
        return utils.send_result(201, req,
            self.identity_service.create_role(utils.get_auth_token(req), role))

    @utils.wrap_error
    def delete_role(self, req, role_id):
        rval = self.identity_service.delete_role(
            utils.get_auth_token(req), role_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_roles(self, req):
        role_name = req.GET["name"] if "name" in req.GET else None
        if role_name:
            return self.__get_roles_by_name(req, role_name)
        else:
            return self.__get_all_roles(req)

    def __get_roles_by_name(self, req, role_name):
        tenant = self.identity_service.get_role_by_name(
            utils.get_auth_token(req), role_name)
        return utils.send_result(200, req, tenant)

    def __get_all_roles(self, req):
        service_id = req.GET["serviceId"] if "serviceId" in req.GET else None
        marker, limit, url = self.get_marker_limit_and_url(req)
        if service_id:
            roles = self.identity_service.get_roles_by_service(
                utils.get_auth_token(req), marker, limit, url,
                service_id)
            return utils.send_result(200, req, roles)
        else:
            roles = self.identity_service.get_roles(
                utils.get_auth_token(req), marker, limit, url)
            return utils.send_result(200, req, roles)

    @utils.wrap_error
    def get_role(self, req, role_id):
        role = self.identity_service.get_role(utils.get_auth_token(req),
            role_id)
        return utils.send_result(200, req, role)

    @utils.wrap_error
    def add_role_to_user(self, req, user_id, role_id, tenant_id=None):
        self.identity_service.add_role_to_user(utils.get_auth_token(req),
            user_id, role_id, tenant_id)
        return utils.send_result(201, None)

    @utils.wrap_error
    def delete_role_from_user(self, req, user_id, role_id, tenant_id=None):
        self.identity_service.remove_role_from_user(utils.get_auth_token(req),
            user_id, role_id, tenant_id)
        return utils.send_result(204, req, None)

    @utils.wrap_error
    def get_user_roles(self, req, user_id, tenant_id=None):
        marker, limit, url = self.get_marker_limit_and_url(req)
        roles = self.identity_service.get_user_roles(
            utils.get_auth_token(req), marker, limit, url, user_id, tenant_id)
        return utils.send_result(200, req, roles)
