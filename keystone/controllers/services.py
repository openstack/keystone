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
Services Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.models import Service
from keystone.logic import service

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class ServicesController(BaseController):
    """Controller for Service related operations"""

    def __init__(self):
        self.identity_service = service.IdentityService()

    @utils.wrap_error
    def create_service(self, req):
        service = utils.get_normalized_request_content(Service, req)
        return utils.send_result(201, req,
            self.identity_service.create_service(utils.get_auth_token(req),
                service))

    @utils.wrap_error
    def get_services(self, req):
        service_name = req.GET["name"] if "name" in req.GET else None
        if service_name:
            tenant = self.identity_service.get_service_by_name(
                    utils.get_auth_token(req), service_name)
            return utils.send_result(200, req, tenant)
        else:
            marker, limit, url = self.get_marker_limit_and_url(req)
            services = self.identity_service.get_services(
                utils.get_auth_token(req), marker, limit, url)
            return utils.send_result(200, req, services)

    @utils.wrap_error
    def get_service(self, req, service_id):
        service = self.identity_service.get_service(
            utils.get_auth_token(req), service_id)
        return utils.send_result(200, req, service)

    @utils.wrap_error
    def delete_service(self, req, service_id):
        rval = self.identity_service.delete_service(utils.get_auth_token(req),
            service_id)
        return utils.send_result(204, req, rval)
