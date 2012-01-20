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
EndpointTemplates Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic import service
from keystone.logic.types.endpoint import EndpointTemplate

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class EndpointTemplatesController(BaseController):
    """Controller for EndpointTemplates related operations"""

    def __init__(self):
        self.identity_service = service.IdentityService()

    @utils.wrap_error
    def get_endpoint_templates(self, req):
        marker, limit, url = self.get_marker_limit_and_url(req)
        service_id = req.GET["serviceId"] if "serviceId" in req.GET else None
        if service_id:
            endpoint_templates = self.identity_service.\
                get_endpoint_templates_by_service(
                utils.get_auth_token(req), service_id, marker, limit, url)
        else:
            endpoint_templates = self.identity_service.get_endpoint_templates(
                utils.get_auth_token(req), marker, limit, url)
        return utils.send_result(200, req, endpoint_templates)

    @utils.wrap_error
    def add_endpoint_template(self, req):
        endpoint_template = utils.get_normalized_request_content(
            EndpointTemplate, req)
        return utils.send_result(201, req,
            self.identity_service.add_endpoint_template(
                utils.get_auth_token(req), endpoint_template))

    @utils.wrap_error
    def modify_endpoint_template(self, req, endpoint_template_id):
        endpoint_template = utils.\
            get_normalized_request_content(EndpointTemplate, req)
        return utils.send_result(201, req,
            self.identity_service.modify_endpoint_template(\
            utils.get_auth_token(req),
            endpoint_template_id, endpoint_template))

    @utils.wrap_error
    def delete_endpoint_template(self, req, endpoint_template_id):
        rval = self.identity_service.delete_endpoint_template(
            utils.get_auth_token(req), endpoint_template_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_endpoint_template(self, req, endpoint_template_id):
        endpoint_template = self.identity_service.get_endpoint_template(
            utils.get_auth_token(req), endpoint_template_id)
        return utils.send_result(200, req, endpoint_template)

    @utils.wrap_error
    def get_endpoints_for_tenant(self, req, tenant_id):
        marker, limit, url = self.get_marker_limit_and_url(req)
        endpoints = self.identity_service.get_tenant_endpoints(
            utils.get_auth_token(req), marker, limit, url, tenant_id)
        return utils.send_result(200, req, endpoints)

    @utils.wrap_error
    def add_endpoint_to_tenant(self, req, tenant_id):
        endpoint = utils.get_normalized_request_content(EndpointTemplate, req)
        return utils.send_result(201, req,
            self.identity_service.create_endpoint_for_tenant(
                utils.get_auth_token(req), tenant_id, endpoint))

    @utils.wrap_error
    def remove_endpoint_from_tenant(self, req, tenant_id, endpoint_id):
        rval = self.identity_service.delete_endpoint(utils.get_auth_token(req),
                                        endpoint_id)
        return utils.send_result(204, req, rval)
