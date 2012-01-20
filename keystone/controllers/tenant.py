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
Tenant Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic import service
from keystone.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class TenantController(BaseController):
    """Controller for Tenant related operations"""

    def __init__(self, is_service_operation=None):
        self.identity_service = service.IdentityService()
        self.is_service_operation = is_service_operation
        logger.debug("Initializing: 'Service API' mode=%s" %
                     self.is_service_operation)

    @utils.wrap_error
    def create_tenant(self, req):
        tenant = utils.get_normalized_request_content(Tenant, req)
        return utils.send_result(201, req,
            self.identity_service.create_tenant(utils.get_auth_token(req),
                tenant))

    @utils.wrap_error
    def get_tenants(self, req):
        tenant_name = req.GET["name"] if "name" in req.GET else None
        if tenant_name:
            tenant = self.identity_service.get_tenant_by_name(
                utils.get_auth_token(req),
                tenant_name)
            return utils.send_result(200, req, tenant)
        else:
            marker, limit, url = self.get_marker_limit_and_url(req)
            tenants = self.identity_service.get_tenants(
                utils.get_auth_token(req), marker, limit, url,
                self.is_service_operation)
            return utils.send_result(200, req, tenants)

    @utils.wrap_error
    def get_tenant(self, req, tenant_id):
        tenant = self.identity_service.get_tenant(utils.get_auth_token(req),
            tenant_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_tenant(self, req, tenant_id):
        tenant = utils.get_normalized_request_content(Tenant, req)
        rval = self.identity_service.update_tenant(utils.get_auth_token(req),
            tenant_id, tenant)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_tenant(self, req, tenant_id):
        rval = self.identity_service.delete_tenant(utils.get_auth_token(req),
            tenant_id)
        return utils.send_result(204, req, rval)
