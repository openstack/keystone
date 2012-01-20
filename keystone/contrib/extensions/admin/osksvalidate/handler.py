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
Router & Controller for handling Secure Token Validation

"""
import logging

from keystone.common import wsgi
from keystone.controllers.token import TokenController

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class SecureValidationController(wsgi.Controller):
    """Controller for Tenant related operations"""

    # pylint: disable=W0231
    def __init__(self):
        self.token_controller = TokenController()

        logger.info("Initializing Secure Token Validation extension")

    def handle_validate_request(self, req):
        token_id = req.headers.get("X-Subject-Token")
        return self.token_controller.validate_token(req=req, token_id=token_id)

    def handle_endpoints_request(self, req):
        token_id = req.headers.get("X-Subject-Token")
        return self.token_controller.endpoints(req=req, token_id=token_id)
