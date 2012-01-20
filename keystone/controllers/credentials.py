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
Credentials Controller

"""
import logging

from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic import service
from keystone.logic.types.credential import PasswordCredentials

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class CredentialsController(BaseController):
    """Controller for Credentials related operations"""
    def __init__(self):
        self.identity_service = service.IdentityService()

    @utils.wrap_error
    def get_credentials(self, req, user_id):
        marker, limit, url = self.get_marker_limit_and_url(req)
        credentials = self.identity_service.get_credentials(
            utils.get_auth_token(req), user_id, marker, limit, url)
        return utils.send_result(200, req, credentials)

    @utils.wrap_error
    def get_password_credential(self, req, user_id):
        credentials = self.identity_service.get_password_credentials(
            utils.get_auth_token(req), user_id)
        return utils.send_result(200, req, credentials)

    @utils.wrap_error
    def delete_password_credential(self, req, user_id):
        self.identity_service.delete_password_credentials(
            utils.get_auth_token(req), user_id)
        return utils.send_result(204, None)

    @utils.wrap_error
    def add_credential(self, req, user_id):
        credential = utils.get_normalized_request_content(
            PasswordCredentials, req)
        credential = self.identity_service.create_password_credentials(
            utils.get_auth_token(req), user_id, credential)
        return utils.send_result(201, req, credential)

    @utils.wrap_error
    def update_password_credential(self, req, user_id):
        credential = utils.get_normalized_request_content(
            PasswordCredentials, req)
        credential = self.identity_service.update_password_credentials(
            utils.get_auth_token(req), user_id, credential)
        return utils.send_result(200, req, credential)
