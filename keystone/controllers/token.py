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
Token Controller

This module contains the TokenController class which receives token-related
calls from the request routers.

"""
import logging

from keystone import config
from keystone import utils
from keystone.controllers.base_controller import BaseController
from keystone.logic import extension_reader
from keystone.logic.types import auth
from keystone.logic.types import fault
from keystone.logic import service

CONF = config.CONF
logger = logging.getLogger(__name__)  # pylint: disable=C0103


class TokenController(BaseController):
    """Controller for token related operations"""

    def __init__(self):
        self.identity_service = service.IdentityService()
        logger.debug("Token controller init with HP-IDM extension: %s" % \
                extension_reader.is_extension_supported('hpidm'))

    @utils.wrap_error
    def authenticate(self, req):
        credential_type = utils.detect_credential_type(req)
        if credential_type == "passwordCredentials":
            auth_with_credentials = utils.get_normalized_request_content(
                    auth.AuthWithPasswordCredentials, req)
            result = self.identity_service.authenticate(
                    auth_with_credentials)
            return utils.send_result(200, req, result)
        elif credential_type == "token":
            unscoped = utils.get_normalized_request_content(
                auth.AuthWithUnscopedToken, req)
            result = self.identity_service.\
                authenticate_with_unscoped_token(unscoped)
            return utils.send_result(200, req, result)
        elif credential_type == "OS-KSEC2:ec2Credentials":
            return self._authenticate_ec2(req)
        elif credential_type == "OS-KSS3:s3Credentials":
            return self._authenticate_s3(req)
        elif credential_type in ["ec2Credentials", "OS-KSEC2-ec2Credentials"]:
            logger.warning('Received EC2 credentials in %s format. Processing '
                           'may fail. Update the client code sending this '
                           'format' % credential_type)
            return self._authenticate_ec2(req)
        else:
            raise fault.BadRequestFault("Invalid credentials %s" %
                                        credential_type)

    @utils.wrap_error
    def authenticate_ec2(self, req):
        return self._authenticate_ec2(req)

    def _authenticate_ec2(self, req):
        """Undecorated EC2 handler"""
        creds = utils.get_normalized_request_content(auth.Ec2Credentials, req)
        return utils.send_result(200, req,
                self.identity_service.authenticate_ec2(creds))

    @utils.wrap_error
    def authenticate_s3(self, req):
        return self._authenticate_s3(req)

    def _authenticate_s3(self, req):
        """Undecorated S3 handler"""
        creds = utils.get_normalized_request_content(auth.S3Credentials, req)
        return utils.send_result(200, req,
            self.identity_service.authenticate_s3(creds))

    def _validate_token(self, req, token_id):
        """Validates the token, and that it belongs to the specified tenant"""
        belongs_to = req.GET.get('belongsTo')
        service_ids = None
        if extension_reader.is_extension_supported('hpidm'):
            # service IDs are only relevant if hpidm extension is enabled
            service_ids = req.GET.get('HP-IDM-serviceId')
        return self.identity_service.validate_token(
                utils.get_auth_token(req), token_id, belongs_to, service_ids)

    @utils.wrap_error
    def validate_token(self, req, token_id):
        if CONF.disable_tokens_in_url:
            fault.ServiceUnavailableFault()
        else:
            result = self._validate_token(req, token_id)
            return utils.send_result(200, req, result)

    @utils.wrap_error
    def check_token(self, req, token_id):
        """Validates the token, but only returns a status code (HEAD)"""
        if CONF.disable_tokens_in_url:
            fault.ServiceUnavailableFault()
        else:
            self._validate_token(req, token_id)
            return utils.send_result(200, req)

    @utils.wrap_error
    def delete_token(self, req, token_id):
        if CONF.disable_tokens_in_url:
            fault.ServiceUnavailableFault()
        else:
            return utils.send_result(204, req,
                    self.identity_service.revoke_token(
                            utils.get_auth_token(req), token_id))

    @utils.wrap_error
    def endpoints(self, req, token_id):
        if CONF.disable_tokens_in_url:
            fault.ServiceUnavailableFault()
        else:
            marker, limit, url = self.get_marker_limit_and_url(req)
            return utils.send_result(200, req,
                    self.identity_service.get_endpoints_for_token(
                            utils.get_auth_token(req),
                            token_id, marker, limit, url))
