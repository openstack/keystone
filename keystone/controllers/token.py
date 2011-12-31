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

from keystone import utils
from keystone.common import wsgi
from keystone.logic import extension_reader
from keystone.logic.types import auth
from keystone.logic.types import fault
from keystone.logic import service
from . import get_marker_limit_and_url

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class TokenController(wsgi.Controller):
    """Controller for token related operations"""

    def __init__(self, options):
        self.options = options
        self.identity_service = service.IdentityService(options)
        logger.debug("Token controller init with HP-IDM extension: %s" % \
                extension_reader.is_extension_supported(self.options, 'hpidm'))

    @utils.wrap_error
    def authenticate(self, req):
        try:
            auth_with_credentials = utils.get_normalized_request_content(
                auth.AuthWithPasswordCredentials, req)
            result = self.identity_service.authenticate(auth_with_credentials)
        except fault.BadRequestFault as e1:
            try:
                unscoped = utils.get_normalized_request_content(
                    auth.AuthWithUnscopedToken, req)
                result = self.identity_service.\
                    authenticate_with_unscoped_token(unscoped)
            except fault.BadRequestFault as e2:
                if e1.msg == e2.msg:
                    raise e1
                else:
                    raise fault.BadRequestFault(e1.msg + ' or ' + e2.msg)

        return utils.send_result(200, req, result)

    @utils.wrap_error
    def authenticate_ec2(self, req):
        creds = utils.get_normalized_request_content(auth.Ec2Credentials, req)
        return utils.send_result(200, req,
            self.identity_service.authenticate_ec2(creds))

    def _validate_token(self, req, token_id):
        """Validates the token, and that it belongs to the specified tenant"""
        belongs_to = req.GET.get('belongsTo')
        service_ids = None
        if extension_reader.is_extension_supported(self.options, 'hpidm'):
            # service IDs are only relevant if hpidm extension is enabled
            service_ids = req.GET.get('HP-IDM-serviceId')
        return self.identity_service.validate_token(
            utils.get_auth_token(req), token_id, belongs_to, service_ids)

    @utils.wrap_error
    def validate_token(self, req, token_id):
        result = self._validate_token(req, token_id)
        return utils.send_result(200, req, result)

    @utils.wrap_error
    def check_token(self, req, token_id):
        """Validates the token, but only returns a status code (HEAD)"""
        self._validate_token(req, token_id)
        return utils.send_result(200, req)

    @utils.wrap_error
    def delete_token(self, req, token_id):
        return utils.send_result(204, req,
            self.identity_service.revoke_token(utils.get_auth_token(req),
                token_id))

    @utils.wrap_error
    def endpoints(self, req, token_id):
        marker, limit, url = get_marker_limit_and_url(req)
        return utils.send_result(200, req,
            self.identity_service.get_endpoints_for_token(
                utils.get_auth_token(req),
                token_id, marker, limit, url))
