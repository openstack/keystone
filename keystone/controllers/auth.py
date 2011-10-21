from keystone import utils
from keystone.common import wsgi
from keystone.logic.types import auth
from keystone.logic.types import fault
import keystone.config as config
from . import get_marker_limit_and_url


class AuthController(wsgi.Controller):
    """Controller for token related operations"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def authenticate(self, req):
        try:
            auth_with_credentials = utils.get_normalized_request_content(
                auth.AuthWithPasswordCredentials, req)
            result = config.SERVICE.authenticate(auth_with_credentials)
        except fault.BadRequestFault as e1:
            try:
                unscoped = utils.get_normalized_request_content(
                    auth.AuthWithUnscopedToken, req)
                result = config.SERVICE.authenticate_with_unscoped_token(
                    unscoped)
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
            config.SERVICE.authenticate_ec2(creds))

    def _validate_token(self, req, token_id):
        """Validates the token, and that it belongs to the specified tenant"""
        belongs_to = req.GET.get('belongsTo')
        return config.SERVICE.validate_token(
            utils.get_auth_token(req), token_id, belongs_to)

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
            config.SERVICE.revoke_token(utils.get_auth_token(req), token_id))

    @utils.wrap_error
    def endpoints(self, req, token_id):
        marker, limit, url = get_marker_limit_and_url(req)
        return utils.send_result(200, req,
            config.SERVICE.get_endpoints_for_token(
                utils.get_auth_token(req),
                token_id, marker, limit, url))
