from keystone import utils
from keystone.common import wsgi
from keystone.logic.types import auth
import keystone.config as config


class AuthController(wsgi.Controller):
    """Controller for token related operations"""

    def __init__(self, options):
        self.options = options
        self.request = None

    @utils.wrap_error
    def authenticate(self, req):
        self.request = req

        creds = utils.get_normalized_request_content(
            auth.PasswordCredentials, req)
        return utils.send_result(200, req, config.SERVICE.authenticate(creds))

    @utils.wrap_error
    def authenticate_ec2(self, req):
        self.request = req

        creds = utils.get_normalized_request_content(
            auth.Ec2Credentials, req)
        return utils.send_result(200, req,
                                 config.SERVICE.authenticate_ec2(creds))

    @utils.wrap_error
    def validate_token(self, req, token_id):
        belongs_to = req.GET["belongsTo"] if "belongsTo" in req.GET else None

        rval = config.SERVICE.validate_token(
            utils.get_auth_token(req), token_id, belongs_to)

        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_token(self, req, token_id):
        return utils.send_result(204, req,
            config.SERVICE.revoke_token(utils.get_auth_token(req), token_id))
