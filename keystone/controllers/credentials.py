from keystone import utils
from keystone.common import wsgi
from keystone.logic.service import IdentityService
from keystone.logic.types.credential import PasswordCredentials
from . import get_marker_limit_and_url


class CredentialsController(wsgi.Controller):
    """Controller for Credentials related operations"""
    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_credentials(self, req, user_id):
        marker, limit, url = get_marker_limit_and_url(req)
        credentials = IdentityService.get_credentials(
            utils.get_auth_token(req), user_id, marker, limit, url)
        return utils.send_result(200, req, credentials)

    @utils.wrap_error
    def get_password_credential(self, req, user_id):
        credentials = IdentityService.get_password_credentials(
            utils.get_auth_token(req), user_id)
        return utils.send_result(200, req, credentials)

    @utils.wrap_error
    def delete_password_credential(self, req, user_id):
        IdentityService.delete_password_credentials(utils.get_auth_token(req),
            user_id)
        return utils.send_result(204, None)

    @utils.wrap_error
    def add_credential(self, req, user_id):
        credential = utils.get_normalized_request_content(
            PasswordCredentials, req)
        credential = IdentityService.create_password_credentials(
            utils.get_auth_token(req), user_id, credential)
        return utils.send_result(201, req, credential)

    @utils.wrap_error
    def update_password_credential(self, req, user_id):
        credential = utils.get_normalized_request_content(
            PasswordCredentials, req)
        credential = IdentityService.update_password_credentials(
            utils.get_auth_token(req), user_id, credential)
        return utils.send_result(200, req, credential)
