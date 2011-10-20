from keystone import utils
from keystone.common import wsgi
import keystone.config as config
from keystone.logic.types.endpoint import EndpointTemplate
from . import get_url, get_marker_limit_and_url


class EndpointTemplatesController(wsgi.Controller):
    """Controller for EndpointTemplates related operations"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def get_endpoint_templates(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        endpoint_templates = config.SERVICE.get_endpoint_templates(
            utils.get_auth_token(req), marker, limit, url)
        return utils.send_result(200, req, endpoint_templates)

    @utils.wrap_error
    def add_endpoint_template(self, req):
        endpoint_template = utils.get_normalized_request_content(
            EndpointTemplate, req)
        return utils.send_result(201, req,
            config.SERVICE.add_endpoint_template(utils.get_auth_token(req),
                endpoint_template))

    @utils.wrap_error
    def modify_endpoint_template(self, req, endpoint_template_id):
        endpoint_template = utils.\
            get_normalized_request_content(EndpointTemplate, req)
        return utils.send_result(201, req,
            config.SERVICE.modify_endpoint_template(\
            utils.get_auth_token(req),
            endpoint_template_id, endpoint_template))

    @utils.wrap_error
    def delete_endpoint_template(self, req, endpoint_template_id):
        rval = config.SERVICE.delete_endpoint_template(
            utils.get_auth_token(req), endpoint_template_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_endpoint_template(self, req, endpoint_template_id):
        endpoint_template = config.SERVICE.get_endpoint_template(
            utils.get_auth_token(req), endpoint_template_id)
        return utils.send_result(200, req, endpoint_template)

    @utils.wrap_error
    def get_endpoints_for_tenant(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        endpoints = config.SERVICE.get_tenant_endpoints(
            utils.get_auth_token(req), marker, limit, url, tenant_id)
        return utils.send_result(200, req, endpoints)

    @utils.wrap_error
    def add_endpoint_to_tenant(self, req, tenant_id):
        endpoint = utils.get_normalized_request_content(EndpointTemplate, req)
        return utils.send_result(201, req,
            config.SERVICE.create_endpoint_for_tenant(
                utils.get_auth_token(req), tenant_id, endpoint))

    @utils.wrap_error
    def remove_endpoint_from_tenant(self, req, tenant_id, endpoint_id):
        rval = config.SERVICE.delete_endpoint(utils.get_auth_token(req),
                                        endpoint_id)
        return utils.send_result(204, req, rval)
