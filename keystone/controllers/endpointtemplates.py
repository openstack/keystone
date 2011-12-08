from keystone import utils
from keystone.common import wsgi
from keystone.logic import service
from keystone.logic.types.endpoint import EndpointTemplate
from . import get_marker_limit_and_url


class EndpointTemplatesController(wsgi.Controller):
    """Controller for EndpointTemplates related operations"""

    def __init__(self, options):
        self.options = options
        self.identity_service = service.IdentityService(options)

    @utils.wrap_error
    def get_endpoint_templates(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
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
        marker, limit, url = get_marker_limit_and_url(req)
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
