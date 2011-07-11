from keystone import utils
from keystone.common import wsgi
import keystone.config as config
from keystone.logic.types.tenant import Tenant, Group
from . import get_marker_limit_and_url

class TenantController(wsgi.Controller):
    """Controller for Tenant and Tenant Group related operations"""

    def __init__(self, options):
        self.options = options

    @utils.wrap_error
    def create_tenant(self, req):
        tenant = utils.get_normalized_request_content(Tenant, req)
        return utils.send_result(201, req,
            config.SERVICE.create_tenant(utils.get_auth_token(req), tenant))

    @utils.wrap_error
    def get_tenants(self, req):
        marker, limit, url = get_marker_limit_and_url(req)
        tenants = config.SERVICE.get_tenants(utils.get_auth_token(req),
            marker, limit, url)
        return utils.send_result(200, req, tenants)

    @utils.wrap_error
    def get_tenant(self, req, tenant_id):
        tenant = config.SERVICE.get_tenant(utils.get_auth_token(req),
            tenant_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_tenant(self, req, tenant_id):
        tenant = utils.get_normalized_request_content(Tenant, req)
        rval = config.SERVICE.update_tenant(utils.get_auth_token(req),
            tenant_id, tenant)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_tenant(self, req, tenant_id):
        rval = config.SERVICE.delete_tenant(utils.get_auth_token(req),
            tenant_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def create_tenant_group(self, req, tenant_id):
        group = utils.get_normalized_request_content(Group, req)
        return utils.send_result(201, req, config.SERVICE.create_tenant_group(
            utils.get_auth_token(req), tenant_id, group))

    @utils.wrap_error
    def get_tenant_groups(self, req, tenant_id):
        marker, limit, url = get_marker_limit_and_url(req)
        groups = config.SERVICE.get_tenant_groups(utils.get_auth_token(req),
            tenant_id, marker, limit, url)
        return utils.send_result(200, req, groups)

    @utils.wrap_error
    def get_tenant_group(self, req, tenant_id, group_id):
        tenant = config.SERVICE.get_tenant_group(utils.get_auth_token(req),
            tenant_id, group_id)
        return utils.send_result(200, req, tenant)

    @utils.wrap_error
    def update_tenant_group(self, req, tenant_id, group_id):
        group = utils.get_normalized_request_content(Group, req)
        rval = config.SERVICE.update_tenant_group(utils.get_auth_token(req),
            tenant_id, group_id, group)
        return utils.send_result(200, req, rval)

    @utils.wrap_error
    def delete_tenant_group(self, req, tenant_id, group_id):
        rval = config.SERVICE.delete_tenant_group(utils.get_auth_token(req),
            tenant_id, group_id)
        return utils.send_result(204, req, rval)

    @utils.wrap_error
    def get_users_tenant_group(self, req, tenant_id, group_id):
        marker, limit, url = get_marker_limit_and_url(req)
        users = config.SERVICE.get_users_tenant_group(
            utils.get_auth_token(req), tenant_id, group_id, marker, limit, url)
        return utils.send_result(200, req, users)

    @utils.wrap_error
    def add_user_tenant_group(self, req, tenant_id, group_id, user_id):
        return utils.send_result(201, req,
            config.SERVICE.add_user_tenant_group(utils.get_auth_token(req),
                tenant_id, group_id, user_id))

    @utils.wrap_error
    def delete_user_tenant_group(self, req, tenant_id, group_id, user_id):
        return utils.send_result(204, req,
            config.SERVICE.delete_user_tenant_group(utils.get_auth_token(req),
                tenant_id, group_id, user_id))
