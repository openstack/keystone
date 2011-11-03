# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
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


#Base APIs
class BaseUserAPI(object):
    def get_all(self):
        raise NotImplementedError

    def create(self, values):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_name(self, name):
        raise NotImplementedError

    def get_by_email(self, email):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def user_roles_by_tenant(self, user_id, tenant_id):
        raise NotImplementedError

    def update(self, id, values):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get_by_tenant(self, id, tenant_id):
        raise NotImplementedError

    def get_by_access(self, access):
        raise NotImplementedError

    def delete_tenant_user(self, id, tenant_id):
        raise NotImplementedError

    def users_get_by_tenant(self, user_id, tenant_id):
        raise NotImplementedError

    def user_role_add(self, values):
        raise NotImplementedError

    def user_get_update(self, id):
        raise NotImplementedError

    def users_get_page(self, marker, limit):
        raise NotImplementedError

    def users_get_page_markers(self, marker, limit):
        raise NotImplementedError

    def users_get_by_tenant_get_page(self, tenant_id, role_id, marker, limit):
        raise NotImplementedError

    def users_get_by_tenant_get_page_markers(self, tenant_id,
        role_id, marker, limit):
        raise NotImplementedError

    def check_password(self, user, password):
        raise NotImplementedError


class BaseTokenAPI(object):
    def create(self, values):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get_for_user(self, user_id):
        raise NotImplementedError

    def get_for_user_by_tenant(self, user_id, tenant_id):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError


class BaseTenantAPI(object):
    def create(self, values):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_name(self, name):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def tenants_for_user_get_page(self, user, marker, limit):
        raise NotImplementedError

    def tenants_for_user_get_page_markers(self, user, marker, limit):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def is_empty(self, id):
        raise NotImplementedError

    def update(self, id, values):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get_all_endpoints(self, tenant_id):
        raise NotImplementedError

    def get_role_assignments(self, tenant_id):
        raise NotImplementedError


class BaseRoleAPI(object):
    def create(self, values):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_name(self, name):
        raise NotImplementedError

    def get_by_service(self, service_id):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def ref_get_page(self, marker, limit, user_id, tenant_id):
        raise NotImplementedError

    def ref_get_all_global_roles(self, user_id):
        raise NotImplementedError

    def ref_get_all_tenant_roles(self, user_id, tenant_id):
        raise NotImplementedError

    def ref_get(self, id):
        raise NotImplementedError

    def ref_get_by_role(self, id):
        raise NotImplementedError

    def ref_delete(self, id):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def ref_get_page_markers(self, user_id, tenant_id, marker, limit):
        raise NotImplementedError

    def ref_get_by_user(self, user_id, role_id, tenant_id):
        raise NotImplementedError


class BaseEndpointTemplateAPI(object):
    def create(self, values):
        raise NotImplementedError

    def update(self, id, values):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_by_service(self, service_id):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def endpoint_get_by_tenant_get_page(self, tenant_id, marker, limit):
        raise NotImplementedError

    def endpoint_get_by_tenant_get_page_markers(self, tenant_id, marker,
            limit):
        raise NotImplementedError

    def endpoint_get_by_endpoint_template(self, endpoint_template_id):
        raise NotImplementedError

    def endpoint_add(self, values):
        raise NotImplementedError

    def endpoint_get(self, id):
        raise NotImplementedError

    def endpoint_get_by_tenant(self, tenant_id):
        raise NotImplementedError

    def endpoint_delete(self, id):
        raise NotImplementedError


class BaseServiceAPI:
    def create(self, values):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_name(self, name):
        raise NotImplementedError

    def get_by_name_and_type(self, name, type):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError


class BaseCredentialsAPI(object):
    def create(self, values):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_access(self, access):
        raise NotImplementedError


#API
#TODO(Yogi) Refactor all API to separate classes specific to models.
ENDPOINT_TEMPLATE = BaseEndpointTemplateAPI()
ROLE = BaseRoleAPI()
TENANT = BaseTenantAPI()
TOKEN = BaseTokenAPI()
USER = BaseUserAPI()
SERVICE = BaseServiceAPI()
CREDENTIALS = BaseCredentialsAPI()


# Function to dynamically set module references.
def set_value(variable_name, value):
    if variable_name == 'endpoint_template':
        global ENDPOINT_TEMPLATE
        ENDPOINT_TEMPLATE = value
    elif variable_name == 'role':
        global ROLE
        ROLE = value
    elif variable_name == 'tenant':
        global TENANT
        TENANT = value
    elif variable_name == 'token':
        global TOKEN
        TOKEN = value
    elif variable_name == 'user':
        global USER
        USER = value
    elif variable_name == 'service':
        global SERVICE
        SERVICE = value
    elif variable_name == 'credentials':
        global CREDENTIALS
        CREDENTIALS = value
