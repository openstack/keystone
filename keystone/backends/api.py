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
# Not Yet PEP8 standardized
#API
#TODO(Yogi) Refactor all API to separate classes specific to models.

#Base APIs
class BaseUserAPI(object):
    def get_all(self):
        pass

    def get_by_group(self, user_id, group_id):
        pass

    def tenant_group(self, values):
        pass

    def tenant_group_delete(self, id, group_id):
        pass

    def create(self, values):
        pass

    def get(self, id):
        pass

    def get_page(self, marker, limit):
        pass

    def get_page_markers(self, marker, limit):
        pass

    def get_by_email(self, email):
        pass

    def get_groups(self, id):
        pass

    def user_roles_by_tenant(self, user_id, tenant_id):
        pass

    def update(self, id, values):
        pass

    def users_tenant_group_get_page(self, group_id, marker):
        pass

    def users_tenant_group_get_page_markers(self, group_id, marker, limit):
        pass

    def delete(self, id):
        pass

    def get_by_tenant(self, id, tenant_id):
        pass

    def get_group_by_tenant(self, id):
        pass

    def delete_tenant_user(self, id, tenant_id):
        pass

    def users_get_by_tenant(self, user_id, tenant_id):
        pass

    def user_role_add(self, values):
        pass

    def user_get_update(self, id):
        pass

    def users_get_page(self, marker, limit):
        pass

    def users_get_page_markers(self, marker, limit):
        pass

    def users_get_by_tenant_get_page(self, tenant_id, marker, limit):
        pass

    def users_get_by_tenant_get_page_markers(self, tenant_id, marker, limit):
        pass

    def user_groups_get_all(self, user_id):
        pass


class BaseTokenAPI(object):
    def create(self, values):
        pass

    def get(self, id):
        pass

    def delete(self, id):
        pass

    def get_for_user(self, user_id):
        pass

    def get_for_user_by_tenant(self, user_id, tenant_id):
        pass

    def get_all(self):
        pass


class BaseTenantGroupAPI(object):
    def create(self, values):
        pass

    def is_empty(self, id):
        pass

    def get(self, id, tenant):
        pass

    def get_page(self, tenantId, marker, limit):
        pass

    def get_page_markers(self, tenantId, marker, limit):
        pass

    def update(self, id, tenant_id, values):
        pass

    def delete(self, id, tenant_id):
        pass


class BaseTenantAPI(object):

    def create(self, values):
        pass

    def get(self, id):
        pass

    def get_all(self):
        pass

    def tenants_for_user_get_page(self, user, marker, limit):
        pass

    def tenants_for_user_get_page_markers(self, user, marker, limit):
        pass

    def get_page(self, marker, limit):
        pass

    def get_page_markers(self, marker, limit):
        pass

    def is_empty(self, id):
        pass

    def update(self, id, values):
        pass

    def delete(self, id):
        pass

    def get_all_endpoints(self, tenant_id):
        pass

    def get_role_assignments(self, tenant_id):
        pass


class BaseRoleAPI(object):
    def create(self, values):
        pass

    def get(self, id):
        pass

    def get_all(self):
        pass

    def get_page(self, marker, limit):
        pass

    def ref_get_page(self, marker, limit, user_id):
        pass

    def ref_get_all_global_roles(self, user_id):
        pass

    def ref_get_all_tenant_roles(self, user_id, tenant_id):
        pass

    def ref_get(self, id):
        pass

    def ref_delete(self, id):
        pass

    def get_page_markers(self, marker, limit):
        pass

    def ref_get_page_markers(self, user_id, marker, limit):
        pass


class BaseGroupAPI(object):
    def get(self, id):
        pass

    def get_users(self, id):
        pass

    def get_all(self):
        pass

    def get_page(self, marker, limit):
        pass

    def get_page_markers(self, marker, limit):
        pass

    def delete(self, id):
        pass

    def get_by_user_get_page(self, user_id, marker, limit):
        pass

    def get_by_user_get_page_markers(self, user_id, marker, limit):
        pass


class BaseEndpointTemplateAPI(object):
    def create(self, values):
        pass

    def get(self, id):
        pass

    def get_all(self):
        pass

    def get_page(self, marker, limit):
        pass

    def get_page_markers(self, marker, limit):
        pass

    def endpoint_get_by_tenant_get_page(self, tenant_id, marker, limit):
        pass

    def endpoint_get_by_tenant_get_page_markers(self, tenant_id, marker,
            limit):
        pass

    def endpoint_add(self, values):
        pass

    def endpoint_get(self, id):
        pass

    def endpoint_get_by_tenant(self, tenant_id):
        pass

    def endpoint_delete(self, id):
        pass

endpoint_template = BaseEndpointTemplateAPI()
group = BaseGroupAPI()
role = BaseRoleAPI()
tenant_group = BaseTenantGroupAPI()
tenant = BaseTenantAPI()
token = BaseTokenAPI()
user = BaseUserAPI()

# Function to dynamically set module references.
def set_value(variable_name, value):
    if variable_name == 'endpoint_template':
        global endpoint_template
        endpoint_template = value
    elif variable_name == 'group':
        global group
        group = value
    elif variable_name == 'role':
        global role
        role = value
    elif variable_name == 'tenant_group':
        global tenant_group
        tenant_group = value
    elif variable_name == 'tenant':
        global tenant
        tenant = value
    elif variable_name == 'token':
        global token
        token = value
    elif variable_name == 'user':
        global user
        user = value
