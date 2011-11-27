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

from keystone.backends.api import BaseUserAPI


#Base APIs
class RAXEXTBaseUserAPI(BaseUserAPI):

    def get_by_group(self, user_id, group_id):
        raise NotImplementedError

    def tenant_group(self, values):
        raise NotImplementedError

    def tenant_group_delete(self, id, group_id):
        raise NotImplementedError

    def get_groups(self, id):
        raise NotImplementedError

    def users_tenant_group_get_page(self, group_id, marker, limit):
        raise NotImplementedError

    def users_tenant_group_get_page_markers(self, group_id, marker, limit):
        raise NotImplementedError

    def get_group_by_tenant(self, id):
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


class RAXEXTBaseTenantGroupAPI(object):
    def create(self, values):
        raise NotImplementedError

    def is_empty(self, id):
        raise NotImplementedError

    def get(self, id, tenant):
        raise NotImplementedError

    def get_page(self, tenant_id, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, tenant_id, marker, limit):
        raise NotImplementedError

    def update(self, id, tenant_id, values):
        raise NotImplementedError

    def delete(self, id, tenant_id):
        raise NotImplementedError


class RAXEXTBaseGroupAPI(object):
    def get(self, id):
        raise NotImplementedError

    def get_users(self, id):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get_by_user_get_page(self, user_id, marker, limit):
        raise NotImplementedError

    def get_by_user_get_page_markers(self, user_id, marker, limit):
        raise NotImplementedError


#API
#TODO(Yogi) Refactor all API to separate classes specific to models.
GROUP = RAXEXTBaseGroupAPI()
TENANT_GROUP = RAXEXTBaseTenantGroupAPI()
USER = RAXEXTBaseUserAPI()


# Function to dynamically set module references.
def set_value(variable_name, value):
    if variable_name == 'group':
        global GROUP
        GROUP = value
    elif variable_name == 'tenant_group':
        global TENANT_GROUP
        TENANT_GROUP = value
    elif variable_name == 'user':
        global USER
        USER = value
