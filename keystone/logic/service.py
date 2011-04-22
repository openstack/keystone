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

import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenant
import keystone.logic.types.atom as atom
import keystone.logic.types.fault as fault

import keystone.db.sqlalchemy.api as db_api

class IDMService(object):
    "This is the logical implemenation of the IDM service"

    #
    #  Token Operations
    #
    def authenticate(self, credentials):
        if not isinstance(credentials, auth.PasswordCredentials):
            raise fault.BadRequestFault("Expecting Password Credentials!")
        True

    def validate_token(self, admin_token, token_id, belongs_to=None):
        self.__validate_admin_token(admin_token)
        group1 = auth.Group("Admin","19928")
        group2 = auth.Group("Other","28882")
        gs = [group1, group2]
        groups = auth.Groups(gs,[])
        user = auth.User("joeuser","19928", groups)
        token = auth.Token ("2010-11-01T03:32:15-05:00", "388376625525637773")
        return auth.AuthData(token, user)

    def revoke_token(self, admin_token, token_id):
        True

    #
    #   Tenant Operations
    #
    def create_tenant(self, admin_token, tenant):
        if not isinstance(tenant, tenant.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")
        True

    def get_tenant(self, admin_token, tenant_id):
        True

    def get_tenants(self, admin_token, marker, limit):
        True

    def update_tenant(self, admin_token, tenant):
        if not isinstance(tenant, tenant.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")
        True

    def delete_tenant(self, admin_token, tenant_id):
        True

    #
    # Private Operations
    #
    def __validate_admin_token(self, admin_token):
        if not admin_token:
            raise fault.UnauthorizedFault("Missing admin token")
        token = db_api.token_get(admin_token)
        if not token:
            raise fault.UnauthorizedFault("Bad token, please reauthenticate")

