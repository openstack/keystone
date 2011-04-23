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

from datetime import datetime
from datetime import timedelta

import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenants
import keystone.logic.types.atom as atom
import keystone.logic.types.fault as fault

import keystone.db.sqlalchemy.api as db_api
import keystone.db.sqlalchemy.models as db_models

import uuid

class IDMService(object):
    "This is the logical implemenation of the IDM service"

    #
    #  Token Operations
    #
    def authenticate(self, credentials):
        if not isinstance(credentials, auth.PasswordCredentials):
            raise fault.BadRequestFault("Expecting Password Credentials!")

        duser = db_api.user_get(credentials.username)
        if duser == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not duser.enabled:
            raise fault.UserDisabledFault("Your account has been disabled")
        if duser.password != credentials.password:
            raise fault.UnauthorizedFault("Unauthorized")

        #
        # Look for an existing token, or create one,
        # TODO: Handle tenant/token search
        #
        dtoken = db_api.token_for_user(duser.id)
        if not dtoken or dtoken.expires < datetime.now():
            dtoken=db_models.Token()
            dtoken.token_id = str(uuid.uuid4())
            dtoken.user_id = duser.id
            dtoken.tenant_id = duser.tenants[0].tenant_id
            dtoken.expires = datetime.now() + timedelta(days=1)

            db_api.token_create (dtoken)

        return self.__get_auth_data(dtoken, duser)

    def validate_token(self, admin_token, token_id, belongs_to=None):
        self.__validate_token(admin_token)

        dauth = self.__get_dauth_data(token_id)
        dtoken = dauth[0]
        duser = dauth[1]

        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        if dtoken.expires < datetime.now():
            raise fault.ItemNotFoundFault("Token not found")

        if belongs_to != None and dtoken.tenant_id != belongs_to:
            raise fault.ItemNotFoundFault("Token not found")

        return self.__get_auth_data(dtoken, duser)

    def revoke_token(self, admin_token, token_id):
        self.__validate_token(admin_token)

        dtoken = db_api.token_get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        db_api.token_delete(token_id)

        return None

    #
    #   Tenant Operations
    #
    def create_tenant(self, admin_token, tenant):
        self.__validate_token(admin_token)

        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        if db_api.tenant_get(tenant.tenant_id) != None:
            raise fault.TenantConflictFault("A tenant with that id already exists")

        dtenant = db_models.Tenant()
        dtenant.id = tenant.tenant_id
        dtenant.desc = tenant.description
        dtenant.enabled = tenant.enabled

        db_api.tenant_create(dtenant)

        return tenant

    def get_tenants(self, admin_token, marker, limit):
        self.__validate_token(admin_token)

        ts = []
        dtenants = db_api.tenant_get_all()
        for dtenant in dtenants:
            ts.append (tenants.Tenant(dtenant.id, dtenant.desc, dtenant.enabled))

        return tenants.Tenants(ts,[])

    def get_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant could not be found")

        return tenants.Tenant(dtenant.id, dtenant.desc, dtenant.enabled)

    def update_tenant(self, admin_token, tenant):
        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")
        True

    def delete_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant cloud not be found")

        db_api.tenant_delete(dtenant.id)
        return None

    #
    # Private Operations
    #
    def __get_dauth_data(self, token_id):
        if not token_id:
            token = None
        else:
            token = db_api.token_get(token_id)
        if not token:
            user = None
        else:
            user = db_api.user_get(token.user_id)
        return (token, user)

    def __get_auth_data(self, dtoken, duser):
        token = auth.Token(dtoken.expires, dtoken.token_id)

        gs = []
        for ug in duser.groups:
            dgroup = db_api.group_get(ug.group_id)
            gs.append (auth.Group (dgroup.id, dgroup.tenant_id))
        groups = auth.Groups(gs,[])

        user = auth.User(duser.id,duser.tenants[0].tenant_id, groups)
        return auth.AuthData(token, user)

    def __validate_token(self, token_id, admin=True):
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")
        auth_data = self.__get_dauth_data(token_id)
        token = auth_data[0]
        user  = auth_data[1]

        if not token:
            raise fault.UnauthorizedFault("Bad token, please reauthenticate")
        if token.expires < datetime.now():
            raise fault.UnauthorizedFault("Token expired, please renew")
        if not user.enabled:
            raise fault.UserDisabledFault("The user "+user.id+" has been disabled!")
        if admin:
            for ug in user.groups:
                if ug.group_id == "Admin":
                    return auth_data
            raise fault.ForbiddenFault("You are not authorized to make this call")
        return auth_data

