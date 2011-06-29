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
import uuid

import keystone.logic.types.auth as auth
import keystone.logic.types.atom as atom
import keystone.backends.api as db_api
import keystone.backends.sqlalchemy.models as db_models
import keystone.logic.types.fault as fault
import keystone.logic.types.tenant as tenants
import keystone.logic.types.role as roles
import keystone.logic.types.user as get_users
import keystone.logic.types.endpoint as endpoints
import keystone.utils as utils
#TODO(Yogi) Remove references to specific backend model and move them to generic models.


class IdentityService(object):
    "This is the logical implemenation of the Identity service"

    #
    #  Token Operations
    #
    def authenticate(self, credentials):
        # Check credentials
        if not isinstance(credentials, auth.PasswordCredentials):
            raise fault.BadRequestFault("Expecting Password Credentials!")

        if not credentials.tenant_id:
            duser = db_api.user.get(credentials.username)
            if duser == None:
                raise fault.UnauthorizedFault("Unauthorized")
        else:
            duser = db_api.user.get_by_tenant(credentials.username,
                                              credentials.tenant_id)
            if duser == None:
                raise fault.UnauthorizedFault("Unauthorized on this tenant")

        if not duser.enabled:
            raise fault.UserDisabledFault("Your account has been disabled")
        if duser.password != utils.get_hashed_password(credentials.password):
            raise fault.UnauthorizedFault("Unauthorized")

        #
        # Look for an existing token, or create one,
        # TODO: Handle tenant/token search
        #
        if not credentials.tenant_id:
            dtoken = db_api.token.get_for_user(duser.id)
        else:
            dtoken = db_api.token.get_for_user_by_tenant(duser.id,
                                                  credentials.tenant_id)
        tenant_id = None
        if credentials.tenant_id:
            tenant_id = credentials.tenant_id
        else:
            tenant_id = duser.tenant_id

        if not dtoken or dtoken.expires < datetime.now():
            # Create new token
            dtoken = db_models.Token()
            dtoken.id = str(uuid.uuid4())
            dtoken.user_id = duser.id
            if credentials.tenant_id:
                dtoken.tenant_id = credentials.tenant_id
            dtoken.expires = datetime.now() + timedelta(days=1)
            db_api.token.create(dtoken)
        #if tenant_id is passed in the call that tenant_id is passed else
        #user's default tenant_id is used.
        return self.__get_auth_data(dtoken, tenant_id)

    def validate_token(self, admin_token, token_id, belongs_to=None):
        self.__validate_token(admin_token)
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")
        (token, user) = self.__get_dauth_data(token_id)

        if not token:
            raise fault.UnauthorizedFault("Bad token, please reauthenticate")
        if token.expires < datetime.now():
            raise fault.ForbiddenFault("Token expired, please renew")
        if not user.enabled:
            raise fault.UserDisabledFault("The user %s has been disabled!"
                                          % user.id)
        return self.__get_validate_data(token, user)

    def revoke_token(self, admin_token, token_id):
        self.__validate_token(admin_token)

        dtoken = db_api.token.get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        db_api.token.delete(token_id)

    #
    #   Tenant Operations
    #

    def create_tenant(self, admin_token, tenant):
        self.__validate_token(admin_token)

        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        if tenant.tenant_id == None:
            raise fault.BadRequestFault("Expecting a unique Tenant Id")

        if db_api.tenant.get(tenant.tenant_id) != None:
            raise fault.TenantConflictFault(
                "A tenant with that id already exists")

        dtenant = db_models.Tenant()
        dtenant.id = tenant.tenant_id
        dtenant.desc = tenant.description
        dtenant.enabled = tenant.enabled

        db_api.tenant.create(dtenant)
        return tenant

    ##
    ##    GET Tenants with Pagination
    ##
    def get_tenants(self, admin_token, marker, limit, url):
        try:
            (token, user) = self.__validate_token(admin_token)
            # If Global admin return all tenants.
            ts = []
            dtenants = db_api.tenant.get_page(marker, limit)
            for dtenant in dtenants:
                ts.append(tenants.Tenant(dtenant.id,
                                         dtenant.desc, dtenant.enabled))
            prev, next = db_api.tenant.get_page_markers(marker, limit)
            links = []
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                    % (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                    % (url, next, limit)))
            return tenants.Tenants(ts, links)
        except fault.UnauthorizedFault:
            #If not global admin ,return tenants specific to user.
            (token, user) = self.__validate_token(admin_token, False)
            ts = []
            dtenants = db_api.tenant.tenants_for_user_get_page(\
                user, marker, limit)
            for dtenant in dtenants:
                ts.append(tenants.Tenant(dtenant.id,
                                         dtenant.desc, dtenant.enabled))
            prev, next = db_api.tenant.tenants_for_user_get_page_markers(\
                user, marker, limit)
            links = []
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                    % (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                    % (url, next, limit)))
            return tenants.Tenants(ts, links)

    def get_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant.get(tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant could not be found")
        return tenants.Tenant(dtenant.id, dtenant.desc, dtenant.enabled)

    def update_tenant(self, admin_token, tenant_id, tenant):
        self.__validate_token(admin_token)

        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        dtenant = db_api.tenant.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant cloud not be found")
        values = {'desc': tenant.description, 'enabled': tenant.enabled}
        db_api.tenant.update(tenant_id, values)
        return tenants.Tenant(dtenant.id, tenant.description, tenant.enabled)

    def delete_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant cloud not be found")

        if not db_api.tenant.is_empty(tenant_id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains get_users or groups")

        db_api.tenant.delete(dtenant.id)
        return None

    #
    #   Tenant Group Operations
    #

    def create_tenant_group(self, admin_token, tenant, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")

        if tenant == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        dtenant = db_api.tenant.get(tenant)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        if group.group_id == None:
            raise fault.BadRequestFault("Expecting a Group Id")

        if db_api.group.get(group.group_id) != None:
            raise fault.TenantGroupConflictFault(
                "A tenant group with that id already exists")

        dtenant = db_models.Group()
        dtenant.id = group.group_id
        dtenant.desc = group.description
        dtenant.tenant_id = tenant
        db_api.tenant_group.create(dtenant)
        return tenants.Group(dtenant.id, dtenant.desc, dtenant.tenant_id)

    def get_tenant_groups(self, admin_token, tenant_id, marker, limit, url):
        self.__validate_token(admin_token)
        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        dtenant = db_api.tenant.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []
        dtenantgroups = db_api.tenant_group.get_page(tenant_id, marker, limit)

        for dtenantgroup in dtenantgroups:
            ts.append(tenants.Group(dtenantgroup.id,
                                     dtenantgroup.desc,
                                     dtenantgroup.tenant_id))
        prev, next = db_api.tenant_group.get_page_markers(tenant_id, marker,
                                                          limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                    % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'"\
                                    % (url, next, limit)))

        return tenants.Groups(ts, links)

    def get_tenant_group(self, admin_token, tenant_id, group_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group.get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")

        return tenants.Group(dtenant.id, dtenant.desc, dtenant.tenant_id)

    def update_tenant_group(self, admin_token, tenant_id, group_id, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")
        True

        dtenant = db_api.tenant.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group.get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")

        if group_id != group.group_id:
            raise fault.BadRequestFault("Wrong Data Provided,\
                                            Group id not matching")

        if str(tenant_id) != str(group.tenant_id):
            raise fault.BadRequestFault("Wrong Data Provided,\
                                            Tenant id not matching ")

        values = {'desc': group.description}

        db_api.tenant_group.update(group_id, tenant_id, values)

        return tenants.Group(group_id, group.description, tenant_id)

    def delete_tenant_group(self, admin_token, tenant_id, group_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant.get(tenant_id)

        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group.get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")

        if not db_api.tenant_group.is_empty(group_id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains get_users or groups")

        db_api.tenant_group.delete(group_id, tenant_id)
        return None

    def get_users_tenant_group(self, admin_token, tenantId, groupId, marker,
                               limit, url):
        self.__validate_token(admin_token)
        if tenantId == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if db_api.tenant.get(tenantId) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        if db_api.tenant_group.get(groupId, tenantId) == None:
            raise fault.ItemNotFoundFault(
                "A tenant group with that id not found")
        ts = []
        dgroupusers = db_api.user.users_tenant_group_get_page(groupId, marker,
                                                          limit)
        for dgroupuser, dgroupuserAsso in dgroupusers:

            ts.append(tenants.User(dgroupuser.id,
                                   dgroupuser.email, dgroupuser.enabled,
                                   tenantId, None))
        links = []
        if ts.__len__():
            prev, next = db_api.user.users_tenant_group_get_page_markers(
                    groupId, marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return tenants.Users(ts, links)

    def add_user_tenant_group(self, admin_token, tenant, group, user):
        self.__validate_token(admin_token)

        if db_api.tenant.get(tenant) == None:
            raise fault.ItemNotFoundFault("The Tenant not found")

        if db_api.group.get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user.get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group.get(group, tenant) == None:
            raise fault.ItemNotFoundFault("A tenant group with"
                                           " that id not found")

        if db_api.user.get_by_group(user, group) != None:
            raise fault.UserGroupConflictFault(
                "A user with that id already exists in group")

        dusergroup = db_models.UserGroupAssociation()
        dusergroup.user_id = user
        dusergroup.group_id = group
        db_api.user.tenant_group(dusergroup)

        return tenants.User(duser.id, duser.email, duser.enabled,
                            tenant, group)

    def delete_user_tenant_group(self, admin_token, tenant, group, user):
        self.__validate_token(admin_token)

        if db_api.tenant.get(tenant) == None:
            raise fault.ItemNotFoundFault("The Tenant not found")

        if db_api.group.get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user.get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group.get(group, tenant) == None:
            raise fault.ItemNotFoundFault("A tenant group with"
                                          " that id not found")

        if db_api.user.get_by_group(user, group) == None:
            raise fault.ItemNotFoundFault("A user with that id "
                                          "in a group not found")

        db_api.user.tenant_group_delete(user, group)
        return None

    #
    # Private Operations
    #
    def __get_dauth_data(self, token_id):
        """return token and user object for a token_id"""

        token = None
        user = None
        if token_id:
            token = db_api.token.get(token_id)
            if token:
                user = db_api.user.get(token.user_id)
        return (token, user)

    #
    #   User Operations
    #
    def create_user(self, admin_token, user):
        self.__validate_token(admin_token)

        dtenant = self.validate_and_fetch_user_tenant(user.tenant_id)

        if not isinstance(user, get_users.User):
            raise fault.BadRequestFault("Expecting a User")

        if user.user_id == None:
            raise fault.BadRequestFault("Expecting a unique User Id")

        if db_api.user.get(user.user_id) != None:
            raise fault.UserConflictFault(
                "An user with that id already exists")

        if db_api.user.get_by_email(user.email) != None:
            raise fault.EmailConflictFault(
                "Email already exists")

        duser = db_models.User()
        duser.id = user.user_id
        duser.password = user.password
        duser.email = user.email
        duser.enabled = user.enabled
        duser.tenant_id = user.tenant_id
        db_api.user.create(duser)

        return user

    def validate_and_fetch_user_tenant(self, tenant_id):
        if tenant_id != None and len(tenant_id) > 0:
            dtenant = db_api.tenant.get(tenant_id)
            if dtenant == None:
                raise fault.ItemNotFoundFault("The tenant is not found")
            elif not dtenant.enabled:
                raise fault.TenantDisabledFault(
                    "Your account has been disabled")
            return dtenant
        else:
            return None

    def get_tenant_users(self, admin_token, tenant_id, marker, limit, url):
        self.__validate_token(admin_token)

        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        dtenant = db_api.tenant.get(tenant_id)
        if dtenant is  None:
            raise fault.ItemNotFoundFault("The tenant not found")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")
        ts = []
        dtenantusers = db_api.user.users_get_by_tenant_get_page(tenant_id, marker,
                                                          limit)
        for dtenantuser in dtenantusers:
            ts.append(get_users.User(None, dtenantuser.id, tenant_id,
                                   dtenantuser.email, dtenantuser.enabled))
        links = []
        if ts.__len__():
            prev, next = db_api.user.users_get_by_tenant_get_page_markers(tenant_id,
                                                             marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                      (url, next, limit)))
        return get_users.Users(ts, links)

    def get_users(self, admin_token, marker, limit, url):
        self.__validate_token(admin_token)
        ts = []
        dusers = db_api.user.users_get_page(marker, limit)
        for duser in dusers:
            ts.append(get_users.User(None, duser.id, duser.tenant_id,
                                   duser.email, duser.enabled))
        links = []
        if ts.__len__():
            prev, next = db_api.user.users_get_page_markers(marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                      (url, next, limit)))
        return get_users.Users(ts, links)

    def get_user(self, admin_token, user_id):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")

        dtenant = db_api.tenant.get(duser.tenant_id)

        ts = []
        dusergroups = db_api.user.user_groups_get_all(user_id)

        for dusergroup, dusergroupAsso in dusergroups:
            ts.append(tenants.Group(dusergroup.id, dusergroup.tenant_id, None))

        return get_users.User_Update(None, duser.id, duser.tenant_id, duser.email,
                                 duser.enabled, ts)

    def update_user(self, admin_token, user_id, user):
        self.__validate_token(admin_token)

        duser = db_api.user.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")

        if not isinstance(user, get_users.User):
            raise fault.BadRequestFault("Expecting a User")

        if user.email != duser.email and \
            db_api.user.get_by_email(user.email) is not None:
            raise fault.EmailConflictFault(
                "Email already exists")

        values = {'email': user.email}
        db_api.user.update(user_id, values)
        duser = db_api.user.user_get_update(user_id)
        return get_users.User(duser.password, duser.id, duser.tenant_id,
                          duser.email, duser.enabled)

    def set_user_password(self, admin_token, user_id, user):
        self.__validate_token(admin_token)

        duser = db_api.user.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")

        if not isinstance(user, get_users.User):
            raise fault.BadRequestFault("Expecting a User")

        duser = db_api.user.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'password': user.password}

        db_api.user.update(user_id, values)

        return get_users.User_Update(user.password, None, None, None, None, None)

    def enable_disable_user(self, admin_token, user_id, user):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, get_users.User):
            raise fault.BadRequestFault("Expecting a User")

        duser = db_api.user.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'enabled': user.enabled}

        db_api.user.update(user_id, values)

        return get_users.User_Update(None, None, None, None, user.enabled, None)

    def set_user_tenant(self, admin_token, user_id, user):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, get_users.User):
            raise fault.BadRequestFault("Expecting a User")

        duser = db_api.user.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        dtenant = self.validate_and_fetch_user_tenant(user.tenant_id)
        values = {'tenant_id': user.tenant_id}
        db_api.user.update(user_id, values)
        return get_users.User_Update(None, None, user.tenant_id, None, None, None)

    def delete_user(self, admin_token, user_id):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        dtenant = db_api.tenant.get(duser.tenant_id)
        if dtenant != None:
            db_api.user.delete_tenant_user(user_id, dtenant.id)
        else:
            db_api.user.delete(user_id)
        return None

    def get_user_groups(self, admin_token, user_id, marker, limit,
                        url):
        self.__validate_token(admin_token)
        ts = []
        dusergroups = db_api.group.get_by_user_get_page(user_id, marker,
                                                          limit)

        for dusergroup, dusergroupAsso in dusergroups:
            ts.append(tenants.Group(dusergroup.id, dusergroup.desc,
                                    dusergroup.tenant_id))
        links = []
        if ts.__len__():
            prev, next = db_api.group.get_by_user_get_page_markers(user_id,
                                                        marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                      (url, next, limit)))
        return tenants.Groups(ts, links)

    #
    # Global Group Operations
    # TODO:(India Team) Rename functions
    #       and to maintain consistency
    #       with server.py
    def __check_create_global_tenant(self):

        dtenant = db_api.tenant.get('GlobalTenant')

        if dtenant is None:
            dtenant = db_models.Tenant()
            dtenant.id = 'GlobalTenant'
            dtenant.desc = 'GlobalTenant is Default tenant for global groups'
            dtenant.enabled = True
            db_api.tenant.create(dtenant)
        return dtenant

    def create_global_group(self, admin_token, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.GlobalGroup):
            raise fault.BadRequestFault("Expecting a Group")

        if group.group_id == None:
            raise fault.BadRequestFault("Expecting a Group Id")

        if db_api.group.get(group.group_id) != None:
            raise fault.TenantGroupConflictFault(
                "A tenant group with that id already exists")
        gtenant = self.__check_create_global_tenant()
        dtenant = db_models.Group()
        dtenant.id = group.group_id
        dtenant.desc = group.description
        dtenant.tenant_id = gtenant.id
        db_api.tenant_group.create(dtenant)
        return tenants.GlobalGroup(dtenant.id, dtenant.desc, None)

    def get_global_groups(self, admin_token, marker, limit, url):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        ts = []
        dtenantgroups = db_api.tenant_group.get_page(gtenant.id, \
                                                      marker, limit)
        for dtenantgroup in dtenantgroups:
            ts.append(tenants.GlobalGroup(dtenantgroup.id,
                                     dtenantgroup.desc))
        prev, next = db_api.tenant_group.get_page_markers(gtenant.id,
                                                       marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                  (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                  (url, next, limit)))
        return tenants.GlobalGroups(ts, links)

    def get_global_group(self, admin_token, group_id):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        dtenant = db_api.tenant.get(gtenant.id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The Global tenant not found")

        dtenant = db_api.tenant_group.get(group_id, gtenant.id)

        if not dtenant:
            raise fault.ItemNotFoundFault("The Global tenant group not found")
        return tenants.GlobalGroup(dtenant.id, dtenant.desc)

    def update_global_group(self, admin_token, group_id, group):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        if not isinstance(group, tenants.GlobalGroup):
            raise fault.BadRequestFault("Expecting a Group")

        dtenant = db_api.tenant.get(gtenant.id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        dtenant = db_api.tenant_group.get(group_id, gtenant.id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The Global tenant group not found")
        if group_id != group.group_id:
            raise fault.BadRequestFault("Wrong Data Provided,"
                                            "Group id not matching")

        values = {'desc': group.description}
        db_api.tenant_group.update(group_id, gtenant.id, values)
        return tenants.GlobalGroup(group_id, group.description, gtenant.id)

    def delete_global_group(self, admin_token, group_id):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        dtenant = db_api.tenant.get(gtenant.id)

        if dtenant == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        dtenant = db_api.tenant_group.get(group_id, dtenant.id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The global tenant group not found")

        if not db_api.tenant_group.is_empty(group_id):
            raise fault.ForbiddenFault("You may not delete a group that "
                                       "contains get_users")

        db_api.tenant_group.delete(group_id, gtenant.id)
        return None

    def get_users_global_group(self, admin_token, groupId, marker, limit, url):
        self.__validate_token(admin_token)

        gtenant = self.__check_create_global_tenant()
        if gtenant.id == None:
            raise fault.BadRequestFault("Expecting a global Tenant")

        if db_api.tenant.get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        if db_api.tenant_group.get(groupId, gtenant.id) == None:
            raise fault.ItemNotFoundFault(
                "A global tenant group with that id not found")
        ts = []
        dgroupusers = db_api.user.users_tenant_group_get_page(groupId, marker,
                                                         limit)
        for dgroupuser, dgroupuserassoc in dgroupusers:
            ts.append(tenants.User(dgroupuser.id, dgroupuser.email,
                                   dgroupuser.enabled))
        links = []
        if ts.__len__():
            prev, next = db_api.user.users_tenant_group_get_page_markers(groupId,
                                                                marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'"
                                       % (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'"
                                       % (url, next, limit)))
        return tenants.Users(ts, links)

    def add_user_global_group(self, admin_token, group, user):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()

        if db_api.tenant.get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The Global Tenant not found")

        if db_api.group.get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user.get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group.get(group, gtenant.id) == None:
            raise fault.ItemNotFoundFault("A global tenant group with"
                                          " that id not found")

        if db_api.user.get_by_group(user, group) != None:
            raise fault.UserGroupConflictFault(
                "A user with that id already exists in group")

        dusergroup = db_models.UserGroupAssociation()
        dusergroup.user_id = user
        dusergroup.group_id = group
        db_api.user.tenant_group(dusergroup)

        return tenants.User(duser.id, duser.email, duser.enabled,
                           group_id=group)

    def delete_user_global_group(self, admin_token, group, user):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()

        if db_api.tenant.get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The Global Tenant not found")

        if db_api.group.get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user.get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group.get(group, gtenant.id) == None:
            raise fault.ItemNotFoundFault("A global tenant group with "
                                          "that id not found")

        if db_api.user.get_by_group(user, group) == None:
            raise fault.ItemNotFoundFault("A user with that id in a "
                                          "group not found")

        db_api.user.tenant_group_delete(user, group)
        return None

    #

    def __get_auth_data(self, dtoken, tenant_id):
        """return AuthData object for a token"""
        endpoints = None
        if tenant_id != None:
            endpoints = db_api.tenant.get_all_endpoints(tenant_id)
        token = auth.Token(dtoken.expires, dtoken.id, tenant_id)
        return auth.AuthData(token, endpoints)

    def __get_validate_data(self, dtoken, duser):
        """return ValidateData object for a token/user pair"""

        token = auth.Token(dtoken.expires, dtoken.id, dtoken.tenant_id)
        ts = []
        if dtoken.tenant_id:
            droleRefs = db_api.role.ref_get_all_tenant_roles(duser.id,
                                                             dtoken.tenant_id)
            for droleRef in droleRefs:
                ts.append(roles.RoleRef(droleRef.id, droleRef.role_id,
                                         droleRef.tenant_id))
        droleRefs = db_api.role.ref_get_all_global_roles(duser.id)
        for droleRef in droleRefs:
            ts.append(roles.RoleRef(droleRef.id, droleRef.role_id,
                                     droleRef.tenant_id))
        user = auth.User(duser.id, duser.tenant_id, None, roles.RoleRefs(ts,
                                                                         []))
        return auth.ValidateData(token, user)

    def __validate_token(self, token_id, admin=True):
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")
        (token, user) = self.__get_dauth_data(token_id)

        if not token:
            raise fault.ItemNotFoundFault("Bad token, please reauthenticate")
        if token.expires < datetime.now():
            raise fault.ForbiddenFault("Token expired, please renew")
        if not user.enabled:
            raise fault.UserDisabledFault("The user %s has been disabled!"
                                          % user.id)
        if admin:
            roleRefs = db_api.role.ref_get_all_global_roles(user.id)
            for roleRef in roleRefs:
                if roleRef.role_id == "Admin" and roleRef.tenant_id is None:
                    return (token, user)
            raise fault.UnauthorizedFault("You are not authorized "
                                       "to make this call")
        return (token, user)

    def create_role(self, admin_token, role):
        self.__validate_token(admin_token)

        if not isinstance(role, roles.Role):
            raise fault.BadRequestFault("Expecting a Role")

        if role.role_id == None:
            raise fault.BadRequestFault("Expecting a Role Id")

        if db_api.role.get(role.role_id) != None:
            raise fault.RoleConflictFault(
                "A role with that id already exists")
        drole = db_models.Role()
        drole.id = role.role_id
        drole.desc = role.desc
        db_api.role.create(drole)
        return role

    def get_roles(self, admin_token, marker, limit, url):
        self.__validate_token(admin_token)

        ts = []
        droles = db_api.role.get_page(marker, limit)
        for drole in droles:
            ts.append(roles.Role(drole.id,
                                     drole.desc))
        prev, next = db_api.role.get_page_markers(marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return roles.Roles(ts, links)

    def get_role(self, admin_token, role_id):
        self.__validate_token(admin_token)

        drole = db_api.role.get(role_id)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")
        return roles.Role(drole.id, drole.desc)

    def create_role_ref(self, admin_token, user_id, roleRef):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(roleRef, roles.RoleRef):
            raise fault.BadRequestFault("Expecting a Role Ref")

        if roleRef.role_id == None:
            raise fault.BadRequestFault("Expecting a Role Id")

        drole = db_api.role.get(roleRef.role_id)
        if drole == None:
            raise fault.ItemNotFoundFault("The role not found")

        if roleRef.tenant_id != None:
            dtenant = db_api.tenant.get(roleRef.tenant_id)
            if dtenant == None:
                raise fault.ItemNotFoundFault("The tenant not found")

        drole_ref = db_models.UserRoleAssociation()
        drole_ref.user_id = duser.id
        drole_ref.role_id = drole.id
        if roleRef.tenant_id != None:
            drole_ref.tenant_id = dtenant.id
        user_role_ref = db_api.user.user_role_add(drole_ref)
        roleRef.role_ref_id = user_role_ref.id
        return roleRef

    def delete_role_ref(self, admin_token, role_ref_id):
        self.__validate_token(admin_token)
        db_api.role.ref_delete(role_ref_id)
        return None

    def get_user_roles(self, admin_token, marker, limit, url, user_id):
        self.__validate_token(admin_token)
        duser = db_api.user.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        ts = []
        droleRefs = db_api.role.ref_get_page(marker, limit, user_id)
        for droleRef in droleRefs:
            ts.append(roles.RoleRef(droleRef.id, droleRef.role_id,
                                     droleRef.tenant_id))
        prev, next = db_api.role.ref_get_page_markers(user_id, marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return roles.RoleRefs(ts, links)

    def get_endpoint_templates(self, admin_token, marker, limit, url):
        self.__validate_token(admin_token)

        ts = []
        dendpointTemplates = db_api.endpoint_template.get_page(marker, limit)
        for dendpointTemplate in dendpointTemplates:
            ts.append(endpoints.EndpointTemplate(dendpointTemplate.id, dendpointTemplate.region,
                                       dendpointTemplate.service, dendpointTemplate.public_url,
                                       dendpointTemplate.admin_url,
                                       dendpointTemplate.internal_url,
                                       dendpointTemplate.enabled,
                                       dendpointTemplate.is_global))
        prev, next = db_api.endpoint_template.get_page_markers(marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return endpoints.EndpointTemplates(ts, links)

    def get_endpoint_template(self, admin_token, endpoint_template_id):
        self.__validate_token(admin_token)

        dendpointTemplate = db_api.endpoint_template.get(endpoint_template_id)
        if not dendpointTemplate:
            raise fault.ItemNotFoundFault("The endpoint template could not be found")
        return endpoints.EndpointTemplate(dendpointTemplate.id, dendpointTemplate.region, dendpointTemplate.service,
                                dendpointTemplate.public_url, dendpointTemplate.admin_url,
                                dendpointTemplate.internal_url, dendpointTemplate.enabled, dendpointTemplate.is_global)

    def get_tenant_endpoints(self, admin_token, marker, limit, url, tenant_id):
        self.__validate_token(admin_token)
        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if db_api.tenant.get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []

        dtenantEndpoints = \
            db_api.endpoint_template.endpoint_get_by_tenant_get_page(tenant_id, marker,
                                                          limit)
        for dtenantEndpoint in dtenantEndpoints:
            ts.append(endpoints.Endpoint(dtenantEndpoint.id,
                    url + '/endpointTemplates/' + \
                    str(dtenantEndpoint.endpoint_template_id)))
        links = []
        if ts.__len__():
            prev, next = \
                db_api.endpoint_template.endpoint_get_by_tenant_get_page_markers(tenant_id,
                                                        marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                      (url, next, limit)))
        return endpoints.Endpoints(ts, links)

    def create_endpoint_for_tenant(self, admin_token,
                                     tenant_id, endpoint_template, url):
        self.__validate_token(admin_token)
        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        if db_api.tenant.get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dendpoint_template = db_api.endpoint_template.get(endpoint_template.id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault("The endpoint template could not be found")
        dendpoint = db_models.Endpoints()
        dendpoint.tenant_id = tenant_id
        dendpoint.endpoint_template_id = endpoint_template.id
        dendpoint = db_api.endpoint_template.endpoint_add(dendpoint)
        dendpoint = endpoints.Endpoint(dendpoint.id, url + \
                                         '/endpointTemplates/' + \
                                         dendpoint.endpoint_template_id)
        return dendpoint

    def delete_endpoint(self, admin_token, endpoint_id):
        self.__validate_token(admin_token)
        db_api.endpoint_template.endpoint_delete(endpoint_id)
        return None
