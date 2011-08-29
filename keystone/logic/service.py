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

from datetime import datetime, timedelta
import uuid

from keystone.logic.types import auth, atom
from keystone.logic.signer import Signer
import keystone.backends as backends
import keystone.backends.api as api
import keystone.backends.models as models
from keystone.logic.types import fault
from keystone.logic.types.tenant import \
    Tenant, Tenants, User as TenantUser
from keystone.logic.types.role import Role, RoleRef, RoleRefs, Roles
from keystone.logic.types.service import Service, Services
from keystone.logic.types.user import User, User_Update, Users
from keystone.logic.types.endpoint import Endpoint, Endpoints, \
    EndpointTemplate, EndpointTemplates
import keystone.utils as utils


class IdentityService(object):
    """Implements Identity service"""

    #
    #  Token Operations
    #
    def authenticate(self, credentials):
        # Check credentials
        if not isinstance(credentials, auth.PasswordCredentials):
            raise fault.BadRequestFault("Expecting Password Credentials!")

        def validate(duser):
            return api.USER.check_password(duser, credentials.password)

        return self._authenticate(validate,
                                  credentials.username,
                                  credentials.tenant_id)

    def authenticate_ec2(self, credentials):
        # Check credentials
        if not isinstance(credentials, auth.Ec2Credentials):
            raise fault.BadRequestFault("Expecting Ec2 Credentials!")

        creds = api.CREDENTIALS.get_by_access(credentials.access)
        if not creds:
            raise fault.UnauthorizedFault("No credentials found for %s"
                                          % credentials.access)

        def validate(duser):
            signer = Signer(creds.secret)
            signature = signer.generate(credentials)
            if signature == credentials.signature:
                return True
            # NOTE(vish): Some libraries don't use the port when signing
            #             requests, so try again without port.
            if ':' in credentials.host:
                hostname, port = credentials.host.split(":")
                credentials.host = hostname
                signature = signer.generate(credentials)
                return signature == credentials.signature
            return False

        return self._authenticate(validate, creds.user_id, creds.tenant_id)

    def _authenticate(self, validate, user_id, tenant_id=None):
        if not tenant_id:
            duser = api.USER.get(user_id)
            if duser == None:
                raise fault.UnauthorizedFault("Unauthorized")
        else:
            duser = api.USER.get_by_tenant(user_id, tenant_id)
            if duser == None:
                raise fault.UnauthorizedFault("Unauthorized on this tenant")

        if not duser.enabled:
            raise fault.UserDisabledFault("Your account has been disabled")

        if not validate(duser):
            raise fault.UnauthorizedFault("Unauthorized")

        #
        # Look for an existing token, or create one,
        # TODO: Handle tenant/token search
        #
        user_id = duser.id
        tenant_id = tenant_id or duser.tenant_id
        dtoken = api.TOKEN.get_for_user_by_tenant(user_id, tenant_id)

        if not dtoken or dtoken.expires < datetime.now():
            # Create new token
            dtoken = models.Token()
            dtoken.id = str(uuid.uuid4())
            dtoken.user_id = user_id
            dtoken.tenant_id = tenant_id
            dtoken.expires = datetime.now() + timedelta(days=1)
            api.TOKEN.create(dtoken)
        #if tenant_id is passed in the call that tenant_id is passed else
        #user's default tenant_id is used.
        return self.__get_auth_data(dtoken, tenant_id)

    def validate_token(self, admin_token, token_id, belongs_to=None):
        self.__validate_service_or_keystone_admin_token(admin_token)

        if not api.TOKEN.get(token_id):
            raise fault.UnauthorizedFault("Bad token, please reauthenticate")

        (token, user) = self.__validate_token(token_id, belongs_to)

        return self.__get_validate_data(token, user)

    def revoke_token(self, admin_token, token_id):
        self.__validate_admin_token(admin_token)

        dtoken = api.TOKEN.get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        api.TOKEN.delete(token_id)

    #
    #   Tenant Operations
    #

    def create_tenant(self, admin_token, tenant):
        self.__validate_admin_token(admin_token)

        if not isinstance(tenant, Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        if tenant.tenant_id == None or len(tenant.tenant_id.strip()) == 0:
            raise fault.BadRequestFault("Expecting a unique Tenant Id")

        if api.TENANT.get(tenant.tenant_id) != None:
            raise fault.TenantConflictFault(
                "A tenant with that id already exists")

        dtenant = models.Tenant()
        dtenant.id = tenant.tenant_id
        dtenant.desc = tenant.description
        dtenant.enabled = tenant.enabled

        api.TENANT.create(dtenant)
        return tenant

    def get_tenants(self, admin_token, marker, limit, url):
        """Fetch tenants for either an admin user or service user."""
        ts = []

        try:
            # If Global admin...
            (_token, user) = self.__validate_admin_token(admin_token)

            # Return all tenants
            dtenants = api.TENANT.get_page(marker, limit)
            prev_page, next_page = api.TENANT.get_page_markers(marker, limit)
        except fault.UnauthorizedFault:
            # If not global admin...
            (_token, user) = self.__validate_token(admin_token, False)

            # Return tenants specific to user
            dtenants = api.TENANT.tenants_for_user_get_page(
                user, marker, limit)
            prev_page, next_page = api.TENANT.\
                tenants_for_user_get_page_markers(user, marker, limit)

        for dtenant in dtenants:
            ts.append(Tenant(dtenant.id, dtenant.desc, dtenant.enabled))

        links = []
        if prev_page:
            links.append(atom.Link('prev',
                "%s?'marker=%s&limit=%s'" % (url, prev_page, limit)))
        if next_page:
            links.append(atom.Link('next',
                "%s?'marker=%s&limit=%s'" % (url, next_page, limit)))

        return Tenants(ts, links)

    def get_tenant(self, admin_token, tenant_id):
        self.__validate_admin_token(admin_token)

        dtenant = api.TENANT.get(tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant could not be found")
        return Tenant(dtenant.id, dtenant.desc, dtenant.enabled)

    def update_tenant(self, admin_token, tenant_id, tenant):
        self.__validate_admin_token(admin_token)

        if not isinstance(tenant, Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        dtenant = api.TENANT.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant could not be found")
        values = {'desc': tenant.description, 'enabled': tenant.enabled}
        api.TENANT.update(tenant_id, values)
        return Tenant(dtenant.id, tenant.description, tenant.enabled)

    def delete_tenant(self, admin_token, tenant_id):
        self.__validate_admin_token(admin_token)

        dtenant = api.TENANT.get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant could not be found")

        if not api.TENANT.is_empty(tenant_id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains get_users")

        api.TENANT.delete(dtenant.id)
        return None

    #
    # Private Operations
    #
    def __get_dauth_data(self, token_id):
        """return token and user object for a token_id"""

        token = None
        user = None
        if token_id:
            token = api.TOKEN.get(token_id)
            if token:
                user = api.USER.get(token.user_id)
        return (token, user)

    #
    #   User Operations
    #
    def create_user(self, admin_token, user):
        self.__validate_admin_token(admin_token)

        self.validate_and_fetch_user_tenant(user.tenant_id)

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        if user.user_id == None or len(user.user_id.strip()) == 0:
            raise fault.BadRequestFault("Expecting a unique User Id")

        if api.USER.get(user.user_id) != None:
            raise fault.UserConflictFault(
                "An user with that id already exists")

        if api.USER.get_by_email(user.email) != None:
            raise fault.EmailConflictFault("Email already exists")

        duser = models.User()
        duser.id = user.user_id
        duser.password = user.password
        duser.email = user.email
        duser.enabled = user.enabled
        duser.tenant_id = user.tenant_id
        api.USER.create(duser)

        return user

    def validate_and_fetch_user_tenant(self, tenant_id):
        if tenant_id != None and len(tenant_id) > 0:
            dtenant = api.TENANT.get(tenant_id)
            if dtenant == None:
                raise fault.ItemNotFoundFault("The tenant is not found")
            elif not dtenant.enabled:
                raise fault.TenantDisabledFault(
                    "Your account has been disabled")
            return dtenant
        else:
            return None

    def get_tenant_users(self, admin_token, tenant_id, marker, limit, url):
        self.__validate_admin_token(admin_token)

        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        dtenant = api.TENANT.get(tenant_id)
        if dtenant is  None:
            raise fault.ItemNotFoundFault("The tenant not found")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")
        ts = []
        dtenantusers = api.USER.users_get_by_tenant_get_page(tenant_id, marker,
                                                          limit)
        for dtenantuser in dtenantusers:
            ts.append(User(None, dtenantuser.id, tenant_id,
                           dtenantuser.email, dtenantuser.enabled,
                           dtenantuser.tenant_roles if hasattr(dtenantuser,
                                                    "tenant_roles") else None))
        links = []
        if ts.__len__():
            prev, next = api.USER.users_get_by_tenant_get_page_markers(
                    tenant_id, marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return Users(ts, links)

    def get_users(self, admin_token, marker, limit, url):
        self.__validate_admin_token(admin_token)
        ts = []
        dusers = api.USER.users_get_page(marker, limit)
        for duser in dusers:
            ts.append(User(None, duser.id, duser.tenant_id,
                                   duser.email, duser.enabled))
        links = []
        if ts.__len__():
            prev, next = api.USER.users_get_page_markers(marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return Users(ts, links)

    def get_user(self, admin_token, user_id):
        self.__validate_admin_token(admin_token)
        duser = api.USER.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        return User_Update(None, duser.id, duser.tenant_id,
                duser.email, duser.enabled)

    def update_user(self, admin_token, user_id, user):
        self.__validate_admin_token(admin_token)

        duser = api.USER.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        if user.email != duser.email and \
            api.USER.get_by_email(user.email) is not None:
            raise fault.EmailConflictFault(
                "Email already exists")

        values = {'email': user.email}
        api.USER.update(user_id, values)
        duser = api.USER.user_get_update(user_id)
        return User(duser.password, duser.id, duser.tenant_id,
                          duser.email, duser.enabled)

    def set_user_password(self, admin_token, user_id, user):
        self.__validate_admin_token(admin_token)

        duser = api.USER.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        duser = api.USER.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'password': user.password}

        api.USER.update(user_id, values)

        return User_Update(user.password,
            None, None, None, None)

    def enable_disable_user(self, admin_token, user_id, user):
        self.__validate_admin_token(admin_token)
        duser = api.USER.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        duser = api.USER.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'enabled': user.enabled}

        api.USER.update(user_id, values)

        return User_Update(None,
            None, None, None, user.enabled)

    def set_user_tenant(self, admin_token, user_id, user):
        self.__validate_admin_token(admin_token)
        duser = api.USER.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        duser = api.USER.get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        self.validate_and_fetch_user_tenant(user.tenant_id)
        values = {'tenant_id': user.tenant_id}
        api.USER.update(user_id, values)
        return User_Update(None,
            None, user.tenant_id, None, None)

    def delete_user(self, admin_token, user_id):
        self.__validate_admin_token(admin_token)
        duser = api.USER.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        dtenant = api.TENANT.get(duser.tenant_id)
        if dtenant != None:
            api.USER.delete_tenant_user(user_id, dtenant.id)
        else:
            api.USER.delete(user_id)
        return None

    def __get_auth_data(self, dtoken, tenant_id):
        """return AuthData object for a token"""
        endpoints = None
        try:
            endpoints = api.TENANT.get_all_endpoints(tenant_id)
        except:
            pass
        token = auth.Token(dtoken.expires, dtoken.id, tenant_id)
        return auth.AuthData(token, endpoints)

    def __get_validate_data(self, dtoken, duser):
        """return ValidateData object for a token/user pair"""

        token = auth.Token(dtoken.expires, dtoken.id, dtoken.tenant_id)
        ts = []
        if dtoken.tenant_id:
            drole_refs = api.ROLE.ref_get_all_tenant_roles(duser.id,
                                                             dtoken.tenant_id)
            for drole_ref in drole_refs:
                ts.append(RoleRef(drole_ref.id, drole_ref.role_id,
                                         drole_ref.tenant_id))
        drole_refs = api.ROLE.ref_get_all_global_roles(duser.id)
        for drole_ref in drole_refs:
            ts.append(RoleRef(drole_ref.id, drole_ref.role_id,
                                     drole_ref.tenant_id))
        user = auth.User(duser.id, duser.tenant_id, RoleRefs(ts, []))
        return auth.ValidateData(token, user)

    def __validate_tenant(self, tenant_id):
        if not tenant_id:
            raise fault.UnauthorizedFault("Missing tenant")

        tenant = api.TENANT.get(tenant_id)

        if not tenant.enabled:
            raise fault.TenantDisabledFault("Tenant %s has been disabled!"
                                          % tenant.id)

    def __validate_token(self, token_id, belongs_to=None):
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")

        (token, user) = self.__get_dauth_data(token_id)

        if not token:
            raise fault.ItemNotFoundFault("Bad token, please reauthenticate")

        if token.expires < datetime.now():
            raise fault.ForbiddenFault("Token expired, please renew")

        if not user.enabled:
            raise fault.UserDisabledFault("User %s has been disabled!"
                                          % user.id)

        if user.tenant_id:
            self.__validate_tenant(user.tenant_id)

        if token.tenant_id:
            self.__validate_tenant(token.tenant_id)

        if belongs_to and token.tenant_id != belongs_to:
            raise fault.UnauthorizedFault("Unauthorized on this tenant")

        return (token, user)

    def __validate_admin_token(self, token_id):
        (token, user) = self.__validate_token(token_id)

        for role_ref in api.ROLE.ref_get_all_global_roles(user.id):
            if role_ref.role_id == backends.KEYSTONEADMINROLE and \
                    role_ref.tenant_id is None:
                return (token, user)

        raise fault.UnauthorizedFault(
            "You are not authorized to make this call")

    def __validate_service_or_keystone_admin_token(self, token_id):
        (token, user) = self.__validate_token(token_id)
        for role_ref in api.ROLE.ref_get_all_global_roles(user.id):
            if (role_ref.role_id == backends.KEYSTONEADMINROLE or \
                role_ref.role_id == backends.KEYSTONESERVICEADMINROLE) and \
                    role_ref.tenant_id is None:
                return (token, user)
        raise fault.UnauthorizedFault(
            "You are not authorized to make this call")

    def create_role(self, admin_token, role):
        self.__validate_service_or_keystone_admin_token(admin_token)

        if not isinstance(role, Role):
            raise fault.BadRequestFault("Expecting a Role")

        if role.role_id == None or len(role.role_id.strip()) == 0:
            raise fault.BadRequestFault("Expecting a Role Id")

        if api.ROLE.get(role.role_id) != None:
            raise fault.RoleConflictFault(
                "A role with that id '" + role.role_id + "' already exists")
        #Check if the passed service exist
        #and the role begins with service_id:.
        if role.service_id != None and\
            len(role.service_id.strip()) > 0:
            if api.SERVICE.get(role.service_id) == None:
                raise fault.BadRequestFault(
                        "A service with that id doesnt exist.")
            if not role.role_id.startswith(role.service_id + ":"):
                raise fault.BadRequestFault(
                    "Role should begin with service id '" +
                        role.service_id + ":'")

        drole = models.Role()
        drole.id = role.role_id
        drole.desc = role.desc
        drole.service_id = role.service_id
        api.ROLE.create(drole)
        return role

    def get_roles(self, admin_token, marker, limit, url):
        self.__validate_service_or_keystone_admin_token(admin_token)

        ts = []
        droles = api.ROLE.get_page(marker, limit)
        for drole in droles:
            ts.append(Role(drole.id,
                                     drole.desc, drole.service_id))
        prev, next = api.ROLE.get_page_markers(marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return Roles(ts, links)

    def get_role(self, admin_token, role_id):
        self.__validate_service_or_keystone_admin_token(admin_token)

        drole = api.ROLE.get(role_id)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")
        return Role(drole.id, drole.desc, drole.service_id)

    def delete_role(self, admin_token, role_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        drole = api.ROLE.get(role_id)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")
        role_refs = api.ROLE.ref_get_by_role(role_id)
        if role_refs != None:
            for role_ref in role_refs:
                api.ROLE.ref_delete(role_ref.id)
        api.ROLE.delete(role_id)

    def create_role_ref(self, admin_token, user_id, role_ref):
        self.__validate_service_or_keystone_admin_token(admin_token)
        duser = api.USER.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(role_ref, RoleRef):
            raise fault.BadRequestFault("Expecting a Role Ref")

        if role_ref.role_id == None:
            raise fault.BadRequestFault("Expecting a Role Id")

        drole = api.ROLE.get(role_ref.role_id)
        if drole == None:
            raise fault.ItemNotFoundFault("The role not found")

        if role_ref.tenant_id != None:
            dtenant = api.TENANT.get(role_ref.tenant_id)
            if dtenant == None:
                raise fault.ItemNotFoundFault("The tenant not found")

        drole_ref = models.UserRoleAssociation()
        drole_ref.user_id = duser.id
        drole_ref.role_id = drole.id
        if role_ref.tenant_id != None:
            drole_ref.tenant_id = dtenant.id
        user_role_ref = api.USER.user_role_add(drole_ref)
        role_ref.role_ref_id = user_role_ref.id
        return role_ref

    def delete_role_ref(self, admin_token, role_ref_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        api.ROLE.ref_delete(role_ref_id)
        return None

    def get_user_roles(self, admin_token, marker, limit, url, user_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        duser = api.USER.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        ts = []
        drole_refs = api.ROLE.ref_get_page(marker, limit, user_id)
        for drole_ref in drole_refs:
            ts.append(RoleRef(drole_ref.id, drole_ref.role_id,
                                     drole_ref.tenant_id))
        prev, next = api.ROLE.ref_get_page_markers(user_id, marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return RoleRefs(ts, links)

    def add_endpoint_template(self, admin_token, endpoint_template):
        self.__validate_service_or_keystone_admin_token(admin_token)

        if not isinstance(endpoint_template, EndpointTemplate):
            raise fault.BadRequestFault("Expecting a EndpointTemplate")

        #Check if the passed service exist.
        if endpoint_template.service != None and\
            len(endpoint_template.service.strip()) > 0 and\
            api.SERVICE.get(endpoint_template.service) == None:
            raise fault.BadRequestFault(
                    "A service with that id doesnt exist.")
        dendpoint_template = models.EndpointTemplates()
        dendpoint_template.region = endpoint_template.region
        dendpoint_template.service = endpoint_template.service
        dendpoint_template.public_url = endpoint_template.public_url
        dendpoint_template.admin_url = endpoint_template.admin_url
        dendpoint_template.internal_url = endpoint_template.internal_url
        dendpoint_template.enabled = endpoint_template.enabled
        dendpoint_template.is_global = endpoint_template.is_global
        dendpoint_template = api.ENDPOINT_TEMPLATE.create(dendpoint_template)
        endpoint_template.id = dendpoint_template.id
        return endpoint_template

    def modify_endpoint_template(self,
        admin_token, endpoint_template_id, endpoint_template):
        self.__validate_service_or_keystone_admin_token(admin_token)

        if not isinstance(endpoint_template, EndpointTemplate):
            raise fault.BadRequestFault("Expecting a EndpointTemplate")
        dendpoint_template = api.ENDPOINT_TEMPLATE.get(endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")

        #Check if the passed service exist.
        if endpoint_template.service != None and\
            len(endpoint_template.service.strip()) > 0 and\
            api.SERVICE.get(endpoint_template.service) == None:
            raise fault.BadRequestFault(
                    "A service with that id doesn't exist.")
        dendpoint_template.region = endpoint_template.region
        dendpoint_template.service = endpoint_template.service
        dendpoint_template.public_url = endpoint_template.public_url
        dendpoint_template.admin_url = endpoint_template.admin_url
        dendpoint_template.internal_url = endpoint_template.internal_url
        dendpoint_template.enabled = endpoint_template.enabled
        dendpoint_template.is_global = endpoint_template.is_global
        dendpoint_template = api.ENDPOINT_TEMPLATE.update(
            endpoint_template_id, dendpoint_template)
        return EndpointTemplate(
            dendpoint_template.id,
            dendpoint_template.region,
            dendpoint_template.service,
            dendpoint_template.public_url,
            dendpoint_template.admin_url,
            dendpoint_template.internal_url,
            dendpoint_template.enabled,
            dendpoint_template.is_global)

    def delete_endpoint_template(self, admin_token, endpoint_template_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        dendpoint_template = api.ENDPOINT_TEMPLATE.get(endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")
        #Delete Related endpoints
        endpoints = api.ENDPOINT_TEMPLATE.\
            endpoint_get_by_endpoint_template(endpoint_template_id)
        if endpoints != None:
            for endpoint in endpoints:
                api.ENDPOINT_TEMPLATE.endpoint_delete(endpoint.id)
        api.ENDPOINT_TEMPLATE.delete(endpoint_template_id)

    def get_endpoint_templates(self, admin_token, marker, limit, url):
        self.__validate_service_or_keystone_admin_token(admin_token)

        ts = []
        dendpoint_templates = api.ENDPOINT_TEMPLATE.get_page(marker, limit)
        for dendpoint_template in dendpoint_templates:
            ts.append(EndpointTemplate(
                dendpoint_template.id,
                dendpoint_template.region,
                dendpoint_template.service,
                dendpoint_template.public_url,
                dendpoint_template.admin_url,
                dendpoint_template.internal_url,
                dendpoint_template.enabled,
                dendpoint_template.is_global))
        prev, next = api.ENDPOINT_TEMPLATE.get_page_markers(marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return EndpointTemplates(ts, links)

    def get_endpoint_template(self, admin_token, endpoint_template_id):
        self.__validate_service_or_keystone_admin_token(admin_token)

        dendpoint_template = api.ENDPOINT_TEMPLATE.get(endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")
        return EndpointTemplate(
            dendpoint_template.id,
            dendpoint_template.region,
            dendpoint_template.service,
            dendpoint_template.public_url,
            dendpoint_template.admin_url,
            dendpoint_template.internal_url,
            dendpoint_template.enabled,
            dendpoint_template.is_global)

    def get_tenant_endpoints(self, admin_token, marker, limit, url, tenant_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if api.TENANT.get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []

        dtenant_endpoints = \
            api.ENDPOINT_TEMPLATE.\
                endpoint_get_by_tenant_get_page(
                    tenant_id, marker, limit)
        for dtenant_endpoint in dtenant_endpoints:
            ts.append(Endpoint(dtenant_endpoint.id,
                    url + '/endpointTemplates/' + \
                    str(dtenant_endpoint.endpoint_template_id)))
        links = []
        if ts.__len__():
            prev, next = \
                api.ENDPOINT_TEMPLATE.endpoint_get_by_tenant_get_page_markers(
                    tenant_id, marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return Endpoints(ts, links)

    def create_endpoint_for_tenant(self, admin_token,
                                     tenant_id, endpoint_template, url):
        self.__validate_service_or_keystone_admin_token(admin_token)
        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        if api.TENANT.get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dendpoint_template = api.ENDPOINT_TEMPLATE.get(endpoint_template.id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")
        dendpoint = models.Endpoints()
        dendpoint.tenant_id = tenant_id
        dendpoint.endpoint_template_id = endpoint_template.id
        dendpoint = api.ENDPOINT_TEMPLATE.endpoint_add(dendpoint)
        dendpoint = Endpoint(dendpoint.id, url +
            '/endpointTemplates/' + dendpoint.endpoint_template_id)
        return dendpoint

    def delete_endpoint(self, admin_token, endpoint_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        if api.ENDPOINT_TEMPLATE.get(endpoint_id) == None:
            raise fault.ItemNotFoundFault("The Endpoint is not found.")
        api.ENDPOINT_TEMPLATE.endpoint_delete(endpoint_id)
        return None

    #Service Operations
    def create_service(self, admin_token, service):
        self.__validate_service_or_keystone_admin_token(admin_token)

        if not isinstance(service, Service):
            raise fault.BadRequestFault("Expecting a Service")

        if service.service_id == None:
            raise fault.BadRequestFault("Expecting a Service Id")

        if api.SERVICE.get(service.service_id) != None:
            raise fault.ServiceConflictFault(
                "A service with that id already exists")
        dservice = models.Service()
        dservice.id = service.service_id
        dservice.desc = service.desc
        api.SERVICE.create(dservice)
        return service

    def get_services(self, admin_token, marker, limit, url):
        self.__validate_service_or_keystone_admin_token(admin_token)

        ts = []
        dservices = api.SERVICE.get_page(marker, limit)
        for dservice in dservices:
            ts.append(Service(dservice.id,
                                     dservice.desc))
        prev, next = api.SERVICE.get_page_markers(marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" \
                                                % (url, next, limit)))
        return Services(ts, links)

    def get_service(self, admin_token, service_id):
        self.__validate_service_or_keystone_admin_token(admin_token)

        dservice = api.SERVICE.get(service_id)
        if not dservice:
            raise fault.ItemNotFoundFault("The service could not be found")
        return Service(dservice.id, dservice.desc)

    def delete_service(self, admin_token, service_id):
        self.__validate_service_or_keystone_admin_token(admin_token)
        dservice = api.SERVICE.get(service_id)

        if not dservice:
            raise fault.ItemNotFoundFault("The service could not be found")

        #Delete Related Endpointtemplates and Endpoints.
        endpoint_templates = api.ENDPOINT_TEMPLATE.get_by_service(service_id)
        if endpoint_templates != None:
            for endpoint_template in endpoint_templates:
                endpoints = api.ENDPOINT_TEMPLATE.\
                    endpoint_get_by_endpoint_template(endpoint_template.id)
                if endpoints != None:
                    for endpoint in endpoints:
                        api.ENDPOINT_TEMPLATE.endpoint_delete(endpoint.id)
                api.ENDPOINT_TEMPLATE.delete(endpoint_template.id)
        #Delete Related Role and RoleRefs
        roles = api.ROLE.get_by_service(service_id)
        if roles != None:
            for role in roles:
                role_refs = api.ROLE.ref_get_by_role(role.id)
                if role_refs != None:
                    for role_ref in role_refs:
                        api.ROLE.ref_delete(role_ref.id)
                api.ROLE.delete(role.id)
        api.SERVICE.delete(service_id)
