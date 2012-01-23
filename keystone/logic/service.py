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
#
# pylint: disable=C0302,W0603,W0602

from datetime import datetime, timedelta
import functools
import logging
import uuid

from keystone import config
from keystone.logic.types import auth, atom
from keystone.logic.signer import Signer
import keystone.backends as backends
import keystone.backends.models as models
from keystone.logic.types import fault
from keystone.logic.types.tenant import Tenants
from keystone.logic.types.user import User, User_Update, Users
from keystone.logic.types.endpoint import Endpoint, Endpoints, \
    EndpointTemplate, EndpointTemplates
from keystone.logic.types.credential import Credentials, PasswordCredentials
from keystone import utils
# New imports as we refactor old backend design and models
from keystone.models import Tenant, Token
from keystone.models import Role, Roles
from keystone.models import Service, Services
from keystone.managers.token import Manager as TokenManager
from keystone.managers.tenant import Manager as TenantManager
from keystone.managers.user import Manager as UserManager
from keystone.managers.role import Manager as RoleManager
from keystone.managers.grant import Manager as GrantManager
from keystone.managers.service import Manager as ServiceManager
from keystone.managers.endpoint_template import Manager \
        as EndpointTemplateManager
from keystone.managers.endpoint import Manager as EndpointManager
from keystone.managers.credential import Manager as CredentialManager

CONF = config.CONF

#Reference to Admin Role.
ADMIN_ROLE_ID = None
ADMIN_ROLE_NAME = None
SERVICE_ADMIN_ROLE_ID = None
SERVICE_ADMIN_ROLE_NAME = None
GLOBAL_SERVICE_ID = None  # to facilitate global roles for validate tokens

LOG = logging.getLogger(__name__)


def admin_token_validator(fnc):
    """Decorator that applies the validate_admin_token() method."""
    @functools.wraps(fnc)
    def _wrapper(self, token_id, *args, **kwargs):
        self.validate_admin_token(token_id)
        return fnc(self, token_id, *args, **kwargs)
    return _wrapper


def service_admin_token_validator(fnc):
    """Decorator that applies the validate_service_admin_token() method."""
    @functools.wraps(fnc)
    def _wrapper(self, token_id, *args, **kwargs):
        self.validate_service_admin_token(token_id)
        return fnc(self, token_id, *args, **kwargs)
    return _wrapper


# pylint: disable=R0902
class IdentityService(object):
    """Implements the Identity service

    This class handles all logic of routing requests to the correct
    backend as well as validating incoming/outgoing data
    """

    def __init__(self):
        """ Initialize

        Loads all necessary backends to handle incoming requests.
        """
        backends.configure_backends()
        self.token_manager = TokenManager()
        self.tenant_manager = TenantManager()
        self.user_manager = UserManager()
        self.role_manager = RoleManager()
        self.grant_manager = GrantManager()
        self.service_manager = ServiceManager()
        self.endpoint_template_manager = EndpointTemplateManager()
        self.endpoint_manager = EndpointManager()
        self.credential_manager = CredentialManager()

        # pylint: disable=W0603
        global ADMIN_ROLE_NAME
        ADMIN_ROLE_NAME = CONF.keystone_admin_role

        global SERVICE_ADMIN_ROLE_NAME
        SERVICE_ADMIN_ROLE_NAME = CONF.keystone_service_admin_role

        global GLOBAL_SERVICE_ID
        GLOBAL_SERVICE_ID = CONF.global_service_id or "global"

        LOG.debug("init with ADMIN_ROLE_NAME=%s, SERVICE_ADMIN_ROLE_NAME=%s, "
                  "GLOBAL_SERVICE_ID=%s" % (ADMIN_ROLE_NAME,
                                            SERVICE_ADMIN_ROLE_NAME,
                                            GLOBAL_SERVICE_ID))

    #
    #  Token Operations
    #
    def authenticate(self, auth_request):
        LOG.debug("Authenticating with passwordCredentials")
        if not isinstance(auth_request, auth.AuthWithPasswordCredentials):
            raise fault.BadRequestFault(
                "Expecting auth_with_password_credentials!")

        def validate(duser):
            return self.user_manager.check_password(duser.id,
                                                    auth_request.password)

        if auth_request.tenant_name:
            dtenant = self.validate_tenant_by_name(auth_request.tenant_name)
            auth_request.tenant_id = dtenant.id
        elif auth_request.tenant_id:
            dtenant = self.validate_tenant_by_id(auth_request.tenant_id)

        user = self.user_manager.get_by_name(auth_request.username)
        if not user:
            LOG.debug("Did not find user with name=%s" % auth_request.username)
            raise fault.UnauthorizedFault("Unauthorized")

        return self._authenticate(validate, user.id, auth_request.tenant_id)

    def authenticate_with_unscoped_token(self, auth_request):
        LOG.debug("Authenticating with token (unscoped)")
        if not isinstance(auth_request, auth.AuthWithUnscopedToken):
            raise fault.BadRequestFault("Expecting auth_with_unscoped_token!")

        # We *should* check for an unscoped token here, but as long as
        # POST /tokens w/ credentials auto-scopes to User.tenantId, users can't
        # reach this flow.
        # _token, user = validate_unscoped_token(auth_request.token_id)
        _token, user = self._validate_token(auth_request.token_id)

        if auth_request.tenant_name:
            dtenant = self.validate_tenant_by_name(auth_request.tenant_name)
            auth_request.tenant_id = dtenant.id
        elif auth_request.tenant_id:
            dtenant = self.validate_tenant_by_id(auth_request.tenant_id)

        # pylint: disable=W0613
        def validate(duser):
            # The user is already authenticated
            return True
        return self._authenticate(validate, user.id, auth_request.tenant_id)

    def authenticate_ec2(self, credentials):
        LOG.debug("Authenticating with EC2 credentials")
        if not isinstance(credentials, auth.Ec2Credentials):
            raise fault.BadRequestFault("Expecting Ec2 Credentials!")

        creds = self.credential_manager.get_by_access(credentials.access)
        if not creds:
            raise fault.UnauthorizedFault("No credentials found for %s"
                                          % credentials.access)

        # pylint: disable=W0613
        def validate(duser):
            signer = Signer(creds.secret)
            signature = signer.generate(credentials)
            if signature == credentials.signature:
                return True
            # NOTE(vish): Some libraries don't use the port when signing
            #             requests, so try again without port.
            if ':' in credentials.host:
                hostname, _port = credentials.host.split(":")
                credentials.host = hostname
                signature = signer.generate(credentials)
                return signature == credentials.signature
            return False
        return self._authenticate(validate, creds.user_id,
                                             creds.tenant_id)

    def authenticate_s3(self, credentials):
        # Check credentials
        if not isinstance(credentials, auth.S3Credentials):
            raise fault.BadRequestFault("Expecting S3 Credentials!")

        creds = self.credential_manager.get_by_access(credentials.access)
        if not creds:
            raise fault.UnauthorizedFault("No credentials found for %s"
                                          % credentials.access)

        def validate(duser):  # pylint: disable=W0613
            signer = Signer(creds.secret)
            signature = signer.generate(credentials, s3=True)
            if signature == credentials.signature:
                return True
            return False

        return self._authenticate(validate, creds.user_id, creds.tenant_id)

    def _authenticate(self, validate, user_id, tenant_id=None):
        LOG.debug("Authenticating user %s (tenant: %s)" % (user_id, tenant_id))
        if tenant_id:
            duser = self.user_manager.get_by_tenant(user_id, tenant_id)
            if duser is None:
                LOG.debug("User %s is not authorized on tenant %s" % (
                    user_id, tenant_id))
                raise fault.UnauthorizedFault("Unauthorized on this tenant")
        else:
            duser = self.user_manager.get(user_id)
            if duser is None:
                LOG.debug("User with id %s not found" % user_id)
                raise fault.UnauthorizedFault("Unauthorized")

        if not duser.enabled:
            LOG.debug("User %s is not enabled" % user_id)
            raise fault.UserDisabledFault("Your account has been disabled")

        if not validate(duser):
            LOG.debug("validate() returned false")
            raise fault.UnauthorizedFault("Unauthorized")

        # use user's default tenant_id if one is not specified
        tenant_id = tenant_id or duser.tenant_id

        # check for an existing token
        dtoken = self.token_manager.find(duser.id, tenant_id)

        if not dtoken or dtoken.expires < datetime.now():
            LOG.debug("Token was not found or expired. Creating a new token "
                      "for the user")
            # Create new token
            dtoken = Token()
            dtoken.id = str(uuid.uuid4())
            dtoken.user_id = duser.id
            dtoken.tenant_id = tenant_id
            dtoken.expires = datetime.now() + timedelta(days=1)
            dtoken = self.token_manager.create(dtoken)
        return self.get_auth_data(dtoken)

    # pylint: disable=W0613
    @service_admin_token_validator
    def validate_token(self, admin_token, token_id, belongs_to=None,
                       service_ids=None):
        (token, user) = self._validate_token(token_id, belongs_to, True)
        if service_ids and (token.tenant_id or belongs_to):
            # scope token, validate the service IDs if present
            service_ids = self.parse_service_ids(service_ids)
            self.validate_service_ids(service_ids)
        auth_data = self.get_validate_data(token, user, service_ids)
        if service_ids and (token.tenant_id or belongs_to):
            # we have service Ids and scope token, make sure we have some roles
            if not auth_data.user.rolegrants.values:
                raise fault.UnauthorizedFault("No roles found for scope token")
        return auth_data

    @admin_token_validator
    def revoke_token(self, admin_token, token_id):
        dtoken = self.token_manager.get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        self.token_manager.delete(token_id)

    @staticmethod
    def parse_service_ids(service_ids):
        """
        Method to parse the service IDs string.
        service_ids -- comma-separated service IDs
        parse and return a list of service IDs.
        """
        if service_ids:
            return [x.strip() for x in service_ids.split(',')]
        return []

    def validate_service_ids(self, service_ids):
        """
        Method to validate the service IDs.
        service_ids -- list of service IDs
        If not service IDs or encounter an invalid service ID,
        fault.UnauthorizedFault will be raised.
        """
        if not service_ids:
            raise fault.UnauthorizedFault("Missing service IDs")

        services = [self.service_manager.get(service_id) for service_id in
                    service_ids if not service_id == GLOBAL_SERVICE_ID]
        if not all(services):
            raise fault.UnauthorizedFault(
                "Invalid service ID: %s" % (service_ids))

    def get_roles_names_by_service_ids(self, service_ids):
        """
        Method to find all the roles for the given service IDs.
        service_ids -- list of service IDs
        """
        roles = []
        for service_id in service_ids:
            if service_id != GLOBAL_SERVICE_ID:
                sroles = self.role_manager.get_by_service(
                                                    service_id=service_id)
                if sroles:
                    roles = roles + sroles
        return [role.name for role in roles]

    def get_global_roles_for_user(self, user_id):
        """
        Method to return all the global roles for the given user.
        user_id -- user ID
        """
        ts = []
        drolegrants = self.grant_manager.list_global_roles_for_user(user_id)
        for drolegrant in drolegrants:
            drole = self.role_manager.get(drolegrant.role_id)
            ts.append(Role(drolegrant.role_id, drole.name,
                      None, drolegrant.tenant_id))
        return ts

    def get_tenant_roles_for_user_and_services(self, user_id, tenant_id,
                                               service_ids):
        """
        Method to return all the tenant roles for the given user,
        filtered by service ID.
        user_id -- user ID
        tenant_id -- tenant ID
        service_ids -- service IDs
        If service_ids are specified, will return the roles filtered by
        service IDs.
        """
        ts = []
        if tenant_id and user_id:
            drolegrants = self.grant_manager.list_tenant_roles_for_user(
                                                            user_id, tenant_id)
            for drolegrant in drolegrants:
                drole = self.role_manager.get(drolegrant.role_id)
                ts.append(Role(drolegrant.role_id, drole.name,
                    None, drolegrant.tenant_id))

        if service_ids:
            # if service IDs are specified, filter roles by service IDs
            sroles_names = self.get_roles_names_by_service_ids(service_ids)
            return [role for role in ts
                    if role.name in sroles_names]
        else:
            return ts

    @service_admin_token_validator
    def get_endpoints_for_token(self, admin_token,
            token_id, marker, limit, url,):
        dtoken = self.token_manager.get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")
        if not dtoken.tenant_id:
            raise fault.ItemNotFoundFault("Token not mapped to any tenant.")
        return self.fetch_tenant_endpoints(
            marker, limit, url, dtoken.tenant_id)

    def get_token_info(self, token_id):
        """returns token and user object for a token_id"""

        token = None
        user = None
        if token_id:
            token = self.token_manager.get(token_id)
            if token:
                user = self.user_manager.get(token.user_id)
        return (token, user)

    def _validate_token(self, token_id, belongs_to=None, is_check_token=None):
        """
        Method to validate a token.
        token_id -- id of the token that needs to be validated.
        belongs_to -- optional tenant_id to check whether the token is
        mapped to a specific tenant.
        is_check_token -- optional argument that tells whether
        we check the existence of a Token using another Token
        to authenticate. This value decides the faults that are to be thrown.
        """
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")

        (token, user) = self.get_token_info(token_id)

        if not token:
            if is_check_token:
                raise fault.ItemNotFoundFault("Token does not exist.")
            else:
                raise fault.UnauthorizedFault(
                    "Bad token, please reauthenticate")

        if token.expires < datetime.now():
            if is_check_token:
                raise fault.ItemNotFoundFault("Token expired, please renew.")
            else:
                raise fault.ForbiddenFault("Token expired, please renew.")

        if not user.enabled:
            raise fault.UserDisabledFault("User %s has been disabled!"
                % user.id)

        if user.tenant_id:
            self.validate_tenant_by_id(user.tenant_id)

        if token.tenant_id:
            self.validate_tenant_by_id(token.tenant_id)

        if belongs_to and unicode(token.tenant_id) != unicode(belongs_to):
            raise fault.UnauthorizedFault("Unauthorized on this tenant")

        return (token, user)

    def has_admin_role(self, token_id):
        """ Checks if the token belongs to a user who has Keystone admin
        rights.

        Returns (token, user) if true. False otherwise.

        This is currently assigned using a global role assignment
        (i.e. role assigned without a tenant id). The actual name of the
        role is defined in the config file using the keystone-admin-role
        setting
        """
        (token, user) = self._validate_token(token_id)
        self.init_admin_role_identifiers()
        if self.has_role(None, user, ADMIN_ROLE_ID):
            return (token, user)
        else:
            return False

    def has_service_admin_role(self, token_id):
        """ Checks if the token belongs to a user who has Keystone Service
        Admin rights. (Note: Keystone Admin rights include Keystone Service
        Admin).

        Returns (token, user) if true. False otherwise.

        This is currently assigned using a global role assignment
        (i.e. role assigned without a tenant id). The actual name of the role
        is defined in the config file using the keystone-admin-role setting
        """
        (token, user) = self._validate_token(token_id)
        self.init_admin_role_identifiers()
        if self.has_role(None, user, SERVICE_ADMIN_ROLE_ID):
            return (token, user)
        else:
            return self.has_admin_role(token_id)

    def validate_admin_token(self, token_id):
        """ Validates that the token belongs to a user who has Keystone admin
        rights. Raises an Unauthorized exception if not.

        This is currently assigned using a global role assignment
        (i.e. role assigned without a tenant id). The actual name of the role
            is defined in the config file using the keystone-admin-role setting
        """
        result = self.has_admin_role(token_id)
        if result:
            return result
        else:
            raise fault.UnauthorizedFault(
                "You are not authorized to make this call")

    def validate_service_admin_token(self, token_id):
        """ Validates that the token belongs to a user who has Keystone admin
        or Keystone Service Admin rights. Raises an Unaithorized exception if
        not.

        These are currently assigned using a global role assignments
        (i.e. roles assigned without a tenant id). The actual name of the roles
        is defined in the config file using the keystone-admin-role and
        keystone-service-admin-role settings
        """
        # Does the user have the Service Admin role
        result = self.has_service_admin_role(token_id)
        if result:
            LOG.debug("token is associated with service admin role")
            return result
        # Does the user have the Admin role (which includes Service Admin
        # rights)
        result = self.has_admin_role(token_id)
        if result:
            LOG.debug("token is associated with admin role, so responding"
                      "positively from validate_service_admin_token")
            return result

        LOG.debug("token is not associated with admin  or service admin role")
        raise fault.UnauthorizedFault(
            "You are not authorized to make this call")

    def init_admin_role_identifiers(self):
        global ADMIN_ROLE_ID, SERVICE_ADMIN_ROLE_ID
        if SERVICE_ADMIN_ROLE_ID is None:
            role = self.role_manager.get_by_name(SERVICE_ADMIN_ROLE_NAME)
            if role:
                SERVICE_ADMIN_ROLE_ID = role.id
            else:
                LOG.warn('No service admin role found (searching for name=%s.'
                         % SERVICE_ADMIN_ROLE_NAME)
        if ADMIN_ROLE_ID is None:
            role = self.role_manager.get_by_name(ADMIN_ROLE_NAME)
            if role:
                ADMIN_ROLE_ID = role.id
            else:
                LOG.warn('No admin role found (searching for name=%s.'
                         % ADMIN_ROLE_NAME)

    def has_role(self, env, user, role):
        """Checks if a user has a specific role.

        env:    provides the context
        user:   the user to be checked
        role:   the role to check that the user has
        """
        for rolegrant in\
                self.grant_manager.list_global_roles_for_user(user.id):
            if ((rolegrant.role_id == role)
                    and rolegrant.tenant_id is None):
                return True
        LOG.debug("User %s failed check - did not have role %s" %
                    (user.id, role))
        return False

    # pylint: disable=W0613
    @staticmethod
    def is_owner(env, user, object):
        """Checks if a user is the owner of an object.

        This is done by checking if the user id matches the 'owner_id'
        field of the object

        env:    provides the context
        user:   the user to be checked
        role:   the role to check that the user has
        """
        if hasattr(object, 'owner_id'):
            if object.owner_id == user.id:
                return True
        return False

    def validate_unscoped_token(self, token_id, belongs_to=None):
        (token, user) = self._validate_token(token_id, belongs_to)

        if token.tenant_id:
            raise fault.ForbiddenFault("Expecting unscoped token")
        return (token, user)

    def validate_tenant_by_id(self, tenant_id):
        if not tenant_id:
            raise fault.UnauthorizedFault("Missing tenant id")

        dtenant = self.tenant_manager.get(tenant_id)
        return self.validate_tenant(dtenant)

    def validate_tenant_by_name(self, tenant_name):
        if not tenant_name:
            raise fault.UnauthorizedFault("Missing tenant name")

        dtenant = self.tenant_manager.get_by_name(name=tenant_name)
        return self.validate_tenant(dtenant)

    def get_auth_data(self, dtoken):
        """returns AuthData object for a token

        AuthData is used for rendering authentication responses
        """
        tenant = None
        endpoints = None

        if dtoken.tenant_id:
            dtenant = self.tenant_manager.get(dtoken.tenant_id)
            tenant = auth.Tenant(id=dtenant.id, name=dtenant.name)
            endpoints = self.tenant_manager.get_all_endpoints(dtoken.tenant_id)
        else:
            endpoints = self.tenant_manager.get_all_endpoints(None)

        token = auth.Token(dtoken.expires, dtoken.id, tenant)
        duser = self.user_manager.get(dtoken.user_id)

        ts = []
        if dtoken.tenant_id:
            drolegrants = self.grant_manager.list_tenant_roles_for_user(
                                                    duser.id, dtoken.tenant_id)
            for drolegrant in drolegrants:
                drole = self.role_manager.get(drolegrant.role_id)
                ts.append(Role(drolegrant.role_id, drole.name,
                    description=drole.desc, tenant_id=drolegrant.tenant_id))
        drolegrants = self.grant_manager.list_global_roles_for_user(duser.id)
        for drolegrant in drolegrants:
            drole = self.role_manager.get(drolegrant.role_id)
            ts.append(Role(drolegrant.role_id, drole.name,
                description=drole.desc, tenant_id=drolegrant.tenant_id))
        user = auth.User(duser.id, duser.name, None, None, Roles(ts, []))
        if self.has_service_admin_role(token.id):
            # Privileged users see the adminURL as well
            url_types = ['admin', 'internal', 'public']
        else:
            url_types = ['internal', 'public']
        return auth.AuthData(token, user, endpoints, url_types=url_types)

    def get_validate_data(self, dtoken, duser, service_ids=None):
        """return ValidateData object for a token/user pair"""
        global GLOBAL_SERVICE_ID
        tenant = None
        if dtoken.tenant_id:
            dtenant = self.tenant_manager.get(dtoken.tenant_id)
            tenant = auth.Tenant(id=dtenant.id, name=dtenant.name)

        token = auth.Token(dtoken.expires, dtoken.id, tenant)

        ts = self.get_tenant_roles_for_user_and_services(duser.id,
                                                    dtoken.tenant_id,
                                                    service_ids)
        if (not dtoken.tenant_id or not service_ids or
                (GLOBAL_SERVICE_ID in service_ids)):
            # return the global roles for unscoped tokens or
            # its ID is in the service IDs
            ts = ts + self.get_global_roles_for_user(duser.id)

        # Also get the user's tenant's name
        tenant_name = None
        if duser.tenant_id:
            utenant = self.tenant_manager.get(duser.tenant_id)
            tenant_name = utenant.name

        user = auth.User(duser.id, duser.name, duser.tenant_id,
            tenant_name, Roles(ts, []))
        return auth.ValidateData(token, user)

    @staticmethod
    def validate_tenant(dtenant):
        if not dtenant:
            raise fault.UnauthorizedFault("Tenant not found")

        if dtenant.enabled is None or \
                str(dtenant.enabled).lower() not in ['1', 'true']:
            raise fault.TenantDisabledFault("Tenant %s has been disabled!"
                % dtenant.id)
        return dtenant

    #
    #   Tenant Operations
    #
    @admin_token_validator
    def create_tenant(self, admin_token, tenant):
        if not isinstance(tenant, Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        utils.check_empty_string(tenant.name, "Expecting a unique Tenant Name")
        if self.tenant_manager.get_by_name(tenant.name) is not None:
            raise fault.TenantConflictFault(
                "A tenant with that name already exists")
        dtenant = Tenant()
        dtenant.name = tenant.name
        dtenant.description = tenant.description
        dtenant.enabled = tenant.enabled
        return self.tenant_manager.create(dtenant)

    # pylint: disable=R0914
    def get_tenants(self, admin_token, marker, limit, url,
                    is_service_operation=False):
        """Fetch tenants for either an admin or service operation."""
        ts = []

        if is_service_operation:
            # Check regular token validity.
            (_token, user) = self._validate_token(admin_token, belongs_to=None,
                                                  is_check_token=False)
            scope = _token.tenant_id
            default_tenant = user.tenant_id

            if (scope is None or
                ((scope and default_tenant) and (scope == default_tenant))):
                # Return all tenants specific to user if token has no scope
                # or if token is scoped to a default tenant
                dtenants = self.tenant_manager.list_for_user_get_page(
                    user.id, marker, limit)
                prev_page, next_page = self.tenant_manager.\
                    list_for_user_get_page_markers(user.id, marker, limit)
            else:
                # Return scoped tenant only
                dtenants = [self.tenant_manager.get(scope or default_tenant)]
                prev_page = 2
                next_page = None
                limit = 10
        else:
            #Check Admin Token
            (_token, user) = self.validate_admin_token(admin_token)
            # Return all tenants
            dtenants = self.tenant_manager.get_page(marker, limit)
            prev_page, next_page = self.tenant_manager.get_page_markers(marker,
                                                                        limit)

        for dtenant in dtenants:
            t = Tenant(id=dtenant.id, name=dtenant.name,
                description=dtenant.desc, enabled=dtenant.enabled)
            ts.append(t)

        links = self.get_links(url, prev_page, next_page, limit)
        return Tenants(ts, links)

    @admin_token_validator
    def get_tenant(self, admin_token, tenant_id):
        dtenant = self.tenant_manager.get(tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant could not be found")
        return Tenant(dtenant.id, dtenant.name, dtenant.desc, dtenant.enabled)

    @admin_token_validator
    def get_tenant_by_name(self, admin_token, tenant_name):
        dtenant = self.tenant_manager.get_by_name(tenant_name)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant could not be found")
        return dtenant

    @admin_token_validator
    def update_tenant(self, admin_token, tenant_id, tenant):
        if not isinstance(tenant, Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        dtenant = self.tenant_manager.get(tenant_id)
        if dtenant is None:
            raise fault.ItemNotFoundFault("The tenant could not be found")

        utils.check_empty_string(tenant.name, "Expecting a unique Tenant Name")

        if tenant.name != dtenant.name and \
                self.tenant_manager.get_by_name(tenant.name):
            raise fault.TenantConflictFault(
                "A tenant with that name already exists")
        values = {'id': tenant_id, 'desc': tenant.description,
                  'enabled': tenant.enabled, 'name': tenant.name}
        self.tenant_manager.update(values)
        dtenant = self.tenant_manager.get(tenant_id)
        return dtenant

    @admin_token_validator
    def delete_tenant(self, admin_token, tenant_id):
        dtenant = self.tenant_manager.get(tenant_id)
        if dtenant is None:
            raise fault.ItemNotFoundFault("The tenant could not be found")

        self.tenant_manager.delete(dtenant.id)
        return None

    #
    #   User Operations
    #
    @admin_token_validator
    def create_user(self, admin_token, user):
        self.validate_and_fetch_user_tenant(user.tenant_id)

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        utils.check_empty_string(user.name,
                "Expecting a unique user Name")

        if self.user_manager.get_by_name(user.name):
            raise fault.UserConflictFault(
                "A user with that name already exists")

        if self.user_manager.get_by_email(user.email):
            raise fault.EmailConflictFault(
                "A user with that email already exists")

        duser = models.User()
        duser.name = user.name
        duser.password = user.password
        duser.email = user.email
        duser.enabled = user.enabled
        duser.tenant_id = user.tenant_id
        duser = self.user_manager.create(duser)
        user.id = duser.id
        return user

    def validate_and_fetch_user_tenant(self, tenant_id):
        if tenant_id:
            dtenant = self.tenant_manager.get(tenant_id)
            if dtenant is None:
                raise fault.ItemNotFoundFault("The tenant is not found")
            elif not dtenant.enabled:
                raise fault.TenantDisabledFault(
                    "Your account has been disabled")
            return dtenant

    # pylint: disable=R0913
    @admin_token_validator
    def get_tenant_users(self, admin_token, tenant_id,
            role_id, marker, limit, url):
        if tenant_id is None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        dtenant = self.tenant_manager.get(tenant_id)
        if dtenant is  None:
            raise fault.ItemNotFoundFault("The tenant not found")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")
        if role_id:
            if not self.role_manager.get(role_id):
                raise fault.ItemNotFoundFault("The role not found")
        ts = []
        dtenantusers = self.user_manager.users_get_by_tenant_get_page(
            tenant_id, role_id, marker, limit)
        for dtenantuser in dtenantusers:
            try:
                troles = dtenantuser.tenant_roles
            except AttributeError:
                troles = None
            ts.append(User(None, dtenantuser.id, dtenantuser.name, tenant_id,
                    dtenantuser.email, dtenantuser.enabled, troles))
        links = []
        if ts.__len__():
            prev, next = self.\
                         user_manager.users_get_by_tenant_get_page_markers(
                                tenant_id, role_id, marker, limit)
            links = self.get_links(url, prev, next, limit)
        return Users(ts, links)

    @admin_token_validator
    def get_users(self, admin_token, marker, limit, url):
        ts = []
        dusers = self.user_manager.users_get_page(marker, limit)
        for duser in dusers:
            ts.append(User(None, duser.id, duser.name, duser.tenant_id,
                                   duser.email, duser.enabled))
        links = []
        if ts.__len__():
            prev, next = self.user_manager.users_get_page_markers(marker,
                                                                  limit)
            links = self.get_links(url, prev, next, limit)
        return Users(ts, links)

    @admin_token_validator
    def get_user(self, admin_token, user_id):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        return User_Update(id=duser.id, tenant_id=duser.tenant_id,
                email=duser.email, enabled=duser.enabled, name=duser.name)

    @admin_token_validator
    def get_user_by_name(self, admin_token, user_name):
        duser = self.user_manager.get_by_name(user_name)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        return User_Update(id=duser.id, tenant_id=duser.tenant_id,
                email=duser.email, enabled=duser.enabled, name=duser.name)

    @admin_token_validator
    def update_user(self, admin_token, user_id, user):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        utils.check_empty_string(user.name,
                "Expecting a unique username")

        if user.name != duser.name and \
          self.user_manager.get_by_name(user.name):
            raise fault.UserConflictFault(
                "A user with that name already exists")

        if user.email != duser.email and \
                self.user_manager.get_by_email(user.email) is not None:
            raise fault.EmailConflictFault("Email already exists")

        values = {'id': user_id, 'email': user.email, 'name': user.name}
        self.user_manager.update(values)
        duser = self.user_manager.get(user_id)
        return User(duser.password, duser.id, duser.name, duser.tenant_id,
            duser.email, duser.enabled)

    @admin_token_validator
    def set_user_password(self, admin_token, user_id, user):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        duser = self.user_manager.get(user_id)
        if duser is None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'id': user_id, 'password': user.password}

        self.user_manager.update(values)

        return User_Update(password=user.password)

    @admin_token_validator
    def enable_disable_user(self, admin_token, user_id, user):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        values = {'id': user_id, 'enabled': user.enabled}

        self.user_manager.update(values)

        duser = self.user_manager.get(user_id)

        return User_Update(enabled=user.enabled)

    @admin_token_validator
    def set_user_tenant(self, admin_token, user_id, user):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not isinstance(user, User):
            raise fault.BadRequestFault("Expecting a User")

        self.validate_and_fetch_user_tenant(user.tenant_id)
        values = {'id': user_id, 'tenant_id': user.tenant_id}
        self.user_manager.update(values)
        return User_Update(tenant_id=user.tenant_id)

    @admin_token_validator
    def delete_user(self, admin_token, user_id):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        self.user_manager.delete(user_id)
        return None

    def create_role(self, admin_token, role):
        user = self.validate_service_admin_token(admin_token)[1]

        if not isinstance(role, Role):
            raise fault.BadRequestFault("Expecting a Role")

        utils.check_empty_string(role.name, "Expecting a Role name")

        if self.role_manager.get_by_name(role.name) is not None:
            raise fault.RoleConflictFault(
                "A role with that name '%s' already exists" % role.name)

        #Check if the role name includes an embedded service: in it
        #if so, verify the service exists
        if role.service_id is None:
            split = role.name.split(":")
            if isinstance(split, list) and len(split) > 1:
                service_name = split[0]
                service = self.service_manager.get_by_name(service_name)
                if service is None:
                    raise fault.BadRequestFault(
                        "A service with the name %s doesn't exist."
                        % service_name)
                role.service_id = service.id

        # Check ownership of the service (or overriding admin rights)
        if role.service_id:
            service = self.service_manager.get(role.service_id)
            if service is None:
                raise fault.BadRequestFault(
                    "A service with that id doesn't exist.")
            if not role.name.startswith(service.name + ":"):
                raise fault.BadRequestFault(
                    "Role should begin with service name '%s:'" % service.name)
            if not self.is_owner(None, user, service):
                if not self.has_admin_role(admin_token):
                    raise fault.UnauthorizedFault(
                        "You do not have ownership of the '%s' service" \
                        % service.name)

        drole = models.Role()
        drole.name = role.name
        drole.desc = role.description
        drole.service_id = role.service_id
        drole = self.role_manager.create(drole)
        role.id = drole.id
        return role

    @service_admin_token_validator
    def get_roles(self, admin_token, marker, limit, url):
        droles = self.role_manager.get_page(marker, limit)
        prev, next = self.role_manager.get_page_markers(marker, limit)
        links = self.get_links(url, prev, next, limit)
        ts = self.transform_roles(droles)
        return Roles(ts, links)

    @service_admin_token_validator
    def get_roles_by_service(self, admin_token, marker, limit, url,
                             service_id):
        droles = self.role_manager.get_by_service_get_page(service_id, marker,
                                                                        limit)
        prev, next = self.role_manager.get_by_service_get_page_markers(
            service_id, marker, limit)
        links = self.get_links(url, prev, next, limit)
        ts = self.transform_roles(droles)
        return Roles(ts, links)

    @staticmethod
    def transform_roles(droles):
        return [Role(drole.id, drole.name, drole.desc, drole.service_id)
                for drole in droles]

    @service_admin_token_validator
    def get_role(self, admin_token, role_id):
        drole = self.role_manager.get(role_id)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")
        return Role(drole.id, drole.name, drole.desc, drole.service_id)

    @service_admin_token_validator
    def get_role_by_name(self, admin_token, role_name):
        drole = self.role_manager.get_by_name(role_name)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")
        return Role(drole.id, drole.name,
            drole.desc, drole.service_id)

    def delete_role(self, admin_token, role_id):
        user = self.validate_service_admin_token(admin_token)[1]

        drole = self.role_manager.get(role_id)
        if not drole:
            raise fault.ItemNotFoundFault("The role could not be found")

        # Check ownership of the service (or overriding admin rights)
        if drole.service_id:
            service = self.service_manager.get(drole.service_id)
            if service:
                if not self.is_owner(None, user, service):
                    if not self.has_admin_role(admin_token):
                        raise fault.UnauthorizedFault(
                            "You do not have ownership of the '%s' service"
                            % service.name)

        rolegrants = self.grant_manager.rolegrant_list_by_role(role_id)
        if rolegrants is not None:
            for rolegrant in rolegrants:
                self.grant_manager.rolegrant_delete(rolegrant.id)
        self.role_manager.delete(role_id)

    @service_admin_token_validator
    def add_role_to_user(self, admin_token, user_id, role_id, tenant_id=None):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        drole = self.role_manager.get(role_id)
        if drole is None:
            raise fault.ItemNotFoundFault("The role not found")
        if tenant_id is not None:
            dtenant = self.tenant_manager.get(tenant_id)
            if dtenant is None:
                raise fault.ItemNotFoundFault("The tenant not found")

        drolegrant = self.grant_manager.rolegrant_get_by_ids(user_id, role_id,
                                                                    tenant_id)
        if drolegrant is not None:
            raise fault.RoleConflictFault(
                "This role is already mapped to the user.")

        drolegrant = models.UserRoleAssociation()
        drolegrant.user_id = duser.id
        drolegrant.role_id = drole.id
        if tenant_id is not None:
            drolegrant.tenant_id = dtenant.id
        self.user_manager.user_role_add(drolegrant)

    @service_admin_token_validator
    def remove_role_from_user(self, admin_token, user_id, role_id,
                              tenant_id=None):
        drolegrant = self.grant_manager.rolegrant_get_by_ids(user_id, role_id,
                                                                    tenant_id)
        if drolegrant is None:
            raise fault.ItemNotFoundFault(
                "This role is not mapped to the user.")
        self.grant_manager.rolegrant_delete(drolegrant.id)

    # pylint: disable=R0913, R0914
    @service_admin_token_validator
    def get_user_roles(self, admin_token, marker,
            limit, url, user_id, tenant_id):
        duser = self.user_manager.get(user_id)

        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if tenant_id is not None:
            dtenant = self.tenant_manager.get(tenant_id)
            if not dtenant:
                raise fault.ItemNotFoundFault("The tenant could not be found.")
        ts = []
        drolegrants = self.grant_manager.rolegrant_get_page(marker, limit,
                                                           user_id, tenant_id)
        for drolegrant in drolegrants:
            drole = self.role_manager.get(drolegrant.role_id)
            ts.append(Role(drole.id, drole.name,
                    drole.desc, drole.service_id))
        prev, next = self.grant_manager.rolegrant_get_page_markers(
            user_id, tenant_id, marker, limit)
        links = self.get_links(url, prev, next, limit)
        return Roles(ts, links)

    def add_endpoint_template(self, admin_token, endpoint_template):
        user = self.validate_service_admin_token(admin_token)[1]

        if not isinstance(endpoint_template, EndpointTemplate):
            raise fault.BadRequestFault("Expecting a EndpointTemplate")

        utils.check_empty_string(endpoint_template.name,
                "Expecting Endpoint Template name.")
        utils.check_empty_string(endpoint_template.type,
                "Expecting Endpoint Template type.")

        dservice = self.service_manager.get_by_name_and_type(
            endpoint_template.name,
            endpoint_template.type)
        if dservice is None:
            raise fault.BadRequestFault(
                    "A service with that name and type doesn't exist.")

        # Check ownership of the service (or overriding admin rights)
        if not self.is_owner(None, user, dservice):
            if not self.has_admin_role(admin_token):
                raise fault.UnauthorizedFault(
                    "You do not have ownership of the '%s' service" \
                    % dservice.name)

        dendpoint_template = models.EndpointTemplates()
        dendpoint_template.region = endpoint_template.region
        dendpoint_template.service_id = dservice.id
        dendpoint_template.public_url = endpoint_template.public_url
        dendpoint_template.admin_url = endpoint_template.admin_url
        dendpoint_template.internal_url = endpoint_template.internal_url
        dendpoint_template.enabled = endpoint_template.enabled
        dendpoint_template.is_global = endpoint_template.is_global
        dendpoint_template.version_id = endpoint_template.version_id
        dendpoint_template.version_list = endpoint_template.version_list
        dendpoint_template.version_info = endpoint_template.version_info
        dendpoint_template = self.endpoint_template_manager.create(
                dendpoint_template)
        endpoint_template.id = dendpoint_template.id
        return endpoint_template

    def modify_endpoint_template(self, admin_token, endpoint_template_id,
                                 endpoint_template):
        user = self.validate_service_admin_token(admin_token)[1]

        if not isinstance(endpoint_template, EndpointTemplate):
            raise fault.BadRequestFault("Expecting a EndpointTemplate")
        dendpoint_template = self.endpoint_template_manager.get(
                endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")

        #Check if the passed service exist.
        utils.check_empty_string(endpoint_template.name,
            "Expecting Endpoint Template name.")
        utils.check_empty_string(endpoint_template.type,
            "Expecting Endpoint Template type.")

        dservice = self.service_manager.get(dendpoint_template.service_id)
        if not dservice:
            raise fault.BadRequestFault(
                    "A service with that name and type doesn't exist.")

        # Check ownership of the service (or overriding admin rights)
        if not self.is_owner(None, user, dservice):
            if not self.has_admin_role(admin_token):
                raise fault.UnauthorizedFault(
                    "You do not have ownership of the '%s' service" \
                    % dservice.name)

        dendpoint_template.region = endpoint_template.region
        dendpoint_template.service_id = dservice.id
        dendpoint_template.public_url = endpoint_template.public_url
        dendpoint_template.admin_url = endpoint_template.admin_url
        dendpoint_template.internal_url = endpoint_template.internal_url
        dendpoint_template.enabled = endpoint_template.enabled
        dendpoint_template.is_global = endpoint_template.is_global
        dendpoint_template.version_id = endpoint_template.version_id
        dendpoint_template.version_list = endpoint_template.version_list
        dendpoint_template.version_info = endpoint_template.version_info
        dendpoint_template = self.endpoint_template_manager.update(
                dendpoint_template)
        return EndpointTemplate(
            dendpoint_template.id,
            dendpoint_template.region,
            dservice.name,
            dservice.type,
            dendpoint_template.public_url,
            dendpoint_template.admin_url,
            dendpoint_template.internal_url,
            dendpoint_template.enabled,
            dendpoint_template.is_global,
            dendpoint_template.version_id,
            dendpoint_template.version_list,
            dendpoint_template.version_info
            )

    def delete_endpoint_template(self, admin_token, endpoint_template_id):
        user = self.validate_service_admin_token(admin_token)[1]
        dendpoint_template = self.endpoint_template_manager.get(
                endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")

        dservice = self.service_manager.get(dendpoint_template.service_id)
        if dservice:
            # Check ownership of the service (or overriding admin rights)
            if not self.is_owner(None, user, dservice):
                if not self.has_admin_role(admin_token):
                    raise fault.UnauthorizedFault(
                        "You do not have ownership of the '%s' service" \
                        % dservice.name)
        else:
            # Cannot verify service ownership, so verify full admin rights
            if not self.has_admin_role(admin_token):
                raise fault.UnauthorizedFault(
                    "You do not have ownership of the '%s' service" \
                    % dservice.name)

        #Delete Related endpoints
        endpoints = self.endpoint_manager.\
            endpoint_get_by_endpoint_template(endpoint_template_id)
        if endpoints is not None:
            for endpoint in endpoints:
                self.endpoint_manager.delete(endpoint.id)
        self.endpoint_template_manager.delete(endpoint_template_id)

    @service_admin_token_validator
    def get_endpoint_templates(self, admin_token, marker, limit, url):
        dendpoint_templates = self.endpoint_template_manager.get_page(marker,
                                                                      limit)
        ts = self.transform_endpoint_templates(dendpoint_templates)
        prev, next = self.endpoint_template_manager.get_page_markers(marker,
                                                                     limit)
        links = self.get_links(url, prev, next, limit)
        return EndpointTemplates(ts, links)

    @service_admin_token_validator
    def get_endpoint_templates_by_service(self, admin_token,
            service_id, marker, limit, url):
        dservice = self.service_manager.get(service_id)
        if dservice is None:
            raise fault.ItemNotFoundFault(
                "No service with the id %s found." % service_id)
        dendpoint_templates = self.endpoint_template_manager.\
            get_by_service_get_page(service_id, marker, limit)
        ts = self.transform_endpoint_templates(dendpoint_templates)
        prev, next = self.endpoint_template_manager.\
            get_by_service_get_page_markers(service_id, marker, limit)
        links = self.get_links(url, prev, next, limit)
        return EndpointTemplates(ts, links)

    def transform_endpoint_templates(self, dendpoint_templates):
        ts = []
        for dendpoint_template in dendpoint_templates:
            dservice = self.service_manager.get(dendpoint_template.service_id)
            ts.append(EndpointTemplate(
                dendpoint_template.id,
                dendpoint_template.region,
                dservice.name,
                dservice.type,
                dendpoint_template.public_url,
                dendpoint_template.admin_url,
                dendpoint_template.internal_url,
                dendpoint_template.enabled,
                dendpoint_template.is_global,
                dendpoint_template.version_id,
                dendpoint_template.version_list,
                dendpoint_template.version_info
                ))
        return ts

    @service_admin_token_validator
    def get_endpoint_template(self, admin_token, endpoint_template_id):
        dendpoint_template = self.endpoint_template_manager.get(
                endpoint_template_id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")
        dservice = self.service_manager.get(dendpoint_template.service_id)
        return EndpointTemplate(
            dendpoint_template.id,
            dendpoint_template.region,
            dservice.name,
            dservice.type,
            dendpoint_template.public_url,
            dendpoint_template.admin_url,
            dendpoint_template.internal_url,
            dendpoint_template.enabled,
            dendpoint_template.is_global,
            dendpoint_template.version_id,
            dendpoint_template.version_list,
            dendpoint_template.version_info
            )

    @service_admin_token_validator
    def get_tenant_endpoints(self, admin_token, marker, limit, url, tenant_id):
        return self.fetch_tenant_endpoints(marker, limit,
                url, tenant_id)

    def fetch_tenant_endpoints(self, marker, limit, url, tenant_id):
        if tenant_id is None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if self.tenant_manager.get(tenant_id) is None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []

        dtenant_endpoints = \
            self.endpoint_manager.endpoint_get_by_tenant_get_page(tenant_id,
                                                                marker, limit)
        for dtenant_endpoint in dtenant_endpoints:
            dendpoint_template = self.endpoint_template_manager.get(
                dtenant_endpoint.endpoint_template_id)
            dservice = self.service_manager.get(dendpoint_template.service_id)
            ts.append(Endpoint(
                            dtenant_endpoint.id,
                            dtenant_endpoint.tenant_id,
                            dendpoint_template.region,
                            dservice.name,
                            dservice.type,
                            dendpoint_template.public_url,
                            dendpoint_template.admin_url,
                            dendpoint_template.internal_url,
                            dendpoint_template.version_id,
                            dendpoint_template.version_list,
                            dendpoint_template.version_info
                            ))
        links = []
        if ts.__len__():
            prev, next = \
                self.endpoint_manager.endpoint_get_by_tenant_get_page_markers(
                    tenant_id, marker, limit)
            links = self.get_links(url, prev, next, limit)
        return Endpoints(ts, links)

    @service_admin_token_validator
    def create_endpoint_for_tenant(self, admin_token, tenant_id,
                                   endpoint_template):
        utils.check_empty_string(tenant_id, "Expecting a Tenant Id.")
        if self.tenant_manager.get(tenant_id) is None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dendpoint_template = self.endpoint_template_manager.get(
                endpoint_template.id)
        if not dendpoint_template:
            raise fault.ItemNotFoundFault(
                "The endpoint template could not be found")
        dendpoint = models.Endpoints()
        dendpoint.tenant_id = tenant_id
        dendpoint.endpoint_template_id = endpoint_template.id
        dendpoint = self.endpoint_manager.create(dendpoint)
        dservice = self.service_manager.get(dendpoint_template.service_id)
        dendpoint = Endpoint(
                            dendpoint.id,
                            dendpoint.tenant_id,
                            dendpoint_template.region,
                            dservice.name,
                            dservice.type,
                            dendpoint_template.public_url,
                            dendpoint_template.admin_url,
                            dendpoint_template.internal_url,
                            dendpoint_template.version_id,
                            dendpoint_template.version_list,
                            dendpoint_template.version_info
                            )
        return dendpoint

    @service_admin_token_validator
    def delete_endpoint(self, admin_token, endpoint_id):
        if self.endpoint_manager.get(endpoint_id) is None:
            raise fault.ItemNotFoundFault("The Endpoint is not found.")
        self.endpoint_manager.delete(endpoint_id)
        return None

    #Service Operations
    @service_admin_token_validator
    def create_service(self, admin_token, service):
        if not isinstance(service, Service):
            raise fault.BadRequestFault("Expecting a Service")

        if self.service_manager.get_by_name(service.name) is not None:
            raise fault.ServiceConflictFault(
                "A service with that name already exists")

        user = self._validate_token(admin_token)[1]

        dservice = models.Service()
        dservice.name = service.name
        dservice.type = service.type
        dservice.desc = service.description
        dservice.owner_id = user.id
        dservice = self.service_manager.create(dservice)
        service.id = dservice.id

        return service

    @service_admin_token_validator
    def get_services(self, admin_token, marker, limit, url):
        ts = []
        dservices = self.service_manager.get_page(marker, limit)
        for dservice in dservices:
            ts.append(Service(dservice.id, dservice.name, dservice.type,
                dservice.desc))
        prev, next = self.service_manager.get_page_markers(marker, limit)
        links = self.get_links(url, prev, next, limit)
        return Services(ts, links)

    @service_admin_token_validator
    def get_service(self, admin_token, service_id):
        dservice = self.service_manager.get(service_id)
        if not dservice:
            raise fault.ItemNotFoundFault("The service could not be found")
        return Service(dservice.id, dservice.name, dservice.type,
            dservice.desc)

    @service_admin_token_validator
    def get_service_by_name(self, admin_token, service_name):
        dservice = self.service_manager.get_by_name(service_name)
        if not dservice:
            raise fault.ItemNotFoundFault("The service could not be found")
        return Service(dservice.id, dservice.name, dservice.type,
            dservice.desc)

    @service_admin_token_validator
    def delete_service(self, admin_token, service_id):
        dservice = self.service_manager.get(service_id)

        if not dservice:
            raise fault.ItemNotFoundFault("The service could not be found")

        #Delete Related Endpointtemplates and Endpoints.
        endpoint_templates = self.endpoint_template_manager.get_by_service(
            service_id)
        if endpoint_templates is not None:
            for endpoint_template in endpoint_templates:
                endpoints = self.endpoint_manager.\
                    endpoint_get_by_endpoint_template(endpoint_template.id)
                if endpoints is not None:
                    for endpoint in endpoints:
                        self.endpoint_manager.delete(endpoint.id)
                self.endpoint_template_manager.delete(endpoint_template.id)
        #Delete Related Role and RoleRefs
        roles = self.role_manager.get_by_service(service_id)
        if roles is not None:
            for role in roles:
                rolegrants = self.grant_manager.rolegrant_list_by_role(role.id)
                if rolegrants is not None:
                    for rolegrant in rolegrants:
                        self.grant_manager.rolegrant_delete(rolegrant.id)
                self.role_manager.delete(role.id)
        self.service_manager.delete(service_id)

    @admin_token_validator
    def get_credentials(self, admin_token, user_id, marker, limit, url):
        ts = []
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        ts.append(PasswordCredentials(duser.name, None))
        links = []
        return Credentials(ts, links)

    @admin_token_validator
    def get_password_credentials(self, admin_token, user_id):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        if not duser.password:
            raise fault.ItemNotFoundFault(
                "Password credentials could not be found")
        return PasswordCredentials(duser.name, None)

    @admin_token_validator
    def delete_password_credentials(self, admin_token, user_id):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        values = {'id': user_id, 'password': None}
        self.user_manager.update(values)

    @admin_token_validator
    def update_password_credentials(self, admin_token, user_id,
                                    password_credentials):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if (password_credentials.user_name is None
                or not password_credentials.user_name.strip()):
            raise fault.BadRequestFault("Expecting a username.")
        duser_name = self.user_manager.get_by_name(
                                            password_credentials.user_name)
        if duser_name.id != duser.id:
            raise fault.UserConflictFault(
                "A user with that name already exists")
        values = {'id': user_id, 'password': password_credentials.password,
            'name': password_credentials.user_name}
        self.user_manager.update(values)
        duser = self.user_manager.get(user_id)
        return PasswordCredentials(duser.name, duser.password)

    @admin_token_validator
    def create_password_credentials(self, admin_token, user_id,
                                    password_credentials):
        duser = self.user_manager.get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if password_credentials.user_name is None or\
            not password_credentials.user_name.strip():
            raise fault.BadRequestFault("Expecting a username.")

        if password_credentials.user_name != duser.name:
            duser_name = self.user_manager.get_by_name(
                                            password_credentials.user_name)
            if duser_name:
                raise fault.UserConflictFault(
                    "A user with that name already exists")
        if duser.password:
            raise fault.BadRequestFault(
                "Password credentials already available.")
        values = {'id': user_id, 'password': password_credentials.password,
            'name': password_credentials.user_name}
        self.user_manager.update(values)
        duser = self.user_manager.get(user_id)
        return PasswordCredentials(duser.name, duser.password)

    @staticmethod
    def get_links(url, prev, next, limit):
        """Method to form and return pagination links."""
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?marker=%s&limit=%s" \
                                                % (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?marker=%s&limit=%s" \
                                                % (url, next, limit)))
        return links
