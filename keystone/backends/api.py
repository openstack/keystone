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

# pylint: disable=W0603, R0921


#Base APIs
class BaseUserAPI(object):
    def __init__(self, *args, **kw):
        pass

    def get_all(self):
        """ Get all users """
        raise NotImplementedError

    def create(self, values):
        """ Create a user

        The backend will assign an ID if is not passed in

        :param values: dict of user attributes (models.User works)
        :returns: models.User - the created user object

        """
        raise NotImplementedError

    def get(self, id):
        """ Get a user

        :param id: string - the user ID to get
        :returns: models.User - the user object

        """
        raise NotImplementedError

    def get_by_name(self, name):
        """ Get a user by username

        :param name: string - the user name
        :returns: models.User

        """
        raise NotImplementedError

    def get_by_email(self, email):
        """ Get a user by email

        :param name: string - the user email
        :returns: models.User

        """
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    def user_roles_by_tenant(self, user_id, tenant_id):
        raise NotImplementedError

    def update(self, id, values):
        """ Update a user

        :param values: dict of user attributes (models.User works)
        :returns: models.User - the updated user object

        """
        raise NotImplementedError

    def delete(self, id):
        """ Delete a user

        :param id: string - the user id

        """
        raise NotImplementedError

    def get_by_tenant(self, user_id, tenant_id):
        """ Gets a user for a tenant

        Same as get user, but also validates the user is related to that tenant
        either through the default tenant (user.tenant_id) or by role

        :param user_id: string - id of user
        :param tenant_id: string - id of tenant
        :returns: models.User - the user object valid on the tenant, othwerwise
            None

        """
        raise NotImplementedError

    def get_by_access(self, access):
        raise NotImplementedError

    def users_get_by_tenant(self, user_id, tenant_id):
        raise NotImplementedError

    def user_role_add(self, values):
        """ Adds a user to a role (optionally for a tenant) - 'grant'

        This creates a new UserRoleAssociation based on the passed in values

        :param values: dict of values containing user_id, role_id, and
                       optionally a tenant_id

        """
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

    def check_password(self, user_id, password):
        """ Check a user password

        The backend should handle any encryption/decryption

        :param user_id: string - user id
        :param password: string - the password to check
        :returns: True/False

        """
        raise NotImplementedError


class BaseTokenAPI(object):
    def __init__(self, *args, **kw):
        pass

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
    def __init__(self, *args, **kw):
        pass

    def create(self, values):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_by_name(self, name):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def list_for_user_get_page(self, user, marker, limit):
        raise NotImplementedError

    def list_for_user_get_page_markers(self, user, marker, limit):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
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
    def __init__(self, *args, **kw):
        pass

    #
    # Role Methods
    #
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

    def get_by_service_get_page(self, service_id, marker, limit):
        """ Get one page of roles by service"""
        raise NotImplementedError

    def get_by_service_get_page_markers(self, service_id, marker, limit):
        """ Calculate pagination markers for roles by service """
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_page(self, marker, limit):
        raise NotImplementedError

    def get_page_markers(self, marker, limit):
        raise NotImplementedError

    #
    # Role-Grant Methods
    #
    def rolegrant_get(self, id):
        """ Get a UserRoleAssociation (role grant) by id """
        raise NotImplementedError

    def rolegrant_delete(self, id):
        """ Delete a UserRoleAssociation (role grant) by id """
        raise NotImplementedError

    def rolegrant_list_by_role(self, id):
        """ Get a list of all (global and tenant) grants for this role """
        raise NotImplementedError

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id):
        raise NotImplementedError

    def list_global_roles_for_user(self, user_id):
        """ Get a list of all global roles granted to this user.

        :param user_id: string - id of user

        """
        raise NotImplementedError

    def list_tenant_roles_for_user(self, user_id, tenant_id):
        """ Get a list of all tenant roles granted to this user.

        :param user_id: string - id of user
        :param tenant_id: string - id of tenant

        """
        raise NotImplementedError

    def rolegrant_get_page(self, marker, limit, user_id, tenant_id):
        raise NotImplementedError

    def rolegrant_get_page_markers(self, user_id, tenant_id, marker, limit):
        raise NotImplementedError


class BaseEndpointTemplateAPI(object):
    def __init__(self, *args, **kw):
        pass

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

    def get_by_service_get_page(self, service_id, marker, limit):
        raise NotImplementedError

    def get_by_service_get_page_markers(self, service_id, marker, limit):
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


class BaseServiceAPI(object):
    def __init__(self, *args, **kw):
        pass

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
    def __init__(self, *args, **kw):
        pass

    def create(self, values):
        raise NotImplementedError

    def update(self, id, credential):
        raise NotImplementedError

    def delete(self, id):
        raise NotImplementedError

    def get(self, id):
        raise NotImplementedError

    def get_all(self):
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
