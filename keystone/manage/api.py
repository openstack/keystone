import sys
import datetime

import keystone.backends as db
import keystone.backends.api as db_api
import keystone.backends.models as db_models


def add_user(id, password, tenant=None):
    try:
        obj = db_models.User()
        obj.id = id
        obj.password = password
        obj.enabled = True
        obj.tenant_id = tenant
        db_api.USER.create(obj)
        return True
    except:
        raise Exception("Failed to create user %s" % (id,), sys.exc_info())


def disable_user(id):
    try:
        obj = db_api.USER.get(id)
        if obj == None:
            raise IndexError("User %s not found" % id)
        obj.enabled = False
        db_api.USER.update(id, obj)
    except:
        raise Exception("Failed to disable user %s" % (id,),
            sys.exc_info())


def list_users():
    try:
        objects = db_api.USER.get_all()
        if objects == None:
            raise IndexError("Users not found")
        return [[o.id, o.enabled, o.tenant_id] for o in objects]
    except:
        raise Exception("Error getting all users", sys.exc_info())


def add_tenant(id):
    try:
        obj = db_models.Tenant()
        obj.id = id
        obj.enabled = True
        db_api.TENANT.create(obj)
        return True
    except:
        raise Exception("Failed to create tenant %s" % (id,), sys.exc_info())


def list_tenants():
    try:
        objects = db_api.TENANT.get_all()
        if objects == None:
            raise IndexError("Tenants not found")
        return [[o.id, o.enabled] for o in objects]
    except:
        raise Exception("Error getting all tenants", sys.exc_info())


def disable_tenant(id):
    try:
        obj = db_api.TENANT.get(id)
        if obj == None:
            raise IndexError("Tenant %s not found" % id)
        obj.enabled = False
        db_api.TENANT.update(id, obj)
        return True
    except:
        raise Exception("Failed to disable tenant %s" % (id,), sys.exc_info())


def add_role(id):
    try:
        obj = db_models.Role()
        obj.id = id
        db_api.ROLE.create(obj)
        return True
    except:
        raise Exception("Failed to create role %s" % (id,), sys.exc_info())


def list_role_assignments(tenant):
    try:
        objects = db_api.TENANT.get_role_assignments(tenant)
        if objects == None:
            raise IndexError("Assignments not found")
        return [[o.user_id, o.role_id] for o in objects]
    except:
        raise Exception("Error getting all role assignments for %s"
            % (tenant,), sys.exc_info())


def list_roles(tenant=None):
    if tenant:
        return list_role_assignments(tenant)
    else:
        try:
            objects = db_api.ROLE.get_all()
            if objects == None:
                raise IndexError("Roles not found")
            return [[o.id] for o in objects]
        except:
            raise Exception("Error getting all roles", sys.exc_info())


def grant_role(role, user, tenant=None):
    """Grants `role` to `user` (and optionally, on `tenant`)"""
    try:
        obj = db_models.UserRoleAssociation()
        obj.role_id = role
        obj.user_id = user
        obj.tenant_id = tenant
        db_api.USER.user_role_add(obj)
        return True
    except:
        raise Exception("Failed to grant role %s to %s on %s" %
            (role, user, tenant), sys.exc_info())


def add_endpoint_template(region, service, public_url, admin_url, internal_url,
        enabled, is_global):
    try:
        obj = db_models.EndpointTemplates()
        obj.region = region
        obj.service = service
        obj.public_url = public_url
        obj.admin_url = admin_url
        obj.internal_url = internal_url
        obj.enabled = enabled
        obj.is_global = is_global
        obj = db_api.ENDPOINT_TEMPLATE.create(obj)
        return True
    except:
        raise Exception("Failed to create EndpointTemplates for %s" %
            (service,), sys.exc_info())


def list_tenant_endpoints(tenant):
    try:
        objects = db_api.ENDPOINT_TEMPLATE.endpoint_get_by_tenant(tenant)
        if objects == None:
            raise IndexError("URLs not found")
        return [[o.service, o.region, o.public_url] for o in objects]
    except:
        raise Exception("Error getting all endpoints for %s" %
            (tenant,), sys.exc_info())


def list_endpoint_templates():
    try:
        objects = db_api.ENDPOINT_TEMPLATE.get_all()
        if objects == None:
            raise IndexError("URLs not found")
        return [[o.service, o.region, o.public_url] for o in objects]
    except:
        raise Exception("Error getting all EndpointTemplates",
            sys.exc_info())


def add_endpoint(tenant, endpoint_template):
    try:
        obj = db_models.Endpoints()
        obj.tenant_id = tenant
        obj.endpoint_template_id = endpoint_template
        db_api.ENDPOINT_TEMPLATE.endpoint_add(obj)
        return obj
    except:
        raise Exception("Failed to create Endpoint", sys.exc_info())


def add_token(token, user, tenant, expires):
    try:
        obj = db_models.Token()
        obj.id = token
        obj.user_id = user
        obj.tenant_id = tenant
        obj.expires = datetime.datetime.strptime(expires.replace("-", ""),
            "%Y%m%dT%H:%M")
        db_api.TOKEN.create(obj)
        return obj
    except:
        raise Exception("Failed to create token %s" % (token,), sys.exc_info())


def list_tokens():
    try:
        objects = db_api.TOKEN.get_all()
        if objects == None:
            raise IndexError("Tokens not found")
        return [[o.id, o.user_id, o.expires, o.tenant_id] for o in objects]
    except:
        raise Exception("Error getting all tokens", sys.exc_info())


def delete_token(token):
    try:
        obj = db_api.TOKEN.get(token)
        if obj == None:
            raise IndexError("Token %s not found" % (token,))
        db_api.TOKEN.delete(token)
        return True
    except:
        raise Exception("Failed to delete token %s" % (token,),
            sys.exc_info())


def add_service(service):
    try:
        obj = db_models.Service()
        obj.id = service
        db_api.SERVICE.create(obj)
        return obj
    except:
        raise Exception("Failed to create Service %s" % (service,),
            sys.exc_info())


def list_services():
    try:
        objects = db_api.SERVICE.get_all()
        if objects == None:
            raise IndexError("Services not found")
        return [[o.id] for o in objects]
    except:
        raise Exception("Error getting all services", sys.exc_info())


def add_credentials(user, type, key, secrete, tenant=None):
    try:
        obj = db_models.Token()
        obj.user_id = user
        obj.type = type
        obj.key = key
        obj.secret = secrete
        obj.tenant_id = tenant
        db_api.CREDENTIALS.create(obj)
        return obj
    except:
        raise Exception("Failed to create credentials %s" % (user,),
            sys.exc_info())
