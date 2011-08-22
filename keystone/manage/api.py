import datetime

import keystone.backends.api as db_api
import keystone.backends.models as db_models


def add_user(name, password, tenant=None):
    obj = db_models.User()
    obj.name = name
    obj.password = password
    obj.enabled = True
    obj.tenant_id = tenant
    return db_api.USER.create(obj)


def disable_user(name):
    user = db_api.USER.get_by_name(name)
    if user == None:
        raise IndexError("User %s not found" % name)
    user.enabled = False
    return db_api.USER.update(user.id, user)


def list_users():
    objects = db_api.USER.get_all()
    if objects == None:
        raise IndexError("Users not found")
    return [[o.id, o.enabled, o.tenant_id] for o in objects]


def add_tenant(name):
    obj = db_models.Tenant()
    obj.name = name
    obj.enabled = True
    return db_api.TENANT.create(obj)


def list_tenants():
    objects = db_api.TENANT.get_all()
    if objects == None:
        raise IndexError("Tenants not found")
    return [[o.id, o.name, o.enabled] for o in objects]


def disable_tenant(name):
    obj = db_api.TENANT.get_by_name(name)
    if obj == None:
        raise IndexError("Tenant %s not found" % name)
    obj.enabled = False
    return db_api.TENANT.update(obj.id, obj)


def add_role(id):
    obj = db_models.Role()
    obj.id = id
    return db_api.ROLE.create(obj)


def list_role_assignments(tenant):
    objects = db_api.TENANT.get_role_assignments(tenant)
    if objects == None:
        raise IndexError("Assignments not found")
    return [[o.user_id, o.role_id] for o in objects]


def list_roles(tenant=None):
    if tenant:
        return list_role_assignments(tenant)
    else:
        objects = db_api.ROLE.get_all()
        if objects == None:
            raise IndexError("Roles not found")
        return [[o.id] for o in objects]


def grant_role(role, user, tenant=None):
    """Grants `role` to `user` (and optionally, on `tenant`)"""
    # translate username to user id
    duser = db_api.USER.get_by_name(name=user)
    if duser:
        # print 'WARNING: Swapping', user, 'for', duser.id
        user = duser.id

    obj = db_models.UserRoleAssociation()
    obj.role_id = role
    obj.user_id = user
    obj.tenant_id = tenant
    return db_api.USER.user_role_add(obj)


def add_endpoint_template(region, service, public_url, admin_url, internal_url,
    enabled, is_global):
    obj = db_models.EndpointTemplates()
    obj.region = region
    obj.service = service
    obj.public_url = public_url
    obj.admin_url = admin_url
    obj.internal_url = internal_url
    obj.enabled = enabled
    obj.is_global = is_global
    return db_api.ENDPOINT_TEMPLATE.create(obj)


def list_tenant_endpoints(tenant):
    objects = db_api.ENDPOINT_TEMPLATE.endpoint_get_by_tenant(tenant)
    if objects == None:
        raise IndexError("URLs not found")
    return [[o.service, o.region, o.public_url] for o in objects]


def list_endpoint_templates():
    objects = db_api.ENDPOINT_TEMPLATE.get_all()
    if objects == None:
        raise IndexError("URLs not found")
    return [[o.service, o.region, o.public_url] for o in objects]


def add_endpoint(tenant, endpoint_template):
    obj = db_models.Endpoints()
    obj.tenant_id = tenant
    obj.endpoint_template_id = endpoint_template
    db_api.ENDPOINT_TEMPLATE.endpoint_add(obj)
    return obj


def add_token(token, user, tenant, expires):
    obj = db_models.Token()
    obj.id = token
    obj.user_id = user
    obj.tenant_id = tenant
    obj.expires = datetime.datetime.strptime(expires.replace("-", ""),
        "%Y%m%dT%H:%M")
    return db_api.TOKEN.create(obj)


def list_tokens():
    objects = db_api.TOKEN.get_all()
    if objects == None:
        raise IndexError("Tokens not found")
    return [[o.id, o.user_id, o.expires, o.tenant_id] for o in objects]


def delete_token(token):
    obj = db_api.TOKEN.get(token)
    if obj == None:
        raise IndexError("Token %s not found" % (token,))
    return db_api.TOKEN.delete(token)


def add_service(service):
    obj = db_models.Service()
    obj.id = service
    return db_api.SERVICE.create(obj)


def list_services():
    objects = db_api.SERVICE.get_all()
    if objects == None:
        raise IndexError("Services not found")
    return [[o.id] for o in objects]


def add_credentials(user, type, key, secrete, tenant=None):
    obj = db_models.Token()
    obj.user_id = user
    obj.type = type
    obj.key = key
    obj.secret = secrete
    obj.tenant_id = tenant
    return db_api.CREDENTIALS.create(obj)
