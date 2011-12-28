import datetime

import keystone.backends.api as db_api
import keystone.backends.models as db_models
import keystone.models as models


def add_user(name, password, tenant=None):
    if tenant:
        tenant = db_api.TENANT.get_by_name(tenant).id

    obj = models.User()
    obj.name = name
    obj.password = password
    obj.enabled = True
    obj.tenant_id = tenant
    return db_api.USER.create(obj)


def disable_user(name):
    user = db_api.USER.get_by_name(name)
    if user is None:
        raise IndexError("User %s not found" % name)
    user.enabled = False
    return db_api.USER.update(user.id, user)


def list_users():
    objects = db_api.USER.get_all()
    if objects is None:
        raise IndexError("No users found")
    return [[o.id, o.name, o.enabled, o.tenant_id] for o in objects]


def add_tenant(name):
    obj = models.Tenant()
    obj.name = name
    obj.enabled = True
    db_api.TENANT.create(obj)


def list_tenants():
    objects = db_api.TENANT.get_all()
    if objects is None:
        raise IndexError("Tenants not found")
    return [[o.id, o.name, o.enabled] for o in objects]


def disable_tenant(name):
    obj = db_api.TENANT.get_by_name(name)
    if obj is None:
        raise IndexError("Tenant %s not found" % name)
    obj.enabled = False
    return db_api.TENANT.update(obj.id, obj)


def add_role(name, service_name=None):
    obj = models.Role()
    obj.name = name

    names = name.split(":")
    if len(names) == 2:
        service_name = names[0] or service_name
    if service_name:
        # we have a role with service prefix, fill in the service ID
        service = db_api.SERVICE.get_by_name(name=service_name)
        obj.service_id = service.id
    return db_api.ROLE.create(obj)


def list_role_assignments(tenant):
    objects = db_api.TENANT.get_role_assignments(tenant)
    if objects is None:
        raise IndexError("Assignments not found")
    return [[o.user.name, o.role.name] for o in objects]


def list_roles(tenant=None):
    if tenant:
        tenant = db_api.TENANT.get_by_name(tenant).id
        return list_role_assignments(tenant)
    else:
        objects = db_api.ROLE.get_all()
        if objects is None:
            raise IndexError("Roles not found")
        return [[o.id, o.name, o.service_id, o.description] for o in objects]


def grant_role(role, user, tenant=None):
    """Grants `role` to `user` (and optionally, on `tenant`)"""
    role = db_api.ROLE.get_by_name(name=role).id
    user = db_api.USER.get_by_name(name=user).id

    if tenant:
        tenant = db_api.TENANT.get_by_name(name=tenant).id

    obj = db_models.UserRoleAssociation()
    obj.role_id = role
    obj.user_id = user
    obj.tenant_id = tenant

    return db_api.USER.user_role_add(obj)


def add_endpoint_template(region, service, public_url, admin_url, internal_url,
    enabled, is_global, version_id, version_list, version_info):
    db_service = db_api.SERVICE.get_by_name(service)
    if db_service is None:
        raise IndexError("Service %s not found" % service)
    obj = db_models.EndpointTemplates()
    obj.region = region
    obj.service_id = db_service.id
    obj.public_url = public_url
    obj.admin_url = admin_url
    obj.internal_url = internal_url
    obj.enabled = enabled
    obj.is_global = is_global
    obj.version_id = version_id
    obj.version_list = version_list
    obj.version_info = version_info
    return db_api.ENDPOINT_TEMPLATE.create(obj)


def list_tenant_endpoints(tenant):
    objects = db_api.ENDPOINT_TEMPLATE.endpoint_get_by_tenant(tenant)
    if objects is None:
        raise IndexError("URLs not found")
    return [[db_api.SERVICE.get(o.service_id).name,
             o.region, o.public_url] for o in objects]


def list_endpoint_templates():
    objects = db_api.ENDPOINT_TEMPLATE.get_all()
    if objects is None:
        raise IndexError("URLs not found")
    return [[o.id,
             db_api.SERVICE.get(o.service_id).name,
             db_api.SERVICE.get(o.service_id).type,
             o.region, o.enabled, o.is_global,
             o.public_url, o.admin_url] for o in objects]


def add_endpoint(tenant, endpoint_template):
    tenant = db_api.TENANT.get_by_name(name=tenant).id
    endpoint_template = db_api.ENDPOINT_TEMPLATE.get(id=endpoint_template).id

    obj = db_models.Endpoints()
    obj.tenant_id = tenant
    obj.endpoint_template_id = endpoint_template
    db_api.ENDPOINT_TEMPLATE.endpoint_add(obj)
    return obj


def add_token(token, user, tenant, expires):
    user = db_api.USER.get_by_name(name=user).id
    if tenant:
        tenant = db_api.TENANT.get_by_name(name=tenant).id

    obj = models.Token()
    obj.id = token
    obj.user_id = user
    obj.tenant_id = tenant
    obj.expires = datetime.datetime.strptime(expires.replace("-", ""),
        "%Y%m%dT%H:%M")
    return db_api.TOKEN.create(obj)


def list_tokens():
    objects = db_api.TOKEN.get_all()
    if objects is None:
        raise IndexError("Tokens not found")
    return [[o.id, o.user_id, o.expires, o.tenant_id] for o in objects]


def delete_token(token):
    obj = db_api.TOKEN.get(token)
    if obj is None:
        raise IndexError("Token %s not found" % (token,))
    return db_api.TOKEN.delete(token)


def add_service(name, type, desc, owner_id):
    obj = models.Service()
    obj.name = name
    obj.type = type
    obj.description = desc
    obj.owner_id = owner_id
    return db_api.SERVICE.create(obj)


def list_services():
    objects = db_api.SERVICE.get_all()
    if objects is None:
        raise IndexError("Services not found")
    return [[o.id, o.name, o.type, o.owner_id, o.description] for o in objects]


def add_credentials(user, type, key, secrete, tenant=None):
    user = db_api.USER.get_by_name(user).id

    if tenant:
        tenant = db_api.TENANT.get_by_name(tenant).id

    obj = models.Credentials()
    obj.user_id = user
    obj.type = type
    obj.key = key
    obj.secret = secrete
    obj.tenant_id = tenant
    return db_api.CREDENTIALS.create(obj)
