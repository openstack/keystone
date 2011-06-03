# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
# Not Yet PEP8 standardized

import logging

from sqlalchemy.orm import joinedload, aliased
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from keystone.common import config
import models


_ENGINE = None
_MAKER = None
BASE = models.Base


def configure_db(options):
    """
    Establish the database, create an engine if needed, and
    register the models.

    :param options: Mapping of configuration options
    """
    global _ENGINE
    if not _ENGINE:
        debug = config.get_option(
            options, 'debug', type='bool', default=False)
        verbose = config.get_option(
            options, 'verbose', type='bool', default=False)
        timeout = config.get_option(
            options, 'sql_idle_timeout', type='int', default=3600)
        _ENGINE = create_engine(options['sql_connection'],
                                pool_recycle=timeout)
        logger = logging.getLogger('sqlalchemy.engine')
        if debug:
            logger.setLevel(logging.DEBUG)
        elif verbose:
            logger.setLevel(logging.INFO)
        register_models()


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _MAKER, _ENGINE
    if not _MAKER:
        assert _ENGINE
        _MAKER = sessionmaker(bind=_ENGINE,
                              autocommit=autocommit,
                              expire_on_commit=expire_on_commit)
    return _MAKER()


def register_models():
    """Register Models and create properties"""
    global _ENGINE
    assert _ENGINE
    BASE.metadata.create_all(_ENGINE)


def unregister_models():
    """Unregister Models, useful clearing out data before testing"""
    global _ENGINE
    assert _ENGINE
    BASE.metadata.drop_all(_ENGINE)


#
# Role API operations
#
def role_create(values):
    role_ref = models.Role()
    role_ref.update(values)
    role_ref.save()
    return role_ref


def role_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Role).filter_by(id=id).first()
    return result


def role_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Role).all()


def role_get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Role).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.Role.id.desc()).limit(limit).all()
    else:
        return session.query(models.Role).order_by(\
                            models.Role.id.desc()).limit(limit).all()


def role_ref_get_page(marker, limit, user_id, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.UserRoleAssociation).\
                filter("id>:marker").params(\
                marker='%s' % marker).filter_by(user_id=user_id).order_by(\
                models.UserRoleAssociation.id.desc()).limit(limit).all()
    else:
        return session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).order_by(\
                models.UserRoleAssociation.id.desc()).limit(limit).all()


def role_ref_get_all_global_roles(user_id, session=None):
    if not session:
        session = get_session()
    return session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter("tenant_id is null").all()


def role_ref_get_all_tenant_roles(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    return session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).all()


def role_ref_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserRoleAssociation).filter_by(id=id).first()
    return result


def role_ref_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        role_ref = role_ref_get(id, session)
        session.delete(role_ref)


#
# Tenant API operations
#
def tenant_create(values):
    tenant_ref = models.Tenant()
    tenant_ref.update(values)
    tenant_ref.save()
    return tenant_ref


def tenant_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Tenant).filter_by(id=id).first()
    return result


def tenant_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Tenant).all()


def tenants_for_user_get_page(user, marker, limit, session=None):
    if not session:
        session = get_session()
    ura = aliased(models.UserRoleAssociation)
    tenant = aliased(models.Tenant)
    q1 = session.query(tenant).join((ura, ura.tenant_id == tenant.id)).\
        filter(ura.user_id == user.id)
    q2 = session.query(tenant).filter(tenant.id == user.tenant_id)
    q3 = q1.union(q2)
    if marker:
        return q3.filter("tenant.id>:marker").params(\
                marker='%s' % marker).order_by(\
                tenant.id.desc()).limit(limit).all()
    else:
        return q3.order_by(\
                            tenant.id.desc()).limit(limit).all()


def tenants_for_user_get_page_markers(user, marker, limit, session=None):
    if not session:
        session = get_session()
    ura = aliased(models.UserRoleAssociation)
    tenant = aliased(models.Tenant)
    q1 = session.query(tenant).join((ura, ura.tenant_id == tenant.id)).\
        filter(ura.user_id == user.id)
    q2 = session.query(tenant).filter(tenant.id == user.tenant_id)
    q3 = q1.union(q2)

    first = q3.order_by(\
                        tenant.id).first()
    last = q3.order_by(\
                        tenant.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = q3.filter(tenant.id > marker).order_by(\
                    tenant.id).limit(limit).all()
    prev = q3.filter(tenant.id > marker).order_by(\
                    tenant.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def tenant_get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Tenant).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.Tenant.id.desc()).limit(limit).all()
    else:
        return session.query(models.Tenant).order_by(\
                            models.Tenant.id.desc()).limit(limit).all()


def tenant_get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.Tenant).order_by(\
                        models.Tenant.id).first()
    last = session.query(models.Tenant).order_by(\
                        models.Tenant.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.Tenant).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Tenant.id).limit(limit).all()
    prev = session.query(models.Tenant).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Tenant.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def tenant_is_empty(id, session=None):
    if not session:
        session = get_session()
    a_user = session.query(models.UserRoleAssociation).filter_by(\
        tenant_id=id).first()
    if a_user != None:
        return False
    a_group = session.query(models.Group).filter_by(tenant_id=id).first()
    if a_group != None:
        return False
    a_user = session.query(models.User).filter_by(tenant_id=id).first()
    if a_user != None:
        return False
    return True


def tenant_update(id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_get(id, session)
        tenant_ref.update(values)
        tenant_ref.save(session=session)


def tenant_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_get(id, session)
        session.delete(tenant_ref)


#
# Tenant Group Operations API
#
def tenant_group_create(values):
    group_ref = models.Group()
    group_ref.update(values)
    group_ref.save()
    return group_ref


def tenant_group_is_empty(id, session=None):
    if not session:
        session = get_session()
    a_user = session.query(models.UserGroupAssociation).filter_by(
        group_id=id).first()
    if a_user != None:
        return False
    return True


def tenant_group_get(id, tenant, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(id=id, \
            tenant_id=tenant).first()

    return result


def tenant_group_get_page(tenantId, marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Group).filter("id>:marker").params(\
                marker='%s' % marker).filter_by(\
                tenant_id=tenantId).order_by(\
                models.Group.id.desc()).limit(limit).all()
    else:
        return session.query(models.Group).filter_by(tenant_id=tenantId)\
                        .order_by(models.Group.id.desc()).limit(limit).all()
    #return session.query(models.Tenant).all()


def tenant_group_get_page_markers(tenantId, marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.Group).filter_by(\
            tenant_id=tenantId).order_by(\
            models.Group.id).first()
    last = session.query(models.Group).filter_by(\
            tenant_id=tenantId).order_by(\
            models.Group.id.desc()).first()

    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.Group).filter("id > :marker").params(\
                    marker='%s' % marker).filter_by(\
                    tenant_id=tenantId).order_by(\
                    models.Group.id).limit(limit).all()
    prev = session.query(models.Group).filter("id < :marker").params(\
                    marker='%s' % marker).filter_by(\
                    tenant_id=tenantId).order_by(\
                    models.Group.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def tenant_group_update(id, tenant_id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_group_get(id, tenant_id, session)
        tenant_ref.update(values)
        tenant_ref.save(session=session)


def tenant_group_delete(id, tenant_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenantgroup_ref = tenant_group_get(id, tenant_id, session)
        session.delete(tenantgroup_ref)


def tenant_role_assignments_get(tenant_id, session=None):
    if not session:
        session = get_session()
    return session.query(models.UserRoleAssociation).\
                        filter_by(tenant_id=tenant_id)


#
# User Operations
#
def user_get_all(session=None):
    if not session:
        session = get_session()
    result = session.query(models.User)
    return result


def get_user_by_group(user_id, group_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserGroupAssociation).filter_by(\
            group_id=group_id, user_id=user_id).first()
    return result


def user_tenant_group(values):
    user_ref = models.UserGroupAssociation()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def user_tenant_group_delete(id, group_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        usertenantgroup_ref = get_user_by_group(id, group_id, session)
        session.delete(usertenantgroup_ref)


def user_create(values):
    user_ref = models.User()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def user_get(id, session=None):
    if not session:
        session = get_session()
    #TODO(Ziad): finish cleaning up model
    #    result = session.query(models.User).options(joinedload('groups')).\
    #              options(joinedload('tenants')).filter_by(id=id).first()
    result = session.query(models.User).filter_by(id=id).first()
    return result


def user_get_email(email, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(email=email).first()
    return result


def user_groups(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(\
            user_id=id)
    return result


def user_roles_by_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserRoleAssociation).filter_by(\
            user_id=user_id, tenant_id=tenant_id).options(joinedload('roles'))
    return result


def user_update(id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = user_get(id, session)
        user_ref.update(values)
        user_ref.save(session=session)


def users_tenant_group_get_page(group_id, marker, limit, session=None):
    if not session:
        session = get_session()
    uga = aliased(models.UserGroupAssociation)
    user = aliased(models.User)
    if marker:
        return session.query(user, uga).join(\
                            (uga, uga.user_id == user.id)).\
                            filter(uga.group_id == group_id).\
                            filter("id>=:marker").params(\
                            marker='%s' % marker).order_by(\
                            user.id).limit(limit).all()
    else:
        return session.query(user, uga).\
                            join((uga, uga.user_id == user.id)).\
                            filter(uga.group_id == group_id).order_by(\
                            user.id).limit(limit).all()


def users_tenant_group_get_page_markers(group_id, marker, limit, session=None):
    if not session:
        session = get_session()
    uga = aliased(models.UserGroupAssociation)
    user = aliased(models.User)
    first = session.query(models.User).order_by(\
                        models.User.id).first()
    last = session.query(models.User).order_by(\
                        models.User.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(user).join(
                            (uga, uga.user_id == user.id)).\
                            filter(uga.group_id == group_id).\
                            filter("id > :marker").params(\
                            marker='%s' % marker).order_by(\
                            user.id).limit(limit).all()
    prev = session.query(user).join(\
                            (uga, uga.user_id == user.id)).\
                            filter(uga.group_id == group_id).\
                            filter("id < :marker").params(\
                            marker='%s' % marker).order_by(\
                            user.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def user_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = user_get(id, session)
        session.delete(user_ref)


def user_get_by_tenant(id, tenant_id, session=None):
    if not session:
        session = get_session()
    # Most common use case: user lives in tenant
    user = session.query(models.User).\
                    filter_by(id=id, tenant_id=tenant_id).first()
    if user:
        return user

    # Find user through grants to this tenant
    user_tenant = session.query(models.UserRoleAssociation).filter_by(\
        tenant_id=tenant_id, user_id=id).first()
    if user_tenant:
        return user_get(id, session)
    else:
        return None


def user_get_by_group(id, session=None):
    if not session:
        session = get_session()
    user_group = session.query(models.Group).filter_by(tenant_id=id).all()
    return user_group


def user_delete_tenant(id, tenant_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        users_tenant_ref = users_get_by_tenant(id, tenant_id, session)
        if users_tenant_ref is not None:
            for user_tenant_ref in users_tenant_ref:
                session.delete(user_tenant_ref)

        user_group_ref = user_get_by_group(tenant_id, session)

        if user_group_ref is not None:
            for user_group in user_group_ref:
                group_users = session.query(models.UserGroupAssociation)\
                                .filter_by(user_id=id,
                                        group_id=user_group.id).all()
                for group_user in group_users:
                    session.delete(group_user)


def user_get_by_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=user_id,
                                                  tenant_id=tenant_id).first()
    return result


def users_get_by_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=user_id,
                                                  tenant_id=tenant_id)
    return result


#
# Group Operations
#
def group_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(id=id).first()
    return result


def group_users(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(\
        group_id=id)
    return result


def group_get_all(session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group)
    return result


def group_get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Group).filter("id>:marker").params(\
                            marker='%s' % marker).order_by(\
                            models.Group.id.desc()).limit(limit).all()
    else:
        return session.query(models.Group).order_by(\
                            models.Group.id.desc()).limit(limit).all()


def group_get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.Group).order_by(\
                        models.Group.id).first()
    last = session.query(models.Group).order_by(\
                        models.Group.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.Group).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Group.id).limit(limit).all()
    prev = session.query(models.Group).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Group.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def group_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        group_ref = group_get(id, session)
        session.delete(group_ref)


#
# Token Operations
#
def token_create(values):
    token_ref = models.Token()
    token_ref.update(values)
    token_ref.save()
    return token_ref


def token_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(token_id=id).first()
    return result


def token_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        token_ref = token_get(id, session)
        session.delete(token_ref)


def token_for_user(user_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(
        user_id=user_id, tenant_id=None).order_by("expires desc").first()
    return result


def token_for_user_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(
        user_id=user_id, tenant_id=tenant_id).order_by("expires desc").first()
    return result


def token_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Token).all()


#
# Unsorted operations
#

def user_role_add(values):
    user_role_ref = models.UserRoleAssociation()
    user_role_ref.update(values)
    user_role_ref.save()
    return user_role_ref


def user_tenant_create(values):
    #TODO(ZIAD): Update model / fix this
    user_tenant_ref = models.UserTenantAssociation()
    user_tenant_ref.update(values)
    user_tenant_ref.save()
    return user_tenant_ref


def user_get_update(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=id).first()
    return result


def users_get_by_tenant_get_page(tenant_id, marker, limit, session=None):
    if not session:
        session = get_session()
    user = aliased(models.User)
    if marker:
        return session.query(user).\
                            filter("tenant_id = :tenant_id").\
                            params(tenant_id='%s' % tenant_id).\
                            filter("id>=:marker").params(
                            marker='%s' % marker).order_by(
                            "id").limit(limit).all()
    else:
        return session.query(user).\
                             filter("tenant_id = :tenant_id").\
                            params(tenant_id='%s' % tenant_id).order_by(
                            "id").limit(limit).all()


def users_get_by_tenant_get_page_markers(tenant_id, marker, limit,\
        session=None):
    if not session:
        session = get_session()
    user = aliased(models.User)
    first = session.query(user).\
                    filter(user.tenant_id == tenant_id).\
                    order_by(user.id).first()
    last = session.query(user).\
                        filter(user.tenant_id == tenant_id).\
                        order_by(user.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(user).\
                    filter(user.tenant_id == tenant_id).\
                    filter("id > :marker").params(\
                    marker='%s' % marker).order_by(user.id).\
                    limit(int(limit)).all()
    prev = session.query(user).\
                    filter(user.tenant_id == tenant_id).\
                    filter("id < :marker").params(
                    marker='%s' % marker).order_by(
                    user.id.desc()).limit(int(limit)).all()
    next_len = len(next)
    prev_len = len(prev)

    if next_len == 0:
        next = last
    else:
        for t in next:
            next = t
    if prev_len == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if first.id == marker:
        prev = None
    else:
        prev = prev.id
    if marker == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def user_groups_get_all(user_id, session=None):
    if not session:
        session = get_session()
    uga = aliased(models.UserGroupAssociation)
    group = aliased(models.Group)
    return session.query(group, uga).\
                            join((uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).order_by(
                            group.id).all()


def groups_get_by_user_get_page(user_id, marker, limit, session=None):
    if not session:
        session = get_session()
    uga = aliased(models.UserGroupAssociation)
    group = aliased(models.Group)
    if marker:
        return session.query(group, uga).join(\
                            (uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).\
                            filter("id>=:marker").params(
                            marker='%s' % marker).order_by(
                            group.id).limit(limit).all()
    else:
        return session.query(group, uga).\
                            join((uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).order_by(
                            group.id).limit(limit).all()


def groups_get_by_user_get_page_markers(user_id, marker, limit, session=None):
    if not session:
        session = get_session()
    uga = aliased(models.UserGroupAssociation)
    group = aliased(models.Group)
    first, firstassoc = session.query(group, uga).\
                        join((uga, uga.group_id == group.id)).\
                        filter(uga.user_id == user_id).\
                        order_by(group.id).first()
    last, lastassoc = session.query(group, uga).\
                        join((uga, uga.group_id == group.id)).\
                        filter(uga.user_id == user_id).\
                        order_by(group.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(group, uga).join(
                            (uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).\
                            filter("id>=:marker").params(
                            marker='%s' % marker).order_by(
                            group.id).limit(int(limit)).all()

    prev = session.query(group, uga).join(
                            (uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).\
                            filter("id < :marker").params(
                            marker='%s' % marker).order_by(
                            group.id).limit(int(limit) + 1).all()
    next_len = len(next)
    prev_len = len(prev)

    if next_len == 0:
        next = last
    else:
        for t, a in next:
            next = t
    if prev_len == 0:
        prev = first
    else:
        for t, a in prev:
            prev = t
    if first.id == marker:
        prev = None
    else:
        prev = prev.id
    if marker == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def role_get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.Role).order_by(\
                        models.Role.id).first()
    last = session.query(models.Role).order_by(\
                        models.Role.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.Role).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Role.id).limit(limit).all()
    prev = session.query(models.Role).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Role.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def role_ref_get_page_markers(user_id, marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.UserRoleAssociation).filter_by(\
                                        user_id=user_id).order_by(\
                        models.UserRoleAssociation.id).first()
    last = session.query(models.UserRoleAssociation).filter_by(\
                                        user_id=user_id).order_by(\
                        models.UserRoleAssociation.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.UserRoleAssociation).filter_by(\
                    user_id=user_id).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.UserRoleAssociation.id).limit(limit).all()
    prev = session.query(models.UserRoleAssociation).filter_by(\
                            user_id=user_id).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.UserRoleAssociation.id.desc()).limit(int(limit)).\
                    all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


#
# BaseURL API operations
#
def baseurls_create(values):
    baseurls_ref = models.BaseUrls()
    baseurls_ref.update(values)
    baseurls_ref.save()
    return baseurls_ref


def baseurls_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.BaseUrls).filter_by(id=id).first()
    return result


def baseurls_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.BaseUrls).all()


def baseurls_get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.BaseUrls).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.BaseUrls.id.desc()).limit(limit).all()
    else:
        return session.query(models.BaseUrls).order_by(\
                            models.BaseUrls.id.desc()).limit(limit).all()


def baseurls_get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.BaseUrls).order_by(\
                        models.BaseUrls.id).first()
    last = session.query(models.BaseUrls).order_by(\
                        models.BaseUrls.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.BaseUrls).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.BaseUrls.id).limit(limit).all()
    prev = session.query(models.BaseUrls).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.BaseUrls.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next = last
    else:
        for t in next:
            next = t
    if len(prev) == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if prev.id == marker:
        prev = None
    else:
        prev = prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def baseurls_ref_get_by_tenant_get_page(tenant_id, marker, limit,
                                        session=None):
    if not session:
        session = get_session()
    if marker:
        return session.query(models.TenantBaseURLAssociation).\
            filter(models.TenantBaseURLAssociation.tenant_id == tenant_id).\
            filter("id >= :marker").params(
            marker='%s' % marker).order_by(
            models.TenantBaseURLAssociation.id).limit(limit).all()
    else:
        return session.query(models.TenantBaseURLAssociation).\
            filter(models.TenantBaseURLAssociation.tenant_id == tenant_id).\
            order_by(models.TenantBaseURLAssociation.id).limit(limit).all()


def baseurls_ref_get_by_tenant_get_page_markers(tenant_id, marker, limit,
                                                session=None):
    if not session:
        session = get_session()
    tba = aliased(models.TenantBaseURLAssociation)
    first = session.query(tba).\
                    filter(tba.tenant_id == tenant_id).\
                    order_by(tba.id).first()
    last = session.query(tba).\
                filter(tba.tenant_id == tenant_id).\
                order_by(tba.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(tba).\
                filter(tba.tenant_id == tenant_id).\
                filter("id>=:marker").params(
                marker='%s' % marker).order_by(
                tba.id).limit(int(limit)).all()

    prev = session.query(tba).\
                    filter(tba.tenant_id == tenant_id).\
                    filter("id < :marker").params(
                    marker='%s' % marker).order_by(
                    tba.id).limit(int(limit) + 1).all()
    next_len = len(next)
    prev_len = len(prev)

    if next_len == 0:
        next = last
    else:
        for t in next:
            next = t
    if prev_len == 0:
        prev = first
    else:
        for t in prev:
            prev = t
    if first.id == marker:
        prev = None
    else:
        prev = prev.id
    if marker == last.id:
        next = None
    else:
        next = next.id
    return (prev, next)


def baseurls_ref_add(values):
    baseurls_ref = models.TenantBaseURLAssociation()
    baseurls_ref.update(values)
    baseurls_ref.save()
    return baseurls_ref


def baseurls_ref_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.TenantBaseURLAssociation).\
                    filter_by(id=id).first()
    return result


def baseurls_ref_get_by_tenant(tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.TenantBaseURLAssociation).\
                    filter_by(tenant_id=tenant_id).first()
    return result


def baseurls_ref_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        baseurls_ref = baseurls_ref_get(id, session)
        session.delete(baseurls_ref)
