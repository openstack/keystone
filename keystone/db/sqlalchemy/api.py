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


from session import get_session
from sqlalchemy.orm import joinedload, aliased
import models


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
    a_user = session.query(models.UserTenantAssociation).filter_by(\
        tenant_id=id).first()
    if a_user != None:
        return False
    a_group = session.query(models.Group).filter_by(tenant_id=id).first()
    if a_group != None:
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

#
# User Operations
#


def user_create(values):
    user_ref = models.User()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def user_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).options(joinedload('groups')).options(\
            joinedload('tenants')).filter_by(id=id).first()
    return result


def user_groups(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(\
            user_id=id)
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
        user_id=user_id).order_by("expires desc").first()
    return result


def user_tenant_create(values):
    user_tenant_ref = models.UserTenantAssociation()
    user_tenant_ref.update(values)
    user_tenant_ref.save()
    return user_tenant_ref


def user_get_update(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=id).first()
    return result


def user_get_email(email, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(email=email).first()
    return result


def users_get_by_tenant_get_page(tenant_id, marker, limit, session=None):
    if not session:
        session = get_session()
    uta = aliased(models.UserTenantAssociation)
    user = aliased(models.User)
    if marker:
        return session.query(user, uta).join(
                            (uta, uta.user_id == user.id)).\
                            filter(uta.tenant_id == tenant_id).\
                            filter("id>=:marker").params(
                            marker='%s' % marker).order_by(
                            user.id).limit(limit).all()
    else:
        return session.query(user, uta).\
                            join((uta, uta.user_id == user.id)).\
                            filter(uta.tenant_id == tenant_id).order_by(
                            user.id).limit(limit).all()


def users_get_by_tenant_get_page_markers(tenant_id, marker, limit,\
        session=None):
    if not session:
        session = get_session()
    uta = aliased(models.UserTenantAssociation)
    user = aliased(models.User)
    first, firstassoc = session.query(user, uta).\
                        join((uta, uta.user_id == user.id)).\
                        filter(uta.tenant_id == tenant_id).\
                        order_by(user.id).first()
    last, lastassoc = session.query(user, uta).\
                        join((uta, uta.user_id == user.id)).\
                        filter(uta.tenant_id == tenant_id).\
                        order_by(user.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(user, uta).join((uta, uta.user_id == user.id)).\
                    filter(uta.tenant_id == tenant_id).\
                    filter("id > :marker").params(\
                    marker='%s' % marker).order_by(user.id).\
                    limit(int(limit)).all()
    prev = session.query(user, uta).join((uta, uta.user_id == user.id)).\
                    filter(uta.tenant_id == tenant_id).\
                    filter("id < :marker").params(
                    marker='%s' % marker).order_by(
                    user.id.desc()).limit(int(limit)).all()
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


def user_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = user_get(id, session)
        session.delete(user_ref)


def user_get_by_tenant(id, tenant_id, session=None):
    if not session:
        session = get_session()
    user_tenant = session.query(models.UserTenantAssociation).filter_by(\
    tenant_id=tenant_id, user_id=id).first()
    return user_tenant


def user_get_by_group(id, session=None):
    if not session:
        session = get_session()
    user_group = session.query(models.Group).filter_by(tenant_id=id).all()
    return user_group


def user_delete_tenant(id, tenant_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_tenant_ref = user_get_by_tenant(id, tenant_id, session)

        session.delete(user_tenant_ref)
        user_group_ref = user_get_by_group(tenant_id, session)

        if user_group_ref is not None:
            for user_group in user_group_ref:
                group_users = session.query(models.UserGroupAssociation)\
                                .filter_by(user_id=id,
                                        group_id=user_group.id).all()
                for group_user in group_users:
                    session.delete(group_user)
        user_tenant_ref = session.query(models.UserTenantAssociation)\
                            .filter_by(user_id=id).first()
        if user_tenant_ref is None:
            user_ref = user_get(id, session)
            session.delete(user_ref)
