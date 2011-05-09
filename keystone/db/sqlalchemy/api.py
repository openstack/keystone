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
from sqlalchemy.orm import joinedload
import models


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


def tenant_get_page(marker,limit,session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Tenant).filter("id>:marker").params(\
                            marker = '%s' % marker).order_by\
                            (models.Tenant.id.desc()).limit(limit).all()
    else:
        return session.query(models.Tenant).order_by(\
                            models.Tenant.id.desc()).limit(limit).all()
    #return session.query(models.Tenant).all()


def tenant_get_page_markers(marker,limit,session=None):
    if not session:
        session = get_session()
    first = session.query(models.Tenant).order_by(\
                        models.Tenant.id).first()
    last = session.query(models.Tenant).order_by(\
                        models.Tenant.id.desc()).first()
    if marker is None:
        marker=first.id
    next=session.query(models.Tenant).filter("id > :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Tenant.id).limit(limit).all()
    prev=session.query(models.Tenant).filter("id < :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Tenant.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next=last
    else:
        for t in next:
            next=t
    if len(prev) == 0:
        prev=first
    else:
        for t in prev:
            prev=t
    if prev.id == marker:
        prev = None
    else:
        prev=prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev,next)


def tenant_is_empty(id, session=None):
    if not session:
        session = get_session()
    a_user = session.query(models.UserTenantAssociation).filter_by(
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


def tenant_group_is_empty( id, session=None):
    if not session:
        session = get_session()
    a_user = session.query(models.UserGroupAssociation).filter_by(
        group_id=id).first()
    if a_user != None:
        return False

    return True

def tenant_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_get(id, session)
        session.delete(tenant_ref)


def tenant_group_create(values):
    group_ref = models.Group()
    group_ref.update(values)
    group_ref.save()
    return group_ref


def tenant_group_get(id, tenant, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(id=id, tenant_id=tenant).first()

    return result

def tenant_group_get_page(tenantId, marker,limit,session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Group).filter("id>:marker").params(\
                            marker = '%s' % marker).filter_by(\
                            tenant_id=tenantId).order_by\
                            (models.Group.id.desc()).limit(limit).all()
    else:
        return session.query(models.Group).filter_by(tenant_id=tenantId)\
                        .order_by(models.Group.id.desc()).limit(limit).all()
    #return session.query(models.Tenant).all()


def tenant_group_get_page_markers(tenantId, marker,limit,session=None):
    if not session:
        session = get_session()
    first = session.query(models.Group).filter_by(tenant_id=tenantId).order_by(\
                        models.Group.id).first()
    last = session.query(models.Group).filter_by(tenant_id=tenantId).order_by(\
                        models.Group.id.desc()).first()
    if marker is None:
        marker=first.id
    next=session.query(models.Group).filter("id > :marker").params(\
                    marker = '%s' % marker).filter_by(\
                    tenant_id=tenantId).order_by(\
                    models.Group.id).limit(limit).all()
    prev=session.query(models.Group).filter("id < :marker").params(\
                    marker = '%s' % marker).filter_by(\
                    tenant_id=tenantId).order_by(\
                    models.Group.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next=last
    else:
        for t in next:
            next=t
    if len(prev) == 0:
        prev=first
    else:
        for t in prev:
            prev=t
    if prev.id == marker:
        prev = None
    else:
        prev=prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev,next)

def tenant_group_update(id, tenant_id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_group_get(id, tenant_id, session)
        tenant_ref.update(values)
        tenant_ref.save(session=session)


def tenant_group_delete(id,tenant_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenantgroup_ref = tenant_group_get(id,tenant_id, session)
        session.delete(tenantgroup_ref)


def user_create(values):
    user_ref = models.User()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def user_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).options(joinedload('groups')).options(
        joinedload('tenants')).filter_by(id=id).first()
    return result


def user_get_by_tenant(tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserTenantAssociation).filter_by(
    tenant_id=tenant_id)
    return result


def user_groups(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(
        user_id=id)
    return result


def user_update(id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = user_get(id, session)
        user_ref.update(values)
        user_ref.save(session=session)


def user_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = user_get(id, session)
        session.delete(user_ref)


def group_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(id=id).first()
    return result


def group_users(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Users).filter_by(
        group_id=id)
    return result

def users_tenant_group_get_page(group_id, marker,limit,session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Users).filter_by(\
                            group_id=group_id).filter("id>:marker").params(\
                            marker = '%s' % marker).order_by\
                            (models.Users.id.desc()).limit(limit).all()
    else:
        return session.query(models.Users).filter_by(\
                            group_id=group_id).order_by(\
                            models.Users.id.desc()).limit(limit).all()



def users_tenant_group_get_page_markers(group_id, marker,limit,session=None):
    if not session:
        session = get_session()
    first = session.query(models.Users).order_by(\
                        models.Users.id).first()
    last = session.query(models.Users).order_by(\
                        models.Users.id.desc()).first()
    if marker is None:
        marker=first.id
    next=session.query(models.Users).filter_by(\
                    group_id=group_id).filter("id > :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Users.id).limit(limit).all()
    prev=session.query(models.Users).filter_by(\
                    group_id=group_id).filter("id < :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Users.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next=last
    else:
        for t in next:
            next=t
    if len(prev) == 0:
        prev=first
    else:
        for t in prev:
            prev=t
    if prev.id == marker:
        prev = None
    else:
        prev=prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev,next)


def group_get_all(session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group)
    return result

def group_get_page(marker,limit,session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Group).filter("id>:marker").params(\
                            marker = '%s' % marker).order_by\
                            (models.Group.id.desc()).limit(limit).all()
    else:
        return session.query(models.Group).order_by(\
                            models.Group.id.desc()).limit(limit).all()



def group_get_page_markers(marker,limit,session=None):
    if not session:
        session = get_session()
    first = session.query(models.Group).order_by(\
                        models.Group.id).first()
    last = session.query(models.Group).order_by(\
                        models.Group.id.desc()).first()
    if marker is None:
        marker=first.id
    next=session.query(models.Group).filter("id > :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Group.id).limit(limit).all()
    prev=session.query(models.Group).filter("id < :marker").params(\
                    marker = '%s' % marker).order_by(\
                    models.Group.id.desc()).limit(int(limit)).all()
    if len(next) == 0:
        next=last
    else:
        for t in next:
            next=t
    if len(prev) == 0:
        prev=first
    else:
        for t in prev:
            prev=t
    if prev.id == marker:
        prev = None
    else:
        prev=prev.id
    if next.id == last.id:
        next = None
    else:
        next = next.id
    return (prev,next)


def group_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        group_ref = group_get(id, session)
        session.delete(group_ref)


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
