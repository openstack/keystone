# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import keystone.utils as utils
from keystone.backends.sqlalchemy import get_session, models, aliased, joinedload

def get_all(session=None):
    if not session:
        session = get_session()
    result = session.query(models.User)
    return result


def get_by_group(user_id, group_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserGroupAssociation).filter_by(\
            group_id=group_id, user_id=user_id).first()
    return result


def tenant_group(values):
    user_ref = models.UserGroupAssociation()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def tenant_group_delete(id, group_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        usertenantgroup_ref = get_by_group(id, group_id, session)
        session.delete(usertenantgroup_ref)


def create(values):
    user_ref = models.User()
    check_and_use_hashed_password(values)
    user_ref.update(values)
    user_ref.save()
    return user_ref

def check_and_use_hashed_password(values):
    if type(values) is dict and 'password' in values.keys():
        values['password'] = utils.get_hashed_password(values['password'])
    elif type(values) is models.User:
        values.password = utils.get_hashed_password(values.password)

def get(id, session=None):
    if not session:
        session = get_session()
    #TODO(Ziad): finish cleaning up model
    #    result = session.query(models.User).options(joinedload('groups')).\
    #              options(joinedload('tenants')).filter_by(id=id).first()
    result = session.query(models.User).filter_by(id=id).first()
    return result


def get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.User).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.User.id.desc()).limit(limit).all()
    else:
        return session.query(models.User).order_by(\
                            models.User.id.desc()).limit(limit).all()


def get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.User).order_by(\
                        models.User.id).first()
    last = session.query(models.User).order_by(\
                        models.User.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.User).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.User.id).limit(limit).all()
    prev = session.query(models.User).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.User.id.desc()).limit(int(limit)).all()
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


def get_by_email(email, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(email=email).first()
    return result


def get_groups(id, session=None):
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


def update(id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = get(id, session)
        check_and_use_hashed_password(values)
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


def delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        user_ref = get(id, session)
        session.delete(user_ref)


def get_by_tenant(id, tenant_id, session=None):
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
        return get(id, session)
    else:
        return None


def get_group_by_tenant(id, session=None):
    if not session:
        session = get_session()
    user_group = session.query(models.Group).filter_by(tenant_id=id).all()
    return user_group


def delete_tenant_user(id, tenant_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        users_tenant_ref = users_get_by_tenant(id, tenant_id, session)
        if users_tenant_ref is not None:
            for user_tenant_ref in users_tenant_ref:
                session.delete(user_tenant_ref)

        user_group_ref = get_group_by_tenant(tenant_id, session)

        if user_group_ref is not None:
            for user_group in user_group_ref:
                get_users = session.query(models.UserGroupAssociation)\
                                .filter_by(user_id=id,
                                        group_id=user_group.id).all()
                for group_user in get_users:
                    session.delete(group_user)


def users_get_by_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=user_id,
                                                  tenant_id=tenant_id)
    return result

def user_role_add(values):
    user_role_ref = models.UserRoleAssociation()
    user_role_ref.update(values)
    user_role_ref.save()
    return user_role_ref


def user_get_update(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).filter_by(id=id).first()
    return result


def users_get_page(marker, limit, session=None):
    if not session:
        session = get_session()
    user = aliased(models.User)
    if marker:
        return session.query(user).\
                            filter("id>=:marker").params(
                            marker='%s' % marker).order_by(
                            "id").limit(limit).all()
    else:
        return session.query(user).\
                            order_by("id").limit(limit).all()

def users_get_page_markers(marker, limit, \
        session=None):
    if not session:
        session = get_session()
    user = aliased(models.User)
    first = session.query(user).\
                    order_by(user.id).first()
    last = session.query(user).\
                        order_by(user.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(user).\
                    filter("id > :marker").params(\
                    marker='%s' % marker).order_by(user.id).\
                    limit(int(limit)).all()
    prev = session.query(user).\
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


def users_get_by_tenant_get_page_markers(tenant_id, marker, limit, \
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
