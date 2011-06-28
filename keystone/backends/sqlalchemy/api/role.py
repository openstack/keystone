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

from keystone.backends.sqlalchemy import get_session, models

def create(values):
    role_ref = models.Role()
    role_ref.update(values)
    role_ref.save()
    return role_ref


def get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Role).filter_by(id=id).first()
    return result


def get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Role).all()


def get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.Role).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.Role.id.desc()).limit(limit).all()
    else:
        return session.query(models.Role).order_by(\
                            models.Role.id.desc()).limit(limit).all()


def ref_get_page(marker, limit, user_id, session=None):
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


def ref_get_all_global_roles(user_id, session=None):
    if not session:
        session = get_session()
    return session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter("tenant_id is null").all()


def ref_get_all_tenant_roles(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    return session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).all()


def ref_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.UserRoleAssociation).filter_by(id=id).first()
    return result


def ref_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        role_ref = ref_get(id, session)
        session.delete(role_ref)

def get_page_markers(marker, limit, session=None):
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


def ref_get_page_markers(user_id, marker, limit, session=None):
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
