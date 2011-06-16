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

from keystone.db.sqlalchemy import get_session, models, aliased

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
