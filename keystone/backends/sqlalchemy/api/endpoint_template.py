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

from keystone.backends.sqlalchemy import get_session, models, aliased

def create(values):
    endpoint_template = models.EndpointTemplates()
    endpoint_template.update(values)
    endpoint_template.save()
    return endpoint_template


def get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.EndpointTemplates).filter_by(id=id).first()
    return result


def get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.EndpointTemplates).all()


def get_page(marker, limit, session=None):
    if not session:
        session = get_session()

    if marker:
        return session.query(models.EndpointTemplates).filter("id>:marker").params(\
                marker='%s' % marker).order_by(\
                models.EndpointTemplates.id.desc()).limit(limit).all()
    else:
        return session.query(models.EndpointTemplates).order_by(\
                            models.EndpointTemplates.id.desc()).limit(limit).all()


def get_page_markers(marker, limit, session=None):
    if not session:
        session = get_session()
    first = session.query(models.EndpointTemplates).order_by(\
                        models.EndpointTemplates.id).first()
    last = session.query(models.EndpointTemplates).order_by(\
                        models.EndpointTemplates.id.desc()).first()
    if first is None:
        return (None, None)
    if marker is None:
        marker = first.id
    next = session.query(models.EndpointTemplates).filter("id > :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.EndpointTemplates.id).limit(limit).all()
    prev = session.query(models.EndpointTemplates).filter("id < :marker").params(\
                    marker='%s' % marker).order_by(\
                    models.EndpointTemplates.id.desc()).limit(int(limit)).all()
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


def endpoint_get_by_tenant_get_page(tenant_id, marker, limit,
                                        session=None):
    if not session:
        session = get_session()
    if marker:
        return session.query(models.Endpoints).\
            filter(models.Endpoints.tenant_id == tenant_id).\
            filter("id >= :marker").params(
            marker='%s' % marker).order_by(
            models.Endpoints.id).limit(limit).all()
    else:
        return session.query(models.Endpoints).\
            filter(models.Endpoints.tenant_id == tenant_id).\
            order_by(models.Endpoints.id).limit(limit).all()


def endpoint_get_by_tenant_get_page_markers(tenant_id, marker, limit,
                                                session=None):
    if not session:
        session = get_session()
    tba = aliased(models.Endpoints)
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


def endpoint_add(values):
    endpoints = models.Endpoints()
    endpoints.update(values)
    endpoints.save()
    return endpoints


def endpoint_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Endpoints).\
                    filter_by(id=id).first()
    return result


def endpoint_get_by_tenant(tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Endpoints).\
                    filter_by(tenant_id=tenant_id).first()
    return result


def endpoint_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        endpoints = endpoint_get(id, session)
        session.delete(endpoints)
