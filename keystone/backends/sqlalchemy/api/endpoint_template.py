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
from keystone.backends import api


# pylint: disable=E1103,W0221
class EndpointTemplateAPI(api.BaseEndpointTemplateAPI):
    def __init__(self, *args, **kw):
        super(EndpointTemplateAPI, self).__init__(*args, **kw)

    @staticmethod
    def transpose(values):
        """ Transposes field names from domain to sql model"""
        pass

    @staticmethod
    def to_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        pass

    @staticmethod
    def to_model_list(refs):
        return [EndpointTemplateAPI.to_model(ref) for ref in refs]

    def create(self, values):
        endpoint_template = models.EndpointTemplates()
        endpoint_template.update(values)
        endpoint_template.save()
        return endpoint_template

    def update(self, id, values, session=None):
        if not session:
            session = get_session()
        with session.begin():
            ref = self.get(id, session)
            ref.update(values)
            ref.save(session=session)
            return ref

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            endpoint_template = self.get(id, session)
            session.delete(endpoint_template)

    def get(self, id, session=None):
        if id is None:
            return None

        session = session or get_session()

        return session.query(models.EndpointTemplates).\
            filter_by(id=id).first()

    def get_all(self, session=None):
        if not session:
            session = get_session()

        return session.query(models.EndpointTemplates).all()

    def get_by_service(self, service_id, session=None):
        if not session:
            session = get_session()
        return session.query(models.EndpointTemplates).\
            filter_by(service_id=service_id).all()

    def get_by_service_get_page(self, service_id, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            return session.query(models.EndpointTemplates).\
                    filter("id>:marker").params(\
                    marker='%s' % marker).filter_by(\
                    service_id=service_id).order_by(\
                    models.EndpointTemplates.id.desc()).limit(int(limit)).all()
        else:
            return session.query(models.EndpointTemplates).filter_by(\
                                service_id=service_id).order_by(\
                                models.EndpointTemplates.id.desc()).\
                                limit(int(limit)).all()

    # pylint: disable=R0912
    def get_by_service_get_page_markers(self, service_id, marker, \
        limit, session=None):
        if not session:
            session = get_session()
        first = session.query(models.EndpointTemplates).filter_by(\
                            service_id=service_id).order_by(\
                            models.EndpointTemplates.id).first()
        last = session.query(models.EndpointTemplates).filter_by(\
                            service_id=service_id).order_by(\
                            models.EndpointTemplates.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = session.query(models.EndpointTemplates).\
            filter("id > :marker").\
            filter_by(service_id=service_id).\
            params(marker='%s' % marker).\
            order_by(models.EndpointTemplates.id).\
            limit(int(limit)).\
            all()
        prev_page = session.query(models.EndpointTemplates).\
            filter("id < :marker").\
            filter_by(service_id=service_id).\
            params(marker='%s' % marker).\
            order_by(models.EndpointTemplates.id.desc()).\
            limit(int(limit)).\
            all()
        if len(next_page) == 0:
            next_page = last
        else:
            for t in next_page:
                next_page = t
        if len(prev_page) == 0:
            prev_page = first
        else:
            for t in prev_page:
                prev_page = t
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            return session.query(models.EndpointTemplates).\
                    filter("id>:marker").params(\
                    marker='%s' % marker).order_by(\
                    models.EndpointTemplates.id.desc()).limit(int(limit)).all()
        else:
            return session.query(models.EndpointTemplates).order_by(\
                                models.EndpointTemplates.id.desc()).\
                                limit(int(limit)).all()

    # pylint: disable=R0912
    def get_page_markers(self, marker, limit, session=None):
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
        next_page = session.query(models.EndpointTemplates).\
            filter("id > :marker").\
            params(marker='%s' % marker).\
            order_by(models.EndpointTemplates.id).\
            limit(int(limit)).\
            all()
        prev_page = session.query(models.EndpointTemplates).\
            filter("id < :marker").\
            params(marker='%s' % marker).\
            order_by(models.EndpointTemplates.id.desc()).\
            limit(int(limit)).\
            all()
        if len(next_page) == 0:
            next_page = last
        else:
            for t in next_page:
                next_page = t
        if len(prev_page) == 0:
            prev_page = first
        else:
            for t in prev_page:
                prev_page = t
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def endpoint_get_by_tenant_get_page(self, tenant_id, marker, limit,
            session=None):
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        if marker:
            results = session.query(models.Endpoints).\
                filter(models.Endpoints.tenant_id == tenant_id).\
                filter("id >= :marker").params(
                marker='%s' % marker).order_by(
                models.Endpoints.id).limit(int(limit)).all()
        else:
            results = session.query(models.Endpoints).\
                filter(models.Endpoints.tenant_id == tenant_id).\
                order_by(models.Endpoints.id).limit(int(limit)).all()

        if hasattr(api.TENANT, 'id_to_uid'):
            for result in results:
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return results

    # pylint: disable=R0912
    def endpoint_get_by_tenant_get_page_markers(self, tenant_id, marker, limit,
            session=None):
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

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
        next_page = session.query(tba).\
            filter(tba.tenant_id == tenant_id).\
            filter("id>=:marker").params(
            marker='%s' % marker).order_by(
            tba.id).limit(int(limit)).all()

        prev_page = session.query(tba).\
                        filter(tba.tenant_id == tenant_id).\
                        filter("id < :marker").params(
                        marker='%s' % marker).order_by(
                        tba.id).limit(int(limit) + 1).all()
        next_len = len(next_page)
        prev_len = len(prev_page)

        if next_len == 0:
            next_page = last
        else:
            for t in next_page:
                next_page = t
        if prev_len == 0:
            prev_page = first
        else:
            for t in prev_page:
                prev_page = t
        if first.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if marker == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def endpoint_add(self, values):
        if hasattr(api.TENANT, 'uid_to_id'):
            values.tenant_id = api.TENANT.uid_to_id(values.tenant_id)

        endpoints = models.Endpoints()
        endpoints.update(values)
        endpoints.save()

        if hasattr(api.TENANT, 'id_to_uid'):
            endpoints.tenant_id = api.TENANT.id_to_uid(endpoints.tenant_id)

        return endpoints

    def endpoint_get(self, id, session=None):
        if not session:
            session = get_session()

        result = session.query(models.Endpoints).\
            filter_by(id=id).first()

        if hasattr(api.TENANT, 'id_to_uid'):
            if result:
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return result

    @staticmethod
    def endpoint_get_by_ids(endpoint_template_id, tenant_id,
            session=None):
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        result = session.query(models.Endpoints).\
            filter_by(endpoint_template_id=endpoint_template_id).\
            filter_by(tenant_id=tenant_id).first()

        if hasattr(api.TENANT, 'id_to_uid'):
            if result:
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return result

    @staticmethod
    def endpoint_get_all(session=None):
        if not session:
            session = get_session()

        results = session.query(models.Endpoints).all()

        for result in results:
            if hasattr(api.TENANT, 'id_to_uid'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return results

    def endpoint_get_by_tenant(self, tenant_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        result = session.query(models.Endpoints).\
                        filter_by(tenant_id=tenant_id).first()

        if hasattr(api.TENANT, 'id_to_uid'):
            if result:
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return result

    def endpoint_get_by_endpoint_template(
        self, endpoint_template_id, session=None):
        if not session:
            session = get_session()

        result = session.query(models.Endpoints).\
            filter_by(endpoint_template_id=endpoint_template_id).all()

        return result

    def endpoint_delete(self, id, session=None):
        if not session:
            session = get_session()

        with session.begin():
            endpoints = self.endpoint_get(id, session)
            if endpoints:
                session.delete(endpoints)


def get():
    return EndpointTemplateAPI()
