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
from keystone.backends.api import BaseTenantAPI


class TenantAPI(BaseTenantAPI):
    # pylint: disable=W0221
    def create(self, values):
        tenant_ref = models.Tenant()
        tenant_ref.update(values)
        tenant_ref.save()
        return tenant_ref

    def get(self, id, session=None):
        session = session or get_session()
        return session.query(models.Tenant).filter_by(id=id).first()

    def get_by_name(self, name, session=None):
        session = session or get_session()
        return session.query(models.Tenant).filter_by(name=name).first()

    def get_all(self, session=None):
        if not session:
            session = get_session()
        return session.query(models.Tenant).all()

    def tenants_for_user_get_page(self, user, marker, limit, session=None):
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
            return q3.order_by(tenant.id.desc()).limit(limit).all()

    def tenants_for_user_get_page_markers(self, user, marker, limit,
            session=None):
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
        next_page = q3.filter(tenant.id > marker).order_by(\
                        tenant.id).limit(limit).all()
        prev_page = q3.filter(tenant.id > marker).order_by(\
                        tenant.id.desc()).limit(int(limit)).all()
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
            return session.query(models.Tenant).filter("id>:marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Tenant.id.desc()).limit(limit).all()
        else:
            return session.query(models.Tenant).order_by(\
                                models.Tenant.id.desc()).limit(limit).all()

    def get_page_markers(self, marker, limit, session=None):
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
        next_page = session.query(models.Tenant).\
            filter("id > :marker").\
            params(marker='%s' % marker).\
            order_by(models.Tenant.id).\
            limit(limit).\
            all()
        prev_page = session.query(models.Tenant).\
            filter("id < :marker").\
            params(marker='%s' % marker).\
            order_by(models.Tenant.id.desc()).\
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

    def is_empty(self, id, session=None):
        if not session:
            session = get_session()
        a_user = session.query(models.UserRoleAssociation).filter_by(\
            tenant_id=id).first()
        if a_user != None:
            return False
        a_user = session.query(models.User).filter_by(tenant_id=id).first()
        if a_user != None:
            return False
        return True

    def update(self, id, values, session=None):
        if not session:
            session = get_session()
        with session.begin():
            tenant_ref = self.get(id, session)
            tenant_ref.update(values)
            tenant_ref.save(session=session)

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            tenant_ref = self.get(id, session)
            session.delete(tenant_ref)

    def get_all_endpoints(self, tenant_id, session=None):
        if not session:
            session = get_session()
        endpointTemplates = aliased(models.EndpointTemplates)
        q = session.query(endpointTemplates).\
            filter(endpointTemplates.is_global == 1)
        if tenant_id:
            ep = aliased(models.Endpoints)
            q1 = session.query(endpointTemplates).join((ep,
                ep.endpoint_template_id == endpointTemplates.id)).\
                filter(ep.tenant_id == tenant_id)
            q = q.union(q1)
        return q.all()

    def get_role_assignments(self, tenant_id, session=None):
        if not session:
            session = get_session()
        return session.query(models.UserRoleAssociation).\
            filter_by(tenant_id=tenant_id)


def get():
    return TenantAPI()
