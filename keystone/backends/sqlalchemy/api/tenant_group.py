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
from keystone.backends.api import BaseTenantGroupAPI

class TenantGroupAPI(BaseTenantGroupAPI):
    def create(self, values):
        group_ref = models.Group()
        group_ref.update(values)
        group_ref.save()
        return group_ref
    
    
    def is_empty(self, id, session=None):
        if not session:
            session = get_session()
        a_user = session.query(models.UserGroupAssociation).filter_by(
            group_id=id).first()
        if a_user != None:
            return False
        return True
    
    
    def get(self, id, tenant, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Group).filter_by(id=id, \
                tenant_id=tenant).first()
    
        return result
    
    
    def get_page(self, tenantId, marker, limit, session=None):
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
    
    
    def get_page_markers(self, tenantId, marker, limit, session=None):
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
    
    
    def update(self, id, tenant_id, values, session=None):
        if not session:
            session = get_session()
        with session.begin():
            tenant_ref = self.get(id, tenant_id, session)
            tenant_ref.update(values)
            tenant_ref.save(session=session)
    
    
    def delete(self, id, tenant_id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            tenantgroup_ref = self.get(id, tenant_id, session)
            session.delete(tenantgroup_ref)

def get():
    return TenantGroupAPI()