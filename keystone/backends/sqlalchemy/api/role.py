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
from keystone.backends.api import BaseRoleAPI


class RoleAPI(BaseRoleAPI):
    # pylint: disable=W0221
    def create(self, values):
        role = models.Role()
        role.update(values)
        role.save()
        return role

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            role = self.get(id, session)
            session.delete(role)

    def get(self, id, session=None):
        if not session:
            session = get_session()
        return session.query(models.Role).filter_by(id=id).first()

    def get_by_name(self, name, session=None):
        if not session:
            session = get_session()
        return session.query(models.Role).filter_by(name=name).first()

    def get_by_service(self, service_id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Role).\
            filter_by(service_id=service_id).all()
        return result

    def get_all(self, session=None):
        if not session:
            session = get_session()
        return session.query(models.Role).all()

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            return session.query(models.Role).filter("id>:marker").params(\
                    marker='%s' % marker).order_by(\
                    models.Role.id.desc()).limit(limit).all()
        else:
            return session.query(models.Role).order_by(\
                                models.Role.id.desc()).limit(limit).all()

    def ref_get_page(self, marker, limit, user_id, tenant_id, session=None):
        if not session:
            session = get_session()
        query = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id)
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        else:
            query = query.filter("tenant_id is null")
        if marker:
            return query.filter("id>:marker").params(\
                    marker='%s' % marker).order_by(\
                    models.UserRoleAssociation.id.desc()).limit(limit).all()
        else:
            return query.order_by(\
                    models.UserRoleAssociation.id.desc()).limit(limit).all()

    def ref_get_all_global_roles(self, user_id, session=None):
        if not session:
            session = get_session()
        return session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id).filter("tenant_id is null").all()

    def ref_get_all_tenant_roles(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()
        return session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).all()

    def ref_get(self, id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.UserRoleAssociation).filter_by(id=id).\
            first()
        return result

    def ref_delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            role_ref = self.ref_get(id, session)
            session.delete(role_ref)

    def get_page_markers(self, marker, limit, session=None):
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
        next_page = session.query(models.Role).filter("id > :marker").params(\
                        marker='%s' % marker).order_by(\
                        models.Role.id).limit(limit).all()
        prev_page = session.query(models.Role).filter("id < :marker").params(\
                        marker='%s' % marker).order_by(\
                        models.Role.id.desc()).limit(int(limit)).all()
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

    def ref_get_page_markers(self, user_id, tenant_id, marker,
        limit, session=None):
        if not session:
            session = get_session()
        query = session.query(models.UserRoleAssociation).filter_by(\
                                            user_id=user_id)
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        else:
            query = query.filter("tenant_id is null")
        first = query.order_by(\
                            models.UserRoleAssociation.id).first()
        last = query.order_by(\
                            models.UserRoleAssociation.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = query.\
            filter("id > :marker").\
            params(marker='%s' % marker).\
            order_by(models.UserRoleAssociation.id).\
            limit(limit).\
            all()
        prev_page = query.\
            filter("id < :marker").\
            params(marker='%s' % marker).\
            order_by(models.UserRoleAssociation.id.desc()).\
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

    def ref_get_by_role(self, role_id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.UserRoleAssociation).\
            filter_by(role_id=role_id).all()
        return result

    def ref_get_by_user(self, user_id, role_id, tenant_id, session=None):
        if not session:
            session = get_session()
        if tenant_id is None:
            result = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter("tenant_id is null").\
                filter_by(role_id=role_id).first()
        else:
            result = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).\
                filter_by(role_id=role_id).first()
        return result


def get():
    return RoleAPI()
