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
from keystone.backends import api
from keystone.models import Role, UserRoleAssociation


# pylint: disable=E1103,W0221
class RoleAPI(api.BaseRoleAPI):
    def __init__(self, *args, **kw):
        super(RoleAPI, self).__init__(*args, **kw)

    @staticmethod
    def transpose(values):
        """ Handles transposing field names from Keystone model to
        sqlalchemy mode

        Differences:
            desc <-> description
        """
        if 'description' in values:
            values['desc'] = values.pop('description')

    @staticmethod
    def to_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        if ref:
            return Role(id=str(ref.id), name=ref.name, description=ref.desc,
                service_id=ref.service_id)

    @staticmethod
    def to_model_list(refs):
        return [RoleAPI.to_model(ref) for ref in refs]

    @staticmethod
    def to_ura_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        if ref:
            return UserRoleAssociation(id=ref.id,
                                       role_id=ref.role_id,
                                       user_id=ref.user_id,
                                       tenant_id=ref.tenant_id)

    @staticmethod
    def to_ura_model_list(refs):
        return [RoleAPI.to_ura_model(ref) for ref in refs]

    # pylint: disable=W0221
    def create(self, values):
        data = values.copy()
        RoleAPI.transpose(data)
        role = models.Role()
        role.update(data)
        role.save()
        return RoleAPI.to_model(role)

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            role = session.query(models.Role).filter_by(id=id).first()
            session.delete(role)

    @staticmethod
    def update(id, values, session=None):
        if not session:
            session = get_session()

        RoleAPI.transpose(values)

        with session.begin():
            ref = session.query(models.Role).filter_by(id=id).first()
            ref.update(values)
            ref.save(session=session)

    def get(self, id, session=None):
        if not session:
            session = get_session()
        return RoleAPI.to_model(
            session.query(models.Role).filter_by(id=id).first())

    def get_by_name(self, name, session=None):
        if not session:
            session = get_session()
        return RoleAPI.to_model(
            session.query(models.Role).filter_by(name=name).first())

    def get_by_service(self, service_id, session=None):
        if not session:
            session = get_session()
        results = session.query(models.Role).\
            filter_by(service_id=service_id).all()
        return RoleAPI.to_model_list(results)

    def get_all(self, session=None):
        if not session:
            session = get_session()
        return RoleAPI.to_model_list(session.query(models.Role).all())

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            results = session.query(models.Role).filter("id>:marker").params(
                    marker='%s' % marker).order_by(
                    models.Role.id.desc()).limit(int(limit)).all()
        else:
            results = session.query(models.Role).order_by(
                                models.Role.id.desc()).limit(int(limit)).all()
        return RoleAPI.to_model_list(results)

    # pylint: disable=R0912
    def get_page_markers(self, marker, limit, session=None):
        if not session:
            session = get_session()
        first = session.query(models.Role).order_by(
                            models.Role.id).first()
        last = session.query(models.Role).order_by(
                            models.Role.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = session.query(models.Role).filter("id > :marker").params(
                marker='%s' % marker).order_by(
                models.Role.id).limit(int(limit)).all()
        prev_page = session.query(models.Role).filter("id < :marker").params(
                marker='%s' % marker).order_by(
                models.Role.id.desc()).limit(int(limit)).all()
        if not next_page:
            next_page = last
        else:
            next_page = next_page[-1]
        if not prev_page:
            prev_page = first
        else:
            prev_page = prev_page[-1]
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def get_by_service_get_page(self, service_id, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            results = session.query(models.Role).filter("id>:marker").params(
                    marker='%s' % marker).filter_by(
                    service_id=service_id).order_by(
                    models.Role.id.desc()).limit(int(limit)).all()
        else:
            results = session.query(models.Role).filter_by(
                    service_id=service_id).order_by(
                                models.Role.id.desc()).limit(int(limit)).all()
        return RoleAPI.to_model_list(results)

    # pylint: disable=R0912
    def get_by_service_get_page_markers(self,
            service_id, marker, limit, session=None):
        if not session:
            session = get_session()
        first = session.query(models.Role).filter_by(
                    service_id=service_id).order_by(
                    models.Role.id).first()
        last = session.query(models.Role).filter_by(
                    service_id=service_id).order_by(
                    models.Role.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = session.query(models.Role).filter("id > :marker").params(
                        marker='%s' % marker).filter_by(
                        service_id=service_id).order_by(
                        models.Role.id).limit(int(limit)).all()
        prev_page = session.query(models.Role).filter("id < :marker").params(
                        marker='%s' % marker).filter_by(
                        service_id=service_id).order_by(
                        models.Role.id.desc()).limit(int(limit)).all()
        if not next_page:
            next_page = last
        else:
            next_page = next_page[-1]
        if not prev_page:
            prev_page = first
        else:
            prev_page = prev_page[-1]
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    #
    # Role Grants start here
    #
    def rolegrant_get(self, id, session=None):
        if not session:
            session = get_session()

        result = session.query(models.UserRoleAssociation).filter_by(id=id).\
            first()

        if result:
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model(result)

    def rolegrant_delete(self, id, session=None):
        if not session:
            session = get_session()

        with session.begin():
            rolegrant = session.query(models.UserRoleAssociation).\
                    filter_by(id=id).first()
            session.delete(rolegrant)

    # pylint: disable=R0912
    def rolegrant_get_page_markers(self, user_id, tenant_id, marker,
            limit, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        query = session.query(models.UserRoleAssociation).filter_by(
                user_id=user_id)
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        else:
            query = query.filter("tenant_id is null")
        first = query.order_by(models.UserRoleAssociation.id).first()
        last = query.order_by(models.UserRoleAssociation.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = query.\
            filter("id > :marker").\
            params(marker='%s' % marker).\
            order_by(models.UserRoleAssociation.id).\
            limit(int(limit)).\
            all()
        prev_page = query.\
            filter("id < :marker").\
            params(marker='%s' % marker).\
            order_by(models.UserRoleAssociation.id.desc()).\
            limit(int(limit)).\
            all()

        if not next_page:
            next_page = last
        else:
            next_page = next_page[-1]
        if not prev_page:
            prev_page = first
        else:
            prev_page = prev_page[-1]
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def rolegrant_get_page(self, marker, limit, user_id, tenant_id,
                           session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        query = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id)
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        else:
            query = query.filter("tenant_id is null")
        if marker:
            results = query.filter("id>:marker").params(
                    marker='%s' % marker).order_by(
                    models.UserRoleAssociation.id.desc()).limit(
                    int(limit)).all()
        else:
            results = query.order_by(
                    models.UserRoleAssociation.id.desc()).limit(
                    int(limit)).all()

        for result in results:
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model_list(results)

    def list_global_roles_for_user(self, user_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)

        results = session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id).filter("tenant_id is null").all()

        for result in results:
            result['role_id'] = str(result['role_id'])
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model_list(results)

    def list_tenant_roles_for_user(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        results = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).all()

        for result in results:
            result['role_id'] = str(result['role_id'])
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model_list(results)

    def rolegrant_list_by_role(self, role_id, session=None):
        """ Get a list of all (global and tenant) grants for this role """
        if not session:
            session = get_session()

        results = session.query(models.UserRoleAssociation).\
            filter_by(role_id=role_id).all()

        for result in results:
            result['role_id'] = str(result['role_id'])
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model_list(results)

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        if tenant_id is None:
            result = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter("tenant_id is null").\
                filter_by(role_id=role_id).first()
        else:
            result = session.query(models.UserRoleAssociation).\
                filter_by(user_id=user_id).filter_by(tenant_id=tenant_id).\
                filter_by(role_id=role_id).first()

        if result:
            result['role_id'] = str(result['role_id'])
            if hasattr(api.USER, 'uid_to_id'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'uid_to_id'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return RoleAPI.to_ura_model(result)


def get():
    return RoleAPI()
