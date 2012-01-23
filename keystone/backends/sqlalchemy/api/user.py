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

import uuid

import keystone.backends.backendutils as utils
from keystone.backends.sqlalchemy import get_session, models, aliased, \
    joinedload
from keystone.backends import api
from keystone.models import User


# pylint: disable=E1103,W0221,W0223
class UserAPI(api.BaseUserAPI):
    def __init__(self, *args, **kw):
        super(UserAPI, self).__init__(*args, **kw)

    @staticmethod
    def transpose(ref):
        """ Transposes field names from domain to sql model"""
        if 'id' in ref:
            ref['uid'] = ref.pop('id')

        if hasattr(api.TENANT, 'uid_to_id'):
            if 'tenant_id' in ref:
                ref['tenant_id'] = api.TENANT.uid_to_id(ref['tenant_id'])
            elif hasattr(ref, 'tenant_id'):
                ref.tenant_id = api.TENANT.uid_to_id(ref.tenant_id)

    @staticmethod
    def to_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        if ref:
            if hasattr(api.TENANT, 'uid_to_id'):
                if 'tenant_id' in ref:
                    ref['tenant_id'] = api.TENANT.id_to_uid(ref['tenant_id'])
                elif hasattr(ref, 'tenant_id'):
                    ref.tenant_id = api.TENANT.id_to_uid(ref.tenant_id)

            return User(id=ref.uid, password=ref.password, name=ref.name,
                tenant_id=ref.tenant_id, email=ref.email,
                enabled=bool(ref.enabled))

    @staticmethod
    def to_model_list(refs):
        return [UserAPI.to_model(ref) for ref in refs]

    # pylint: disable=W0221
    def get_all(self, session=None):
        if not session:
            session = get_session()

        results = session.query(models.User)

        return UserAPI.to_model_list(results)

    def create(self, values):
        data = values.copy()
        UserAPI.transpose(data)
        utils.set_hashed_password(data)
        if 'uid' not in data or data['uid'] is None:
            data['uid'] = uuid.uuid4().hex
        user_ref = models.User()
        user_ref.update(data)
        user_ref.save()
        return UserAPI.to_model(user_ref)

    def get(self, id, session=None):
        if not session:
            session = get_session()

        id = str(id) if id is not None else None
        result = session.query(models.User).filter_by(uid=id).first()

        return UserAPI.to_model(result)

    @staticmethod
    def _get_by_id(id, session=None):
        """Only for use by the sql backends

        - Queries by PK ID
        - Doesn't wrap result with domain layer models
        """
        if not session:
            session = get_session()

        id = str(id) if id is not None else None
        return session.query(models.User).filter_by(id=id).first()

    @staticmethod
    def id_to_uid(id, session=None):
        session = session or get_session()
        id = str(id) if id is not None else None
        user = session.query(models.User).filter_by(id=id).first()
        return user.uid if user else None

    @staticmethod
    def uid_to_id(uid, session=None):
        session = session or get_session()
        uid = str(uid) if uid is not None else None
        user = session.query(models.User).filter_by(uid=uid).first()
        return user.id if user else None

    def get_by_name(self, name, session=None):
        if not session:
            session = get_session()

        result = session.query(models.User).filter_by(name=name).first()

        return UserAPI.to_model(result)

    def get_by_email(self, email, session=None):
        if not session:
            session = get_session()

        result = session.query(models.User).filter_by(email=email).first()

        return UserAPI.to_model(result)

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            results = session.query(models.User).filter("id>:marker").params(
                    marker='%s' % marker).order_by(
                    models.User.id.desc()).limit(int(limit)).all()
        else:
            results = session.query(models.User).order_by(
                                models.User.id.desc()).limit(int(limit)).all()

        return UserAPI.to_model_list(results)

    # pylint: disable=R0912
    def get_page_markers(self, marker, limit, session=None):
        if not session:
            session = get_session()

        first = session.query(models.User).order_by(
                            models.User.id).first()
        last = session.query(models.User).order_by(
                            models.User.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = session.query(models.User).filter("id > :marker").params(
                        marker='%s' % marker).order_by(
                        models.User.id).limit(int(limit)).all()
        prev_page = session.query(models.User).filter("id < :marker").params(
                        marker='%s' % marker).order_by(
                        models.User.id.desc()).limit(int(limit)).all()
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

    def user_roles_by_tenant(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        results = session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id, tenant_id=tenant_id).\
            options(joinedload('roles'))

        for result in results:
            if hasattr(api.USER, 'id_to_uid'):
                result.user_id = api.USER.id_to_uid(result.user_id)
            if hasattr(api.TENANT, 'id_to_uid'):
                result.tenant_id = api.TENANT.id_to_uid(result.tenant_id)

        return results

    def update(self, id, values, session=None):
        if not session:
            session = get_session()

        UserAPI.transpose(values)

        with session.begin():
            user_ref = session.query(models.User).filter_by(uid=id).first()
            utils.set_hashed_password(values)
            user_ref.update(values)
            user_ref.save(session=session)

    def delete(self, id, session=None):
        if not session:
            session = get_session()

        with session.begin():
            user_ref = session.query(models.User).filter_by(uid=id).first()
            session.delete(user_ref)

    def get_by_tenant(self, id, tenant_id, session=None):
        if not session:
            session = get_session()

        uid = id

        if hasattr(api.USER, 'uid_to_id'):
            id = api.USER.uid_to_id(uid)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        # Most common use case: user lives in tenant
        user = session.query(models.User).\
                        filter_by(id=id, tenant_id=tenant_id).first()
        if user:
            return UserAPI.to_model(user)

        # Find user through grants to this tenant
        result = session.query(models.UserRoleAssociation).\
                         filter_by(tenant_id=tenant_id, user_id=id).first()
        if result:
            return self.get(uid, session)
        else:
            return None

    def users_get_by_tenant(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()

        if hasattr(api.USER, 'uid_to_id'):
            user_id = api.USER.uid_to_id(user_id)
        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        results = session.query(models.User).filter_by(id=user_id,
                                                      tenant_id=tenant_id)
        return UserAPI.to_model_list(results)

    def user_role_add(self, values):
        if hasattr(api.USER, 'uid_to_id'):
            values['user_id'] = api.USER.uid_to_id(values['user_id'])
        if hasattr(api.TENANT, 'uid_to_id'):
            values['tenant_id'] = api.TENANT.uid_to_id(values['tenant_id'])

        user_rolegrant = models.UserRoleAssociation()
        user_rolegrant.update(values)
        user_rolegrant.save()

        if hasattr(api.USER, 'id_to_uid'):
            user_rolegrant.user_id = api.USER.id_to_uid(user_rolegrant.user_id)
        if hasattr(api.TENANT, 'id_to_uid'):
            user_rolegrant.tenant_id = api.TENANT.id_to_uid(
                user_rolegrant.tenant_id)

        return user_rolegrant

    def users_get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        user = aliased(models.User)
        if marker:
            results = session.query(user).\
                                filter("id>=:marker").params(
                                marker='%s' % marker).order_by(
                                "id").limit(int(limit)).all()
        else:
            results = session.query(user).\
                                order_by("id").limit(int(limit)).all()

        return UserAPI.to_model_list(results)

    # pylint: disable=R0912
    def users_get_page_markers(self, marker, limit, session=None):
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
        next_page = session.query(user).\
                        filter("id > :marker").params(
                        marker='%s' % marker).order_by(user.id).\
                        limit(int(limit)).all()
        prev_page = session.query(user).\
                        filter("id < :marker").params(
                        marker='%s' % marker).order_by(
                        user.id.desc()).limit(int(limit)).all()
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

    def users_get_by_tenant_get_page(self, tenant_id, role_id, marker, limit,
            session=None):
        # This is broken.  If a user has more than one role per project
        # shit hits the fan because we're limiting the wrong model.
        # Also the user lookup is nasty and potentially injectiable.
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        user = aliased(models.UserRoleAssociation)
        query = session.query(user).\
            filter("tenant_id = :tenant_id").\
            params(tenant_id='%s' % tenant_id)

        if role_id:
            query = query.filter(
                user.role_id == role_id)

        if marker:
            rv = query.filter("id>=:marker").\
                         params(marker='%s' % marker).\
                         order_by("id").\
                         limit(int(limit)).\
                         all()
        else:
            rv = query.\
                         order_by("id").\
                         limit(int(limit)).\
                         all()

        user_ids = set([str(assoc.user_id) for assoc in rv])
        users = session.query(models.User).\
                      filter("id in ('%s')" % "','".join(user_ids)).\
                      all()

        for usr in users:
            usr.tenant_roles = set()
            for role in usr.roles:
                if role.tenant_id == tenant_id:
                    usr.tenant_roles.add(role.role_id)

        return UserAPI.to_model_list(users)

    # pylint: disable=R0912
    def users_get_by_tenant_get_page_markers(self, tenant_id, \
            role_id, marker, limit, session=None):
        if not session:
            session = get_session()

        if hasattr(api.TENANT, 'uid_to_id'):
            tenant_id = api.TENANT.uid_to_id(tenant_id)

        user = aliased(models.UserRoleAssociation)
        query = session.query(user).\
                        filter(user.tenant_id == tenant_id)
        if role_id:
            query = query.filter(
                user.role_id == role_id)
        first = query.\
            order_by(user.id).first()
        last = query.\
            order_by(user.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = query.\
            filter("id > :marker").params(
            marker='%s' % marker).order_by(user.id).\
            limit(int(limit)).all()
        prev_page = query.\
            filter("id < :marker").params(
            marker='%s' % marker).order_by(
            user.id.desc()).limit(int(limit)).all()
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

    def check_password(self, user_id, password):
        user = self.get(user_id)
        return utils.check_password(password, user.password)
    # pylint: enable=W0221


def get():
    return UserAPI()
