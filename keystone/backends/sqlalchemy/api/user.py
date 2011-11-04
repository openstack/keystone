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

import keystone.backends.backendutils as utils
from keystone.backends.sqlalchemy import get_session, models, aliased, \
    joinedload
from keystone.backends.api import BaseUserAPI


class UserAPI(BaseUserAPI):
    # pylint: disable=W0221
    def get_all(self, session=None):
        if not session:
            session = get_session()
        return session.query(models.User)

    def create(self, values):
        user_ref = models.User()
        utils.set_hashed_password(values)
        user_ref.update(values)
        user_ref.save()
        return user_ref

    def get(self, id, session=None):
        if not session:
            session = get_session()
        user = session.query(models.User).filter_by(id=id).first()

        return user or self.get_by_name(id, session)

    def get_by_name(self, name, session=None):
        if not session:
            session = get_session()
        return session.query(models.User).filter_by(name=name).first()

    def get_by_email(self, email, session=None):
        if not session:
            session = get_session()
        return session.query(models.User).filter_by(email=email).first()

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()

        if marker:
            return session.query(models.User).filter("id>:marker").params(\
                    marker='%s' % marker).order_by(\
                    models.User.id.desc()).limit(limit).all()
        else:
            return session.query(models.User).order_by(\
                                models.User.id.desc()).limit(limit).all()

    def get_page_markers(self, marker, limit, session=None):
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
        next_page = session.query(models.User).filter("id > :marker").params(\
                        marker='%s' % marker).order_by(\
                        models.User.id).limit(limit).all()
        prev_page = session.query(models.User).filter("id < :marker").params(\
                        marker='%s' % marker).order_by(\
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
        result = session.query(models.UserRoleAssociation).\
            filter_by(user_id=user_id, tenant_id=tenant_id).\
            options(joinedload('roles'))
        return result

    def update(self, id, values, session=None):
        if not session:
            session = get_session()
        with session.begin():
            user_ref = self.get(id, session)
            utils.set_hashed_password(values)
            user_ref.update(values)
            user_ref.save(session=session)

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            user_ref = self.get(id, session)
            session.delete(user_ref)

    def get_by_tenant(self, id, tenant_id, session=None):
        if not session:
            session = get_session()
        # Most common use case: user lives in tenant
        user = session.query(models.User).\
                        filter_by(id=id, tenant_id=tenant_id).first()
        if user:
            return user

        # Find user through grants to this tenant
        result = session.query(models.UserRoleAssociation).\
                         filter_by(tenant_id=tenant_id, user_id=id).first()
        if result:
            return self.get(id, session)
        else:
            return None

    def delete_tenant_user(self, id, tenant_id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            users_tenant_ref = self.users_get_by_tenant(id, tenant_id, session)
            if users_tenant_ref is not None:
                for user_tenant_ref in users_tenant_ref:
                    session.delete(user_tenant_ref)

    def users_get_by_tenant(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.User).filter_by(id=user_id,
                                                      tenant_id=tenant_id)
        return result

    def user_role_add(self, values):
        user_role_ref = models.UserRoleAssociation()
        user_role_ref.update(values)
        user_role_ref.save()
        return user_role_ref

    def user_get_update(self, id, session=None):
        if not session:
            session = get_session()
        return session.query(models.User).filter_by(id=id).first()

    def users_get_page(self, marker, limit, session=None):
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

    def users_get_page_markers(self, marker, limit, \
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
        next_page = session.query(user).\
                        filter("id > :marker").params(\
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
                         limit(limit).\
                         all()
        else:
            rv = query.\
                         order_by("id").\
                         limit(limit).\
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
        return users

    def users_get_by_tenant_get_page_markers(self, tenant_id, \
            role_id, marker, limit, session=None):
        if not session:
            session = get_session()
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
            filter("id > :marker").params(\
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

    def check_password(self, user, password):
        return utils.check_password(password, user.password)
    # pylint: enable=W0221


def get():
    return UserAPI()
