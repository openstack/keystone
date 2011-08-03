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
from keystone.backends.api import BaseTokenAPI


class TokenAPI(BaseTokenAPI):
    def create(self, values):
        token_ref = models.Token()
        token_ref.update(values)
        token_ref.save()
        return token_ref

    def get(self, id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Token).filter_by(id=id).first()
        return result

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            token_ref = self.get(id, session)
            session.delete(token_ref)

    def get_for_user(self, user_id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Token).filter_by(
            user_id=user_id, tenant_id=None).order_by("expires desc").first()
        return result

    def get_for_user_by_tenant(self, user_id, tenant_id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Token).\
            filter_by(user_id=user_id, tenant_id=tenant_id).\
            order_by("expires desc").\
            first()
        return result

    def get_all(self, session=None):
        if not session:
            session = get_session()
        return session.query(models.Token).all()


def get():
    return TokenAPI()
