# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Not Yet PEP8 standardized


from session import get_session
from sqlalchemy.orm import joinedload
import models


def tenant_create(values):
    tenant_ref = models.Tenant()
    tenant_ref.update(values)
    tenant_ref.save()
    return tenant_ref


def tenant_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Tenant).filter_by(id=id).first()
    return result


def tenant_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Tenant).all()


def tenant_is_empty(id, session=None):
    if not session:
        session = get_session()
    a_user = session.query(models.UserTenantAssociation).filter_by(
        tenant_id=id).first()
    if a_user != None:
        return False
    a_group = session.query(models.Group).filter_by(tenant_id=id).first()
    if a_group != None:
        return False
    return True


def tenant_update(id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_get(id, session)
        tenant_ref.update(values)
        tenant_ref.save(session=session)


def tenant_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        tenant_ref = tenant_get(id, session)
        session.delete(tenant_ref)


def user_create(values):
    user_ref = models.User()
    user_ref.update(values)
    user_ref.save()
    return user_ref


def user_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.User).options(joinedload('groups')).options(
        joinedload('tenants')).filter_by(id=id).first()
    return result


def group_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Group).filter_by(id=id).first()
    return result


def token_create(values):
    token_ref = models.Token()
    token_ref.update(values)
    token_ref.save()
    return token_ref


def token_get(id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(token_id=id).first()
    return result


def token_delete(id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        token_ref = token_get(id, session)
        session.delete(token_ref)


def token_for_user(user_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(
        user_id=user_id).order_by("expires desc").first()
    return result
