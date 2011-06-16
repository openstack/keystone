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

from keystone.db.sqlalchemy import get_session, models

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
        user_id=user_id, tenant_id=None).order_by("expires desc").first()
    return result


def token_for_user_tenant(user_id, tenant_id, session=None):
    if not session:
        session = get_session()
    result = session.query(models.Token).filter_by(
        user_id=user_id, tenant_id=tenant_id).order_by("expires desc").first()
    return result


def token_get_all(session=None):
    if not session:
        session = get_session()
    return session.query(models.Token).all()
