# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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
from keystone.models import Credentials
from keystone.logic.types import fault


# pylint: disable=E1103,W0221
class CredentialsAPI(api.BaseCredentialsAPI):
    def __init__(self, *args, **kw):
        super(CredentialsAPI, self).__init__(*args, **kw)

    @staticmethod
    def transpose(ref):
        """ Transposes field names from domain to sql model"""
        if hasattr(api.TENANT, 'uid_to_id'):
            if 'tenant_id' in ref:
                ref['tenant_id'] = api.TENANT.uid_to_id(ref['tenant_id'])
            elif hasattr(ref, 'tenant_id'):
                ref.tenant_id = api.TENANT.uid_to_id(ref.tenant_id)

        if hasattr(api.USER, 'uid_to_id'):
            if 'user_id' in ref:
                ref['user_id'] = api.USER.uid_to_id(ref['user_id'])
            elif hasattr(ref, 'tenant_id'):
                ref.user_id = api.USER.uid_to_id(ref.user_id)

    @staticmethod
    def to_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        if ref:
            if hasattr(api.TENANT, 'uid_to_id'):
                if 'tenant_id' in ref:
                    ref['tenant_id'] = api.TENANT.id_to_uid(ref['tenant_id'])
                elif hasattr(ref, 'tenant_id'):
                    ref.tenant_id = api.TENANT.id_to_uid(ref.tenant_id)

            if hasattr(api.USER, 'uid_to_id'):
                if 'user_id' in ref:
                    ref['user_id'] = api.USER.id_to_uid(ref['user_id'])
                elif hasattr(ref, 'user_id'):
                    ref.user_id = api.USER.id_to_uid(ref.user_id)

            return Credentials(id=ref.id, user_id=ref.user_id,
                tenant_id=ref.tenant_id, type=ref.type, key=ref.key,
                secret=ref.secret)

    @staticmethod
    def to_model_list(refs):
        return [CredentialsAPI.to_model(ref) for ref in refs]

    def create(self, values):
        data = values.copy()
        CredentialsAPI.transpose(data)

        if 'tenant_id' in values:
            if data['tenant_id'] is None and values['tenant_id'] is not None:
                raise fault.ItemNotFoundFault('Invalid tenant id: %s' % \
                                              values['tenant_id'])

        credentials_ref = models.Credentials()
        credentials_ref.update(data)
        credentials_ref.save()

        return CredentialsAPI.to_model(credentials_ref)

    @staticmethod
    def update(id, values, session=None):
        if not session:
            session = get_session()

        CredentialsAPI.transpose(values)

        with session.begin():
            ref = session.query(models.Credentials).filter_by(id=id).first()
            ref.update(values)
            ref.save(session=session)

    def get(self, id, session=None):
        result = self._get(id, session)

        return CredentialsAPI.to_model(result)

    @staticmethod
    def _get(id, session=None):
        if not session:
            session = get_session()

        return session.query(models.Credentials).filter_by(id=id).first()

    @staticmethod
    def get_all(session=None):
        if not session:
            session = get_session()

        results = session.query(models.Credentials).all()

        return CredentialsAPI.to_model_list(results)

    def get_by_access(self, access, session=None):
        if not session:
            session = get_session()

        result = session.query(models.Credentials).\
                         filter_by(type="EC2", key=access).first()

        return CredentialsAPI.to_model(result)

    def delete(self, id, session=None):
        if not session:
            session = get_session()

        with session.begin():
            group_ref = self._get(id, session)
            session.delete(group_ref)


def get():
    return CredentialsAPI()
