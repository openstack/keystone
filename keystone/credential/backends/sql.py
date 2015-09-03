# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import sql
from keystone import credential
from keystone import exception


class CredentialModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'credential'
    attributes = ['id', 'user_id', 'project_id', 'blob', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    user_id = sql.Column(sql.String(64),
                         nullable=False)
    project_id = sql.Column(sql.String(64))
    blob = sql.Column(sql.JsonBlob(), nullable=False)
    type = sql.Column(sql.String(255), nullable=False)
    extra = sql.Column(sql.JsonBlob())


class Credential(credential.CredentialDriverV8):

    # credential crud

    @sql.handle_conflicts(conflict_type='credential')
    def create_credential(self, credential_id, credential):
        session = sql.get_session()
        with session.begin():
            ref = CredentialModel.from_dict(credential)
            session.add(ref)
        return ref.to_dict()

    @sql.truncated
    def list_credentials(self, hints):
        session = sql.get_session()
        credentials = session.query(CredentialModel)
        credentials = sql.filter_limit_query(CredentialModel,
                                             credentials, hints)
        return [s.to_dict() for s in credentials]

    def list_credentials_for_user(self, user_id):
        session = sql.get_session()
        query = session.query(CredentialModel)
        refs = query.filter_by(user_id=user_id).all()
        return [ref.to_dict() for ref in refs]

    def _get_credential(self, session, credential_id):
        ref = session.query(CredentialModel).get(credential_id)
        if ref is None:
            raise exception.CredentialNotFound(credential_id=credential_id)
        return ref

    def get_credential(self, credential_id):
        session = sql.get_session()
        return self._get_credential(session, credential_id).to_dict()

    @sql.handle_conflicts(conflict_type='credential')
    def update_credential(self, credential_id, credential):
        session = sql.get_session()
        with session.begin():
            ref = self._get_credential(session, credential_id)
            old_dict = ref.to_dict()
            for k in credential:
                old_dict[k] = credential[k]
            new_credential = CredentialModel.from_dict(old_dict)
            for attr in CredentialModel.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_credential, attr))
            ref.extra = new_credential.extra
        return ref.to_dict()

    def delete_credential(self, credential_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_credential(session, credential_id)
            session.delete(ref)

    def delete_credentials_for_project(self, project_id):
        session = sql.get_session()

        with session.begin():
            query = session.query(CredentialModel)
            query = query.filter_by(project_id=project_id)
            query.delete()

    def delete_credentials_for_user(self, user_id):
        session = sql.get_session()

        with session.begin():
            query = session.query(CredentialModel)
            query = query.filter_by(user_id=user_id)
            query.delete()
