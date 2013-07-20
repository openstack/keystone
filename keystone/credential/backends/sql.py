# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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
from keystone.common.sql import migration
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


class Credential(sql.Base, credential.Driver):
    # Internal interface to manage the database
    def db_sync(self, version=None):
        migration.db_sync(version=version)

    # credential crud

    @sql.handle_conflicts(type='credential')
    def create_credential(self, credential_id, credential):
        session = self.get_session()
        with session.begin():
            ref = CredentialModel.from_dict(credential)
            session.add(ref)
            session.flush()
        return ref.to_dict()

    def list_credentials(self, **filters):
        session = self.get_session()
        query = session.query(CredentialModel)
        if 'user_id' in filters:
            query = query.filter_by(user_id=filters.get('user_id'))
        refs = query.all()
        return [ref.to_dict() for ref in refs]

    def _get_credential(self, session, credential_id):
        ref = session.query(CredentialModel).get(credential_id)
        if ref is None:
            raise exception.CredentialNotFound(credential_id=credential_id)
        return ref

    def get_credential(self, credential_id):
        session = self.get_session()
        return self._get_credential(session, credential_id).to_dict()

    @sql.handle_conflicts(type='credential')
    def update_credential(self, credential_id, credential):
        session = self.get_session()
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
            session.flush()
        return ref.to_dict()

    def delete_credential(self, credential_id):
        session = self.get_session()

        with session.begin():
            ref = self._get_credential(session, credential_id)
            session.delete(ref)
            session.flush()
