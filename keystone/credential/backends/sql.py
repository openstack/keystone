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

from oslo_db import api as oslo_db_api
from sqlalchemy.ext.hybrid import hybrid_property

from keystone.common import driver_hints
from keystone.common import sql
from keystone.credential.backends import base
from keystone import exception


class CredentialModel(sql.ModelBase, sql.ModelDictMixinWithExtras):
    __tablename__ = 'credential'
    attributes = [
        'id', 'user_id', 'project_id', 'encrypted_blob', 'type', 'key_hash'
    ]
    id = sql.Column(sql.String(64), primary_key=True)
    user_id = sql.Column(sql.String(64),
                         nullable=False)
    project_id = sql.Column(sql.String(64))
    _encrypted_blob = sql.Column('encrypted_blob', sql.Text(), nullable=True)
    type = sql.Column(sql.String(255), nullable=False)
    key_hash = sql.Column(sql.String(64), nullable=True)
    extra = sql.Column(sql.JsonBlob())

    @hybrid_property
    def encrypted_blob(self):
        return self._encrypted_blob

    @encrypted_blob.setter
    def encrypted_blob(self, encrypted_blob):
        # Make sure to hand over the encrypted credential as a string value
        # to the backend driver to avoid the sql drivers (esp. psycopg2)
        # treating this as binary data and e.g. hex-escape it.
        if isinstance(encrypted_blob, bytes):
            encrypted_blob = encrypted_blob.decode('utf-8')
        self._encrypted_blob = encrypted_blob


class Credential(base.CredentialDriverBase):

    # credential crud

    @sql.handle_conflicts(conflict_type='credential')
    def create_credential(self, credential_id, credential):
        with sql.session_for_write() as session:
            ref = CredentialModel.from_dict(credential)
            session.add(ref)
            return ref.to_dict()

    @driver_hints.truncated
    def list_credentials(self, hints):
        with sql.session_for_read() as session:
            credentials = session.query(CredentialModel)
            credentials = sql.filter_limit_query(CredentialModel,
                                                 credentials, hints)
            return [s.to_dict() for s in credentials]

    def list_credentials_for_user(self, user_id, type=None):
        with sql.session_for_read() as session:
            query = session.query(CredentialModel)
            query = query.filter_by(user_id=user_id)
            if type:
                query = query.filter_by(type=type)
            refs = query.all()
            return [ref.to_dict() for ref in refs]

    def _get_credential(self, session, credential_id):
        ref = session.query(CredentialModel).get(credential_id)
        if ref is None:
            raise exception.CredentialNotFound(credential_id=credential_id)
        return ref

    def get_credential(self, credential_id):
        with sql.session_for_read() as session:
            return self._get_credential(session, credential_id).to_dict()

    @sql.handle_conflicts(conflict_type='credential')
    def update_credential(self, credential_id, credential):
        with sql.session_for_write() as session:
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
        with sql.session_for_write() as session:
            ref = self._get_credential(session, credential_id)
            session.delete(ref)

    def delete_credentials_for_project(self, project_id):
        with sql.session_for_write() as session:
            query = session.query(CredentialModel)
            query = query.filter_by(project_id=project_id)
            query.delete()

    @oslo_db_api.wrap_db_retry(retry_on_deadlock=True)
    def delete_credentials_for_user(self, user_id):
        with sql.session_for_write() as session:
            query = session.query(CredentialModel)
            query = query.filter_by(user_id=user_id)
            query.delete()
