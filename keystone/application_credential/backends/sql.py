# Copyright 2018 SUSE Linux GmbH
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

import datetime

import sqlalchemy

from keystone.application_credential.backends import base
from keystone.common import password_hashing
from keystone.common import sql
from keystone import exception
from keystone.i18n import _


class ApplicationCredentialModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'application_credential'
    attributes = ['internal_id', 'id', 'name', 'secret_hash', 'description',
                  'user_id', 'project_id', 'system', 'expires_at',
                  'unrestricted']
    internal_id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    id = sql.Column(sql.String(64), nullable=False)
    name = sql.Column(sql.String(255), nullable=False)
    secret_hash = sql.Column(sql.String(255), nullable=False)
    description = sql.Column(sql.Text())
    user_id = sql.Column(sql.String(64), nullable=False)
    project_id = sql.Column(sql.String(64), nullable=True)
    system = sql.Column(sql.String(64), nullable=True)
    expires_at = sql.Column(sql.DateTimeInt())
    unrestricted = sql.Column(sql.Boolean)
    __table_args__ = (sql.UniqueConstraint('name', 'user_id',
                      name='duplicate_app_cred_constraint'),)

    roles = sqlalchemy.orm.relationship(
        'ApplicationCredentialRoleModel',
        backref=sqlalchemy.orm.backref('application_credential'),
        cascade='all, delete-orphan')


class ApplicationCredentialRoleModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'application_credential_role'
    attributes = ['application_credential_id', 'role_id']
    application_credential_id = sql.Column(
        sql.Integer,
        sql.ForeignKey('application_credential.internal_id',
                       ondelete='cascade'),
        primary_key=True,
        nullable=False)
    role_id = sql.Column(sql.String(64), primary_key=True, nullable=False)


class ApplicationCredential(base.ApplicationCredentialDriverBase):

    def _check_secret(self, secret, app_cred_ref):
        secret_hash = app_cred_ref['secret_hash']
        return password_hashing.check_password(secret, secret_hash)

    def _check_expired(self, app_cred_ref):
        if app_cred_ref.get('expires_at'):
            return datetime.datetime.utcnow() >= app_cred_ref['expires_at']
        return False

    def authenticate(self, application_credential_id, secret):
        msg = _('Invalid application credential ID or secret')
        try:
            app_cred_ref = self.get_application_credential(
                application_credential_id)
        except exception.ApplicationCredentialNotFound:
            raise AssertionError(msg)
        if not self._check_secret(secret, app_cred_ref):
            raise AssertionError(msg)
        if self._check_expired(app_cred_ref):
            raise AssertionError(msg)

    def _hash_secret(self, app_cred_ref):
        unhashed_secret = app_cred_ref.pop('secret')
        hashed_secret = password_hashing.hash_password(unhashed_secret)
        app_cred_ref['secret_hash'] = hashed_secret

    @sql.handle_conflicts(conflict_type='application_credential')
    def create_application_credential(self, application_credential, roles):
        app_cred = application_credential.copy()
        self._hash_secret(app_cred)
        with sql.session_for_write() as session:
            ref = ApplicationCredentialModel.from_dict(app_cred)
            session.add(ref)
            for role in roles:
                app_cred_role = ApplicationCredentialRoleModel()
                app_cred_role.application_credential = ref
                app_cred_role.role_id = role['id']
                session.add(app_cred_role)
            application_credential_dict = ref.to_dict()
            application_credential_dict.pop('internal_id')
            application_credential_dict['roles'] = roles
            return application_credential_dict

    def _to_dict(self, ref):
        app_cred = ref.to_dict()
        roles = [{'id': r.to_dict()['role_id']} for r in ref.roles]
        app_cred['roles'] = roles
        app_cred.pop('internal_id')
        return app_cred

    def get_application_credential(self, application_credential_id):
        with sql.session_for_read() as session:
            query = session.query(ApplicationCredentialModel).filter_by(
                id=application_credential_id)
            ref = query.first()
            if ref is None:
                raise exception.ApplicationCredentialNotFound(
                    application_credential_id=application_credential_id)
            app_cred_dict = self._to_dict(ref)
            return app_cred_dict

    def list_application_credentials_for_user(self, user_id, hints):
        with sql.session_for_read() as session:
            query = session.query(ApplicationCredentialModel)
            query = sql.filter_limit_query(ApplicationCredentialModel, query,
                                           hints)
            app_creds = query.filter_by(user_id=user_id)
            return [self._to_dict(ref) for ref in app_creds]

    @sql.handle_conflicts(conflict_type='application_credential')
    def delete_application_credential(self, application_credential_id):
        with sql.session_for_write() as session:
            query = session.query(ApplicationCredentialModel)
            app_cred_ref = query.filter_by(
                id=application_credential_id).first()
            if not app_cred_ref:
                raise exception.ApplicationCredentialNotFound(
                    application_credential_id=application_credential_id)
            session.delete(app_cred_ref)

    def delete_application_credentials_for_user(self, user_id):
        with sql.session_for_write() as session:
            query = session.query(ApplicationCredentialModel)
            query = query.filter_by(user_id=user_id)
            query.delete()

    def delete_application_credentials_for_user_on_project(self, user_id,
                                                           project_id):
        with sql.session_for_write() as session:
            query = session.query(ApplicationCredentialModel)
            query = query.filter_by(user_id=user_id)
            query = query.filter_by(project_id=project_id)
            query.delete()
