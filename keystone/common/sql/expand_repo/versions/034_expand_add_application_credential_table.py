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

import sqlalchemy as sql

from keystone.common import sql as ks_sql


def upgrade(migrate_engine):

    meta = sql.MetaData()
    meta.bind = migrate_engine

    application_credential = sql.Table(
        'application_credential', meta,
        sql.Column('internal_id', sql.Integer, primary_key=True,
                   nullable=False),
        sql.Column('id', sql.String(length=64), nullable=False),
        sql.Column('name', sql.String(length=255), nullable=False),
        sql.Column('secret_hash', sql.String(length=255), nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('user_id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(64), nullable=False),
        sql.Column('expires_at', ks_sql.DateTimeInt()),
        sql.Column('allow_application_credential_creation', sql.Boolean),
        sql.UniqueConstraint('user_id', 'name',
                             name='duplicate_app_cred_constraint'),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    application_credential_role = sql.Table(
        'application_credential_role', meta,
        sql.Column('application_credential_id', sql.Integer,
                   sql.ForeignKey(application_credential.c.internal_id,
                                  ondelete='CASCADE'),
                   primary_key=True, nullable=False),
        sql.Column('role_id', sql.String(length=64), primary_key=True,
                   nullable=False),
        mysql_engine='InnoDB', mysql_charset='utf8')

    application_credential.create(migrate_engine, checkfirst=True)
    application_credential_role.create(migrate_engine, checkfirst=True)
