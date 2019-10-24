# Copyright 2019 SUSE Linux GmbH
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

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    application_credential = sql.Table(
        'application_credential', meta, autoload=True)
    access_rule = sql.Table(
        'access_rule', meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('service', sql.String(64)),
        sql.Column('path', sql.String(128)),
        sql.Column('method', sql.String(16)),
        mysql_engine='InnoDB', mysql_charset='utf8'
    )
    app_cred_access_rule = sql.Table(
        'application_credential_access_rule', meta,
        sql.Column('application_credential_id', sql.Integer,
                   sql.ForeignKey(application_credential.c.internal_id,
                                  ondelete='CASCADE'),
                   primary_key=True, nullable=False),
        sql.Column('access_rule_id', sql.Integer,
                   sql.ForeignKey(access_rule.c.id,
                                  ondelete='CASCADE'),
                   primary_key=True, nullable=False),
        mysql_engine='InnoDB', mysql_charset='utf8'
    )
    access_rule.create(migrate_engine, checkfirst=True)
    app_cred_access_rule.create(migrate_engine, checkfirst=True)
