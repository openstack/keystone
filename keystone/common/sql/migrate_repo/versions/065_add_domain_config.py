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


WHITELIST_TABLE = 'whitelisted_config'
SENSITIVE_TABLE = 'sensitive_config'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    whitelist_table = sql.Table(
        WHITELIST_TABLE,
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('group', sql.String(255), primary_key=True),
        sql.Column('option', sql.String(255), primary_key=True),
        sql.Column('value', ks_sql.JsonBlob.impl, nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    whitelist_table.create(migrate_engine, checkfirst=True)

    sensitive_table = sql.Table(
        SENSITIVE_TABLE,
        meta,
        sql.Column('domain_id', sql.String(64), primary_key=True),
        sql.Column('group', sql.String(255), primary_key=True),
        sql.Column('option', sql.String(255), primary_key=True),
        sql.Column('value', ks_sql.JsonBlob.impl, nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    sensitive_table.create(migrate_engine, checkfirst=True)
