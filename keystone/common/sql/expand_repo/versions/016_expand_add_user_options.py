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

import sqlalchemy as sql

from keystone.common import sql as ks_sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)

    user_option = sql.Table(
        'user_option',
        meta,
        sql.Column('user_id', sql.String(64), sql.ForeignKey(user_table.c.id,
                   ondelete='CASCADE'), nullable=False, primary_key=True),
        sql.Column('option_id', sql.String(4), nullable=False,
                   primary_key=True),
        sql.Column('option_value', ks_sql.JsonBlob, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    user_option.create(migrate_engine, checkfirst=True)
