# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('role', meta, autoload=True)
    sql.Table('project', meta, autoload=True)

    trust_table = sql.Table(
        'trust',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('trustor_user_id',
                   sql.String(64),
                   unique=False,
                   nullable=False,),
        sql.Column('trustee_user_id',
                   sql.String(64),
                   unique=False,
                   nullable=False),
        sql.Column('project_id', sql.String(64),
                   unique=False,
                   nullable=True),
        sql.Column("impersonation", sql.types.Boolean, nullable=False),
        sql.Column("deleted_at", sql.types.DateTime, nullable=True),
        sql.Column("expires_at", sql.types.DateTime, nullable=True),
        sql.Column('extra', sql.Text()))
    trust_table.create(migrate_engine, checkfirst=True)

    trust_role_table = sql.Table(
        'trust_role',
        meta,
        sql.Column('trust_id', sql.String(64), primary_key=True,
                   nullable=False),
        sql.Column('role_id', sql.String(64), primary_key=True,
                   nullable=False))
    trust_role_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    # Operations to reverse the above upgrade go here.
    for table_name in ['trust_role', 'trust']:
        table = sql.Table(table_name, meta, autoload=True)
        table.drop()
