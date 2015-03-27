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

import sqlalchemy as sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    consumer_table = sql.Table(
        'consumer',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('description', sql.String(64), nullable=False),
        sql.Column('secret', sql.String(64), nullable=False),
        sql.Column('extra', sql.Text(), nullable=False))
    consumer_table.create(migrate_engine, checkfirst=True)

    request_token_table = sql.Table(
        'request_token',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('request_secret', sql.String(64), nullable=False),
        sql.Column('verifier', sql.String(64), nullable=True),
        sql.Column('authorizing_user_id', sql.String(64), nullable=True),
        sql.Column('requested_project_id', sql.String(64), nullable=False),
        sql.Column('requested_roles', sql.Text(), nullable=False),
        sql.Column('consumer_id', sql.String(64), nullable=False, index=True),
        sql.Column('expires_at', sql.String(64), nullable=True))
    request_token_table.create(migrate_engine, checkfirst=True)

    access_token_table = sql.Table(
        'access_token',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('access_secret', sql.String(64), nullable=False),
        sql.Column('authorizing_user_id', sql.String(64),
                   nullable=False, index=True),
        sql.Column('project_id', sql.String(64), nullable=False),
        sql.Column('requested_roles', sql.Text(), nullable=False),
        sql.Column('consumer_id', sql.String(64), nullable=False),
        sql.Column('expires_at', sql.String(64), nullable=True))
    access_token_table.create(migrate_engine, checkfirst=True)
