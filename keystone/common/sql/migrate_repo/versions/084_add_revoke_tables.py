# Copyright 2014 IBM Corp.
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

from keystone.common.sql import upgrades


def upgrade(migrate_engine):
    try:
        extension_version = upgrades.get_db_version(
            extension='revoke',
            engine=migrate_engine)
    except Exception:
        extension_version = 0

    # This migration corresponds to revoke extension migration 2. Only
    # update if it has not been run.
    if extension_version >= 2:
        return

    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    service_table = sql.Table(
        'revocation_event',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64)),
        sql.Column('project_id', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.Column('role_id', sql.String(64)),
        sql.Column('trust_id', sql.String(64)),
        sql.Column('consumer_id', sql.String(64)),
        sql.Column('access_token_id', sql.String(64)),
        sql.Column('issued_before', sql.DateTime(), nullable=False),
        sql.Column('expires_at', sql.DateTime()),
        sql.Column('revoked_at', sql.DateTime(), index=True, nullable=False),
        sql.Column('audit_id', sql.String(32), nullable=True),
        sql.Column('audit_chain_id', sql.String(32), nullable=True))

    service_table.create(migrate_engine, checkfirst=True)
