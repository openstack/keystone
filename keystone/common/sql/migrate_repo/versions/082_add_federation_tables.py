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
import keystone.conf

CONF = keystone.conf.CONF
_RELAY_STATE_PREFIX = 'relay_state_prefix'


def upgrade(migrate_engine):
    try:
        extension_version = upgrades.get_db_version(
            extension='federation',
            engine=migrate_engine)
    except Exception:
        extension_version = 0

    # This migration corresponds to federation extension migration 8. Only
    # update if it has not been run.
    if extension_version >= 8:
        return

    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    idp_table = sql.Table(
        'identity_provider',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('enabled', sql.Boolean, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    idp_table.create(migrate_engine, checkfirst=True)

    federation_protocol_table = sql.Table(
        'federation_protocol',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('idp_id', sql.String(64),
                   sql.ForeignKey('identity_provider.id', ondelete='CASCADE'),
                   primary_key=True),
        sql.Column('mapping_id', sql.String(64), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    federation_protocol_table.create(migrate_engine, checkfirst=True)

    mapping_table = sql.Table(
        'mapping',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('rules', sql.Text(), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    mapping_table.create(migrate_engine, checkfirst=True)

    relay_state_prefix_default = CONF.saml.relay_state_prefix
    sp_table = sql.Table(
        'service_provider',
        meta,
        sql.Column('auth_url', sql.String(256), nullable=False),
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('enabled', sql.Boolean, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('sp_url', sql.String(256), nullable=False),
        sql.Column(_RELAY_STATE_PREFIX, sql.String(256), nullable=False,
                   server_default=relay_state_prefix_default),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    sp_table.create(migrate_engine, checkfirst=True)

    idp_table = sql.Table('identity_provider', meta, autoload=True)
    remote_id_table = sql.Table(
        'idp_remote_ids',
        meta,
        sql.Column('idp_id', sql.String(64),
                   sql.ForeignKey('identity_provider.id', ondelete='CASCADE')),
        sql.Column('remote_id', sql.String(255), primary_key=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    remote_id_table.create(migrate_engine, checkfirst=True)
