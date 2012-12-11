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

import migrate
import sqlalchemy as sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    # catalog

    service_table = sql.Table(
        'service',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('type', sql.String(255)),
        sql.Column('extra', sql.Text()))
    service_table.create(migrate_engine, checkfirst=True)

    endpoint_table = sql.Table(
        'endpoint',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('region', sql.String(255)),
        sql.Column('service_id',
                   sql.String(64),
                   sql.ForeignKey('service.id'),
                   nullable=False),
        sql.Column('extra', sql.Text()))
    endpoint_table.create(migrate_engine, checkfirst=True)

    # identity

    role_table = sql.Table(
        'role',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(255), unique=True, nullable=False))
    role_table.create(migrate_engine, checkfirst=True)

    tenant_table = sql.Table(
        'tenant',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()))
    tenant_table.create(migrate_engine, checkfirst=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        sql.Column('user_id', sql.String(64), primary_key=True),
        sql.Column('tenant_id', sql.String(64), primary_key=True),
        sql.Column('data', sql.Text()))
    metadata_table.create(migrate_engine, checkfirst=True)

    ec2_credential_table = sql.Table(
        'ec2_credential',
        meta,
        sql.Column('access', sql.String(64), primary_key=True),
        sql.Column('secret', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.Column('tenant_id', sql.String(64)))
    ec2_credential_table.create(migrate_engine, checkfirst=True)

    user_table = sql.Table(
        'user',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()))
    user_table.create(migrate_engine, checkfirst=True)

    user_tenant_membership_table = sql.Table(
        'user_tenant_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'tenant_id',
            sql.String(64),
            sql.ForeignKey('tenant.id'),
            primary_key=True))
    user_tenant_membership_table.create(migrate_engine, checkfirst=True)

    # token

    token_table = sql.Table(
        'token',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('expires', sql.DateTime()),
        sql.Column('extra', sql.Text()))
    token_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    tables = ['user_tenant_membership', 'token', 'user', 'tenant', 'role',
              'metadata', 'ec2_credential', 'endpoint', 'service']
    for t in tables:
        table = sql.Table(t, meta, autoload=True)
        table.drop(migrate_engine, checkfirst=True)
