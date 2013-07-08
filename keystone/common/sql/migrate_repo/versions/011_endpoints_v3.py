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

from keystone.common.sql import migration_helpers


def upgrade(migrate_engine):
    """Create API-version specific endpoint tables."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    legacy_table = sql.Table('endpoint', meta, autoload=True)

    renames = {'endpoint_v2': legacy_table}
    service_table = sql.Table('service', meta, autoload=True)
    constraints = [{'table': legacy_table,
                    'fk_column': 'service_id',
                    'ref_column': service_table.c.id}]
    migration_helpers.rename_tables_with_constraints(renames, constraints,
                                                     migrate_engine)

    sql.Table('service', meta, autoload=True)
    new_table = sql.Table(
        'endpoint_v3',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('legacy_endpoint_id', sql.String(64)),
        sql.Column('interface', sql.String(8), nullable=False),
        sql.Column('region', sql.String(255)),
        sql.Column('service_id',
                   sql.String(64),
                   sql.ForeignKey('service.id'),
                   nullable=False),
        sql.Column('url', sql.Text(), nullable=False),
        sql.Column('extra', sql.Text()))
    new_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    """Replace API-version specific endpoint tables with one based on v2."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    new_table = sql.Table('endpoint_v3', meta, autoload=True)
    new_table.drop()

    legacy_table = sql.Table('endpoint_v2', meta, autoload=True)

    renames = {'endpoint': legacy_table}
    service_table = sql.Table('service', meta, autoload=True)
    constraints = [{'table': legacy_table,
                    'fk_column': 'service_id',
                    'ref_column': service_table.c.id}]
    migration_helpers.rename_tables_with_constraints(renames, constraints,
                                                     migrate_engine)
