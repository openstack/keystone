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


"""Adds an `enabled` column to the `endpoint` table.

The enabled value for the `endpoint` table was stored in the `extra` column
as part of a JSON string.

To upgrade, the `enabled` column is added with a default value of ``true``,
then we check all the `extra` JSON for disabled and set the value to ``false``
for those.

Downgrade is essentially the opposite -- we update the JSON with
``"enabled": false`` for any endpoints that are disabled and drop the `enabled`
column.

"""

import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker

from keystone.openstack.common import jsonutils
from keystone.openstack.common import strutils


def _migrate_enabled_from_extra(migrate_engine, endpoint_table):
    """Remove `enabled` from `extra`, put it in the `enabled` column."""

    eps = list(endpoint_table.select().execute())

    for ep in eps:
        extra_dict = jsonutils.loads(ep.extra)

        if 'enabled' not in extra_dict:
            # `enabled` and `extra` are already as expected.
            continue

        enabled = extra_dict.pop('enabled')

        if enabled is None:
            enabled = True
        else:
            enabled = strutils.bool_from_string(enabled, default=True)

        new_values = {
            'enabled': enabled,
            'extra': jsonutils.dumps(extra_dict),
        }
        f = endpoint_table.c.id == ep.id
        update = endpoint_table.update().where(f).values(new_values)
        migrate_engine.execute(update)


def _migrate_enabled_to_extra(migrate_engine, endpoint_table):
    """Get enabled value from 'enabled' column and put it in 'extra' JSON.

    Only put the enabled value to the 'extra' JSON if it's False, since the
    default is True.

    """

    eps = list(endpoint_table.select().execute())

    for ep in eps:

        if ep.enabled:
            # Nothing to do since the endpoint is enabled.
            continue

        extra_dict = jsonutils.loads(ep.extra)
        extra_dict['enabled'] = False

        new_values = {
            'extra': jsonutils.dumps(extra_dict),
        }
        f = endpoint_table.c.id == ep.id
        update = endpoint_table.update().where(f).values(new_values)
        migrate_engine.execute(update)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table('endpoint', meta, autoload=True)
    enabled_column = sql.Column('enabled', sql.Boolean, nullable=False,
                                default=True, server_default='1')
    enabled_column.create(endpoint_table)

    _migrate_enabled_from_extra(migrate_engine, endpoint_table)


def _downgrade_endpoint_table_with_copy(meta, migrate_engine):
    # Used with databases that don't support dropping a column (e.g., sqlite).

    maker = sessionmaker(bind=migrate_engine)
    session = maker()

    session.execute('ALTER TABLE endpoint RENAME TO orig_endpoint;')

    # Need to load the metadata for the service table since it's used as
    # foreign key.
    sql.Table('service', meta, autoload=True)

    endpoint_table = sql.Table(
        'endpoint',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('legacy_endpoint_id', sql.String(64)),
        sql.Column('interface', sql.String(8), nullable=False),
        sql.Column('region', sql.String(255)),
        sql.Column('service_id', sql.String(64), sql.ForeignKey('service.id'),
                   nullable=False),
        sql.Column('url', sql.Text(), nullable=False),
        sql.Column('extra', sql.Text()))
    endpoint_table.create(migrate_engine, checkfirst=True)

    orig_endpoint_table = sql.Table('orig_endpoint', meta, autoload=True)
    for endpoint in session.query(orig_endpoint_table):
        new_values = {
            'id': endpoint.id,
            'legacy_endpoint_id': endpoint.legacy_endpoint_id,
            'interface': endpoint.interface,
            'region': endpoint.region,
            'service_id': endpoint.service_id,
            'url': endpoint.url,
            'extra': endpoint.extra,
        }
        session.execute('insert into endpoint (id, legacy_endpoint_id, '
                        'interface, region, service_id, url, extra) '
                        'values ( :id, :legacy_endpoint_id, :interface, '
                        ':region, :service_id, :url, :extra);',
                        new_values)
    session.execute('drop table orig_endpoint;')
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table('endpoint', meta, autoload=True)
    _migrate_enabled_to_extra(migrate_engine, endpoint_table)

    if migrate_engine.name == 'sqlite':
        meta.clear()
        _downgrade_endpoint_table_with_copy(meta, migrate_engine)
        return

    endpoint_table.c.enabled.drop()
