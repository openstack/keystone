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


"""Adds an `enabled` column to the `service` table.

The enabled value for the `service` table was stored in the `extra` column
as part of a JSON string.

To upgrade, the `enabled` column is added with a default value of ``true``,
then we check all the `extra` JSON for disabled and set the value to ``false``
for those.

Downgrade is essentially the opposite -- we update the JSON with
``"enabled": false`` for any services that are disabled and drop the `enabled`
column.

"""

import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker

from keystone.openstack.common import jsonutils
from keystone.openstack.common import strutils


def _migrate_enabled_from_extra(migrate_engine, service_table):
    """Remove `enabled` from `extra`, put it in the `enabled` column."""

    services = list(service_table.select().execute())

    for service in services:
        extra_dict = jsonutils.loads(service.extra)

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
        f = service_table.c.id == service.id
        update = service_table.update().where(f).values(new_values)
        migrate_engine.execute(update)


def _migrate_enabled_to_extra(migrate_engine, service_table):
    """Get enabled value from 'enabled' column and put it in 'extra' JSON.

    Only put the enabled value to the 'extra' JSON if it's False, since the
    default is True.

    """

    services = list(service_table.select().execute())

    for service in services:

        if service.enabled:
            # Nothing to do since the service is enabled.
            continue

        extra_dict = jsonutils.loads(service.extra)
        extra_dict['enabled'] = False

        new_values = {
            'extra': jsonutils.dumps(extra_dict),
        }
        f = service_table.c.id == service.id
        update = service_table.update().where(f).values(new_values)
        migrate_engine.execute(update)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    service_table = sql.Table('service', meta, autoload=True)
    enabled_column = sql.Column('enabled', sql.Boolean, nullable=False,
                                default=True, server_default='1')
    enabled_column.create(service_table)

    _migrate_enabled_from_extra(migrate_engine, service_table)


def _downgrade_service_table_with_copy(meta, migrate_engine):
    # Used with databases that don't support dropping a column (e.g., sqlite).

    maker = sessionmaker(bind=migrate_engine)
    session = maker()

    session.execute('ALTER TABLE service RENAME TO orig_service;')

    service_table = sql.Table(
        'service',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('type', sql.String(255)),
        sql.Column('extra', sql.Text()))
    service_table.create(migrate_engine, checkfirst=True)

    orig_service_table = sql.Table('orig_service', meta, autoload=True)
    for service in session.query(orig_service_table):
        new_values = {
            'id': service.id,
            'type': service.type,
            'extra': service.extra,
        }
        session.execute('insert into service (id, type, extra) '
                        'values ( :id, :type, :extra);',
                        new_values)
    session.execute('drop table orig_service;')
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    service_table = sql.Table('service', meta, autoload=True)
    _migrate_enabled_to_extra(migrate_engine, service_table)

    if migrate_engine.name == 'sqlite':
        meta.clear()
        _downgrade_service_table_with_copy(meta, migrate_engine)
        return

    service_table.c.enabled.drop()
