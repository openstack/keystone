# Copyright (c) 2013 Hewlett-Packard Development Company, L.P
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

"""Migrated the endpoint 'region' column to 'region_id.

In addition to the rename, the new column is made a foreign key to the
respective 'region' in the region table, ensuring that we auto-create
any regions that are missing.  Further, since the old region column
was 255 chars, and the id column in the region table is 64 chars, the size
of the id column in the region table is increased to match.

To Upgrade:


Region Table

Increase the size of the if column in the region table

Endpoint Table

a. Add the endpoint region_id column, that is a foreign key to the region table
b. For each endpoint
    i. Ensure there is matching region in region table, and if not, create it
    ii. Assign the id to the region_id column
c. Remove the column region

"""

import migrate
import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


def _migrate_to_region_id(migrate_engine, region_table, endpoint_table):
    endpoints = list(endpoint_table.select().execute())

    for endpoint in endpoints:
        if endpoint.region is None:
            continue

        region = list(region_table.select(
            whereclause=region_table.c.id == endpoint.region).execute())
        if len(region) == 1:
            region_id = region[0].id
        else:
            region_id = endpoint.region
            region = {'id': region_id,
                      'description': '',
                      'extra': '{}'}
            session = sessionmaker(bind=migrate_engine)()
            region_table.insert(region).execute()
            session.commit()

        new_values = {'region_id': region_id}
        f = endpoint_table.c.id == endpoint.id
        update = endpoint_table.update().where(f).values(new_values)
        migrate_engine.execute(update)

    migrate.ForeignKeyConstraint(
        columns=[endpoint_table.c.region_id],
        refcolumns=[region_table.c.id],
        name='fk_endpoint_region_id').create()


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    region_table = sql.Table('region', meta, autoload=True)
    region_table.c.id.alter(type=sql.String(length=255))
    region_table.c.parent_region_id.alter(type=sql.String(length=255))
    endpoint_table = sql.Table('endpoint', meta, autoload=True)
    region_id_column = sql.Column('region_id',
                                  sql.String(length=255), nullable=True)
    region_id_column.create(endpoint_table)

    _migrate_to_region_id(migrate_engine, region_table, endpoint_table)

    endpoint_table.c.region.drop()
