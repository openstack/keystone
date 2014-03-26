# Copyright 2014 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""Relax the uniqueness of `description` column in region table.

The region table has a dedicated column for the region `description`. This
column originally was not nullable and had to be unique. So if a user wanted
to create a region without sending a `description` in the request, they would
experience an SQL error because the `description` column can't be null for a
region. This means that every region had to have a unique description.

To upgrade, we are going to transfer all the data from the existing region
table to a temporary table, drop the original region table, and then finally
rename the temporary table to the correct name.

There is no downgrade path as the original migration has been fixed to not
include the unique constraint on description column.

"""

import migrate
import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


_TEMP_REGION_TABLE_NAME = 'temp_region'
_REGION_TABLE_NAME = 'region'


def _migrate_to_new_region_table(meta, migrate_engine, region_table):
    # Create a temporary region table to hold data while we recreate the
    # new region table without a unique constraint on the description column

    session = sessionmaker(bind=migrate_engine)()

    temp_region_table = sql.Table(
        _TEMP_REGION_TABLE_NAME,
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('description', sql.String(255), nullable=False),
        sql.Column('parent_region_id', sql.String(64), nullable=True),
        sql.Column('extra', sql.Text()))
    temp_region_table.create(migrate_engine, checkfirst=True)

    # Migrate the data
    for region in list(session.query(region_table)):
        session.execute(temp_region_table.insert().values(
            id=region.id,
            description=region.description,
            parent_region_id=region.parent_region_id,
            extra=region.extra))

    session.commit()
    session.close()

    # Drop the old region table
    region_table.drop(checkfirst=True)
    migrate.rename_table(temp_region_table, _REGION_TABLE_NAME, meta.bind)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    region_table = sql.Table(_REGION_TABLE_NAME, meta, autoload=True)
    for idx in region_table.indexes:
        if ((idx.columns.get('description') == region_table.c.description) and
                len(idx.columns) is 1):
            # Constraint was found, do the migration.
            _migrate_to_new_region_table(meta, migrate_engine, region_table)
            break


def downgrade(migrate_engine):
    # There is no downgrade option. The unique constraint should not have
    # existed and therefore does not need to be re-added. The previous
    # migration has been modified to not contain the unique constraint.
    pass
