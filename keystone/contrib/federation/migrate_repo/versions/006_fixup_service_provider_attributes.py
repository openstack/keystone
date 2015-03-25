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

_SP_TABLE_NAME = 'service_provider'


def _update_null_columns(migrate_engine, sp_table):
    stmt = (sp_table.update().
            where(sp_table.c.auth_url.is_(None)).
            values(auth_url=''))
    migrate_engine.execute(stmt)

    stmt = (sp_table.update().
            where(sp_table.c.sp_url.is_(None)).
            values(sp_url=''))
    migrate_engine.execute(stmt)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    sp_table = sql.Table(_SP_TABLE_NAME, meta, autoload=True)
    # The columns are being changed to non-nullable. To prevent
    # database errors when both are altered, all the existing
    # null-records should be filled with not null values.
    _update_null_columns(migrate_engine, sp_table)

    sp_table.c.auth_url.alter(nullable=False)
    sp_table.c.sp_url.alter(nullable=False)
