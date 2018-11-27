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
    meta = sql.MetaData()
    meta.bind = migrate_engine

    limit_table = sql.Table('limit', meta, autoload=True)
    domain_id = sql.Column('domain_id', sql.String(64), nullable=True)
    limit_table.create_column(domain_id)

    if migrate_engine.name == 'sqlite':
        meta = sql.MetaData()
        meta.bind = migrate_engine
        # "limit_new" is the table created in 047 expand script for SQLite
        # case.
        try:
            limit_table_new = sql.Table('limit_new', meta, autoload=True)
            domain_id = sql.Column('domain_id', sql.String(64), nullable=True)
            limit_table_new.create_column(domain_id)
        except sql.exc.NoSuchTableError:
            pass
