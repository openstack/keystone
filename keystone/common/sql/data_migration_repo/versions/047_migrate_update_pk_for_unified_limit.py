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
    # For SQLite, migrate the data from old tables to new ones.
    if migrate_engine == 'sqlite':
        registered_limit_table = sql.Table('registered_limit', meta,
                                           autoload=True)
        registered_limit_table_new = sql.Table('registered_limit_new', meta,
                                               autoload=True)

        limit_table = sql.Table('limit', meta, autoload=True)
        limit_table_new = sql.Table('limit_new', meta, autoload=True)

        registered_limit_table_new.insert().from_select(
            ['id', 'service_id', 'region_id', 'resource_name', 'default_limit',
             'description'],
            registered_limit_table.select()).execute()

        limit_table_new.insert().from_select(
            ['id', 'project_id', 'service_id', 'region_id', 'resource_name',
             'resource_limit', 'description'],
            limit_table.select()).execute()
