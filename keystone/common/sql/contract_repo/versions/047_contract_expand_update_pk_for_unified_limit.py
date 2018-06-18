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
    meta = sql.MetaData()
    meta.bind = migrate_engine
    # For Mysql and PostgreSQL, drop the FK in limit table, drop the unique
    # constraint in registered limit and limit tables.
    #
    # For SQLite, drop the old tables, then rename the new tables.
    limit_table = sql.Table('limit', meta, autoload=True)
    registered_limit_table = sql.Table('registered_limit', meta, autoload=True)

    if migrate_engine.name != 'sqlite':
        project_table = sql.Table('project', meta, autoload=True)
        inspector = sql.engine.reflection.Inspector.from_engine(migrate_engine)
        for fk in inspector.get_foreign_keys('limit'):
            fkey = migrate.ForeignKeyConstraint(
                [limit_table.c.project_id],
                [project_table.c.id],
                name=fk['name'])
            fkey.drop()
        for uc in inspector.get_unique_constraints('limit'):
            if set(uc['column_names']) == set(['project_id', 'service_id',
                                               'region_id', 'resource_name']):
                uc = migrate.UniqueConstraint(limit_table.c.project_id,
                                              limit_table.c.service_id,
                                              limit_table.c.region_id,
                                              limit_table.c.resource_name,
                                              name=uc['name'])
                uc.drop()
        for uc in inspector.get_unique_constraints('registered_limit'):
            if set(uc['column_names']) == set(['service_id', 'region_id',
                                               'resource_name']):
                uc = migrate.UniqueConstraint(
                    registered_limit_table.c.service_id,
                    registered_limit_table.c.region_id,
                    registered_limit_table.c.resource_name,
                    name=uc['name'])
                uc.drop()

    else:
        registered_limit_table_new = sql.Table('registered_limit_new', meta,
                                               autoload=True)
        limit_table_new = sql.Table('limit_new', meta, autoload=True)

        limit_table.drop()
        limit_table_new.rename('limit')
        registered_limit_table.drop()
        registered_limit_table_new.rename('registered_limit')
