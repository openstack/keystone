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


MYSQL_CREATE_ID_PRIMARY_KEY_COLUMN = """
ALTER TABLE `%s` ADD `internal_id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY;
"""

POSTGRESQL_CREATE_ID_PRIMARY_KEY_COLUMN = """
ALTER TABLE "%s" ADD COLUMN "internal_id" SERIAL PRIMARY KEY;
"""


def upgrade(migrate_engine):

    # For both registered_limit and limit tables in MySQL and PostgreSQL:
    #
    # 1. drop the primary key on `id` column.
    # 2. create a auto increment `internal_id` column with primary key.
    # 3. add unique constraint on `id` column.
    #
    # But SQLite doesn't support add primary key to a existed table, so for
    # SQLite, we'll follow the steps, take the registered_limit as an example:
    #
    # 1. Add a new table `registered_limit_new` which contains `internal_id`
    #    column.
    # 2. migrate the data from `registered_limit` to `registered_limit_new`
    # 3. drop the `registered_limit`, rename `registered_limit_new` to
    #    `registered_limit`.

    meta = sql.MetaData()
    meta.bind = migrate_engine
    registered_limit_table = sql.Table('registered_limit', meta, autoload=True)
    limit_table = sql.Table('limit', meta, autoload=True)

    if migrate_engine.name != 'sqlite':
        pk = migrate.PrimaryKeyConstraint('id', table=registered_limit_table)
        pk.drop()
        if migrate_engine.name == 'mysql':
            migrate_engine.execute(
                MYSQL_CREATE_ID_PRIMARY_KEY_COLUMN % 'registered_limit')
        else:
            migrate_engine.execute(
                POSTGRESQL_CREATE_ID_PRIMARY_KEY_COLUMN % 'registered_limit')
        unique_constraint = migrate.UniqueConstraint(
            'id', table=registered_limit_table)
        unique_constraint.create()

        pk = migrate.PrimaryKeyConstraint('id', table=limit_table)
        pk.drop()
        if migrate_engine.name == 'mysql':
            migrate_engine.execute(
                MYSQL_CREATE_ID_PRIMARY_KEY_COLUMN % 'limit')
        else:
            migrate_engine.execute(
                POSTGRESQL_CREATE_ID_PRIMARY_KEY_COLUMN % 'limit')
        unique_constraint = migrate.UniqueConstraint('id', table=limit_table)
        unique_constraint.create()
    else:
        # SQLite case
        registered_limit_table_new = sql.Table(
            'registered_limit_new',
            meta,
            sql.Column('internal_id', sql.Integer, primary_key=True),
            sql.Column('id', sql.String(length=64), unique=True),
            sql.Column('service_id',
                       sql.String(64)),
            sql.Column('region_id',
                       sql.String(64),
                       nullable=True),
            sql.Column('resource_name', sql.String(255)),
            sql.Column('default_limit', sql.Integer, nullable=False),
            sql.Column('description', sql.Text),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
        registered_limit_table_new.create(migrate_engine, checkfirst=True)

        limit_table_new = sql.Table(
            'limit_new',
            meta,
            sql.Column('internal_id', sql.Integer, primary_key=True),
            sql.Column('id', sql.String(length=64), unique=True),
            sql.Column('project_id', sql.String(64)),
            sql.Column('service_id', sql.String(64)),
            sql.Column('region_id', sql.String(64), nullable=True),
            sql.Column('resource_name', sql.String(255)),
            sql.Column('resource_limit', sql.Integer, nullable=False),
            sql.Column('description', sql.Text),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
        limit_table_new.create(migrate_engine, checkfirst=True)
