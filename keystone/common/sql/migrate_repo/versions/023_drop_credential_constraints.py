# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

from migrate import ForeignKeyConstraint
import sqlalchemy
from sqlalchemy.orm import sessionmaker

MYSQL_FKEY_QUERY = ("select CONSTRAINT_NAME from "
                    "INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS "
                    "where table_name = 'credential'")


def drop_constraint_mysql(migrate_engine):
    session = sessionmaker(bind=migrate_engine)()
    #http://bugs.mysql.com/bug.php?id=10333
    #MySQL varies from the SQL norm in naming
    #Foreign Keys.  The mapping from the column name
    #to the actual foreign key is stored in
    #INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS
    #SQLAlchemy expects the constraint name to be
    # the column name.
    for constraint in session.execute(MYSQL_FKEY_QUERY):
        session.execute('ALTER TABLE credential DROP FOREIGN KEY %s;'
                        % constraint[0])
    session.commit()


def remove_constraints(migrate_engine):
    if migrate_engine.name == 'sqlite':
        return
    if migrate_engine.name == 'mysql':
        drop_constraint_mysql(migrate_engine)
        return
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    user_table = sqlalchemy.Table('user', meta, autoload=True)
    proj_table = sqlalchemy.Table('project', meta, autoload=True)
    cred_table = sqlalchemy.Table('credential', meta, autoload=True)
    ForeignKeyConstraint(columns=[cred_table.c.user_id],
                         refcolumns=[user_table.c.id]).drop()
    ForeignKeyConstraint(columns=[cred_table.c.project_id],
                         refcolumns=[proj_table.c.id]).drop()


def add_constraints(migrate_engine):
    if migrate_engine.name == 'sqlite':
        return
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    user_table = sqlalchemy.Table('user', meta, autoload=True)
    proj_table = sqlalchemy.Table('project', meta, autoload=True)
    cred_table = sqlalchemy.Table('credential', meta, autoload=True)
    ForeignKeyConstraint(columns=[cred_table.c.user_id],
                         refcolumns=[user_table.c.id]).create()
    ForeignKeyConstraint(columns=[cred_table.c.project_id],
                         refcolumns=[proj_table.c.id]).create()


def upgrade(migrate_engine):
    remove_constraints(migrate_engine)


def downgrade(migrate_engine):
    add_constraints(migrate_engine)
