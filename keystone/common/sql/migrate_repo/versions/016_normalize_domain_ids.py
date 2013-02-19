# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2013 IBM
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

"""
Normalize for domain_id, i.e. ensure User and Project entities have the
domain_id as a first class attribute.

Both User and Project (as well as Group) entities are owned by a
domain, which is implemented as each having a domain_id foreign key
in their sql representation that points back to the respective
domain in the domain table.  This domain_id attribute should also
be required (i.e. not nullable)

Adding a non_nullable foreign key attribute to a table with existing
data causes a few problems since not all DB engines support the
ability to either control the triggering of integrity constraints
or the ability to modify columns after they are created.

To get round the above inconsistencies, two versions of the
upgrade/downgrade functions are supplied, one for those engines
that support dropping columns, and one for those that don't.  For
the latter we are forced to do table copy AND control the triggering
of integrity constraints.
"""

import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker
from keystone import config


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


def _disable_foreign_constraints(session, migrate_engine):
    if migrate_engine.name == 'mysql':
        session.execute('SET foreign_key_checks = 0;')


def _enable_foreign_constraints(session, migrate_engine):
    if migrate_engine.name == 'mysql':
        session.execute('SET foreign_key_checks = 1;')


def upgrade_user_table_with_copy(meta, migrate_engine, session):
    # We want to add the domain_id attribute to the user table.  Since
    # it is non nullable and the table may have data, easiest way is
    # a table copy. Further, in order to keep foreign key constraints
    # pointing at the right table, we need to be able and do a table
    # DROP then CREATE, rather than ALTERing the name of the table.

    # First make a copy of the user table
    temp_user_table = sql.Table(
        'temp_user',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('password', sql.String(128)),
        sql.Column('enabled', sql.Boolean, default=True))
    temp_user_table.create(migrate_engine, checkfirst=True)

    user_table = sql.Table('user', meta, autoload=True)
    for user in session.query(user_table):
        session.execute('insert into temp_user (id, name, extra, '
                        'password, enabled) '
                        'values ( :id, :name, :extra, '
                        ':password, :enabled);',
                        {'id': user.id,
                         'name': user.name,
                         'extra': user.extra,
                         'password': user.password,
                         'enabled': user.enabled})

    # Now switch off constraints while we drop and then re-create the
    # user table, with the additional domain_id column
    _disable_foreign_constraints(session, migrate_engine)
    session.execute('drop table user;')
    # Need to create a new metadata stream since we are going to load a
    # different version of the user table
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine
    domain_table = sql.Table('domain', meta2, autoload=True)
    user_table = sql.Table(
        'user',
        meta2,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column("password", sql.String(128)),
        sql.Column("enabled", sql.Boolean, default=True),
        sql.Column('domain_id', sql.String(64), sql.ForeignKey('domain.id'),
                   nullable=False),
        sql.UniqueConstraint('domain_id', 'name'))
    user_table.create(migrate_engine, checkfirst=True)

    # Finally copy in the data from our temp table and then clean
    # up by deleting our temp table
    for user in session.query(temp_user_table):
        session.execute('insert into user (id, name, extra, '
                        'password, enabled, domain_id) '
                        'values ( :id, :name, :extra, '
                        ':password, :enabled, :domain_id);',
                        {'id': user.id,
                         'name': user.name,
                         'extra': user.extra,
                         'password': user.password,
                         'enabled': user.enabled,
                         'domain_id': DEFAULT_DOMAIN_ID})
    _enable_foreign_constraints(session, migrate_engine)
    session.execute('drop table temp_user;')


def upgrade_project_table_with_copy(meta, migrate_engine, session):
    # We want to add the domain_id attribute to the project table.  Since
    # it is non nullable and the table may have data, easiest way is
    # a table copy. Further, in order to keep foreign key constraints
    # pointing at the right table, we need to be able and do a table
    # DROP then CREATE, rather than ALTERing the name of the table.

    # Fist make a copy of the project table
    temp_project_table = sql.Table(
        'temp_project',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('description', sql.Text()),
        sql.Column('enabled', sql.Boolean, default=True))
    temp_project_table.create(migrate_engine, checkfirst=True)

    project_table = sql.Table('project', meta, autoload=True)
    for project in session.query(project_table):
        session.execute('insert into temp_project (id, name, extra, '
                        'description, enabled) '
                        'values ( :id, :name, :extra, '
                        ':description, :enabled);',
                        {'id': project.id,
                         'name': project.name,
                         'extra': project.extra,
                         'description': project.description,
                         'enabled': project.enabled})

    # Now switch off constraints while we drop and then re-create the
    # project table, with the additional domain_id column
    _disable_foreign_constraints(session, migrate_engine)
    session.execute('drop table project;')
    # Need to create a new metadata stream since we are going to load a
    # different version of the project table
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine
    domain_table = sql.Table('domain', meta2, autoload=True)
    project_table = sql.Table(
        'project',
        meta2,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('description', sql.Text()),
        sql.Column('enabled', sql.Boolean, default=True),
        sql.Column('domain_id', sql.String(64), sql.ForeignKey('domain.id'),
                   nullable=False),
        sql.UniqueConstraint('domain_id', 'name'))
    project_table.create(migrate_engine, checkfirst=True)

    # Finally copy in the data from our temp table and then clean
    # up by deleting our temp table
    for project in session.query(temp_project_table):
        session.execute('insert into project (id, name, extra, '
                        'description, enabled, domain_id) '
                        'values ( :id, :name, :extra, '
                        ':description, :enabled, :domain_id);',
                        {'id': project.id,
                         'name': project.name,
                         'extra': project.extra,
                         'description': project.description,
                         'enabled': project.enabled,
                         'domain_id': DEFAULT_DOMAIN_ID})
    _enable_foreign_constraints(session, migrate_engine)
    session.execute('drop table temp_project;')


def downgrade_user_table_with_copy(meta, migrate_engine, session):
    # For engines that don't support dropping columns, we need to do this
    # as a table copy.  Further, in order to keep foreign key constraints
    # pointing at the right table, we need to be able and do a table
    # DROP then CREATE, rather than ALTERing the name of the table.

    # Fist make a copy of the user table
    temp_user_table = sql.Table(
        'temp_user',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('password', sql.String(128)),
        sql.Column('enabled', sql.Boolean, default=True),
        sql.Column('extra', sql.Text()))
    temp_user_table.create(migrate_engine, checkfirst=True)

    user_table = sql.Table('user', meta, autoload=True)
    for user in session.query(user_table):
        session.execute('insert into temp_user (id, name, '
                        'password, enabled, extra) '
                        'values ( :id, :name, '
                        ':password, :enabled, :extra);',
                        {'id': user.id,
                         'name': user.name,
                         'password': user.password,
                         'enabled': user.enabled,
                         'extra': user.extra})

    # Now switch off constraints while we drop and then re-create the
    # user table, less the columns we wanted to drop
    _disable_foreign_constraints(session, migrate_engine)
    session.execute('drop table user;')
    # Need to create a new metadata stream since we are going to load a
    # different version of the user table
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine
    user_table = sql.Table(
        'user',
        meta2,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('password', sql.String(128)),
        sql.Column('enabled', sql.Boolean, default=True))
    user_table.create(migrate_engine, checkfirst=True)
    _enable_foreign_constraints(session, migrate_engine)

    # Finally copy in the data from our temp table and then clean
    # up by deleting our temp table
    for user in session.query(temp_user_table):
        session.execute('insert into user (id, name, extra, '
                        'password, enabled) '
                        'values ( :id, :name, :extra, '
                        ':password, :enabled);',
                        {'id': user.id,
                         'name': user.name,
                         'extra': user.extra,
                         'password': user.password,
                         'enabled': user.enabled})
    session.execute('drop table temp_user;')


def downgrade_project_table_with_copy(meta, migrate_engine, session):
    # For engines that don't support dropping columns, we need to do this
    # as a table copy.  Further, in order to keep foreign key constraints
    # pointing at the right table, we need to be able and do a table
    # DROP then CREATE, rather than ALTERing the name of the table.

    # Fist make a copy of the project table
    temp_project_table = sql.Table(
        'temp_project',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('description', sql.Text()),
        sql.Column('enabled', sql.Boolean, default=True),
        sql.Column('extra', sql.Text()))
    temp_project_table.create(migrate_engine, checkfirst=True)

    project_table = sql.Table('project', meta, autoload=True)
    for project in session.query(project_table):
        session.execute('insert into temp_project (id, name, '
                        'description, enabled, extra) '
                        'values ( :id, :name, '
                        ':description, :enabled, :extra);',
                        {'id': project.id,
                         'name': project.name,
                         'description': project.description,
                         'enabled': project.enabled,
                         'extra': project.extra})

    # Now switch off constraints while we drop and then re-create the
    # project table, less the columns we wanted to drop
    _disable_foreign_constraints(session, migrate_engine)
    session.execute('drop table project;')
    # Need to create a new metadata stream since we are going to load a
    # different version of the project table
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine
    project_table = sql.Table(
        'project',
        meta2,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), unique=True, nullable=False),
        sql.Column('extra', sql.Text()),
        sql.Column('description', sql.Text()),
        sql.Column('enabled', sql.Boolean, default=True))
    project_table.create(migrate_engine, checkfirst=True)
    _enable_foreign_constraints(session, migrate_engine)

    # Finally copy in the data from our temp table and then clean
    # up by deleting our temp table
    for project in session.query(temp_project_table):
        session.execute('insert into project (id, name, extra, '
                        'description, enabled) '
                        'values ( :id, :name, :extra, '
                        ':description, :enabled);',
                        {'id': project.id,
                         'name': project.name,
                         'extra': project.extra,
                         'description': project.description,
                         'enabled': project.enabled})
    session.execute("drop table temp_project;")


def upgrade_user_table_with_col_create(meta, migrate_engine, session):
    # Create the domain_id column.  We want this to be not nullable
    # but also a foreign key.  We can't create this right off the
    # bat since any existing rows would cause an Integrity Error.
    # We therefore create it nullable, fill the column with the
    # default data and then set it to non nullable.
    domain_table = sql.Table('domain', meta, autoload=True)
    user_table = sql.Table('user', meta, autoload=True)
    user_table.create_column(
        sql.Column('domain_id', sql.String(64),
                   sql.ForeignKey('domain.id'), nullable=True))
    for user in session.query(user_table).all():
        values = {'domain_id': DEFAULT_DOMAIN_ID}
        update = user_table.update().\
            where(user_table.c.id == user.id).\
            values(values)
        migrate_engine.execute(update)
    # Need to commit this or setting nullable to False will fail
    session.commit()
    user_table.columns.domain_id.alter(nullable=False)

    # Finally, change the uniqueness settings for the name attribute
    session.execute('ALTER TABLE "user" DROP CONSTRAINT user_name_key;')
    session.execute('ALTER TABLE "user" ADD CONSTRAINT user_dom_name_unique '
                    'UNIQUE (domain_id, name);')


def upgrade_project_table_with_col_create(meta, migrate_engine, session):
    # Create the domain_id column.  We want this to be not nullable
    # but also a foreign key.  We can't create this right off the
    # bat since any existing rows would cause an Integrity Error.
    # We therefore create it nullable, fill the column with the
    # default data and then set it to non nullable.
    domain_table = sql.Table('domain', meta, autoload=True)
    project_table = sql.Table('project', meta, autoload=True)
    project_table.create_column(
        sql.Column('domain_id', sql.String(64),
                   sql.ForeignKey('domain.id'), nullable=True))
    for project in session.query(project_table).all():
        values = {'domain_id': DEFAULT_DOMAIN_ID}
        update = project_table.update().\
            where(project_table.c.id == project.id).\
            values(values)
        migrate_engine.execute(update)
    # Need to commit this or setting nullable to False will fail
    session.commit()
    project_table.columns.domain_id.alter(nullable=False)

    # Finally, change the uniqueness settings for the name attribute
    session.execute('ALTER TABLE project DROP CONSTRAINT tenant_name_key;')
    session.execute('ALTER TABLE project ADD CONSTRAINT proj_dom_name_unique '
                    'UNIQUE (domain_id, name);')


def downgrade_user_table_with_col_drop(meta, migrate_engine, session):
    # Revert uniqueness settings for the name attribute
    session.execute('ALTER TABLE "user" DROP CONSTRAINT '
                    'user_dom_name_unique;')
    session.execute('ALTER TABLE "user" ADD UNIQUE (name);')
    session.commit()
    # And now go ahead an drop the domain_id column
    domain_table = sql.Table('domain', meta, autoload=True)
    user_table = sql.Table('user', meta, autoload=True)
    column = sql.Column('domain_id', sql.String(64),
                        sql.ForeignKey('domain.id'), nullable=False)
    column.drop(user_table)


def downgrade_project_table_with_col_drop(meta, migrate_engine, session):
    # Revert uniqueness settings for the name attribute
    session.execute('ALTER TABLE project DROP CONSTRAINT '
                    'proj_dom_name_unique;')
    session.execute('ALTER TABLE project ADD CONSTRAINT tenant_name_key '
                    'UNIQUE (name);')
    session.commit()
    # And now go ahead an drop the domain_id column
    domain_table = sql.Table('domain', meta, autoload=True)
    project_table = sql.Table('project', meta, autoload=True)
    column = sql.Column('domain_id', sql.String(64),
                        sql.ForeignKey('domain.id'), nullable=False)
    column.drop(project_table)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sessionmaker(bind=migrate_engine)()
    if migrate_engine.name in ['sqlite', 'mysql']:
        upgrade_user_table_with_copy(meta, migrate_engine, session)
        upgrade_project_table_with_copy(meta, migrate_engine, session)
    else:
        upgrade_user_table_with_col_create(meta, migrate_engine, session)
        upgrade_project_table_with_col_create(meta, migrate_engine, session)
    session.commit()
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sessionmaker(bind=migrate_engine)()
    if migrate_engine.name in ['sqlite', 'mysql']:
        downgrade_user_table_with_copy(meta, migrate_engine, session)
        downgrade_project_table_with_copy(meta, migrate_engine, session)
    else:
        # MySQL should in theory be able to use this path, but seems to
        # have problems dropping columns which are foreign keys
        downgrade_user_table_with_col_drop(meta, migrate_engine, session)
        downgrade_project_table_with_col_drop(meta, migrate_engine, session)
    session.commit()
    session.close()
