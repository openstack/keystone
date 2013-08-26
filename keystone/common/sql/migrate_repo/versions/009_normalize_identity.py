# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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


from sqlalchemy import Column, MetaData, String, Table, Text, types
from sqlalchemy.orm import sessionmaker


#sqlite doesn't support dropping columns. Copy to a new table instead
def downgrade_user_table_with_copy(meta, migrate_engine):
    maker = sessionmaker(bind=migrate_engine)
    session = maker()
    session.execute("ALTER TABLE user RENAME TO orig_user;")

    user_table = Table(
        'user',
        meta,
        Column('id', String(64), primary_key=True),
        Column('name', String(64), unique=True, nullable=False),
        Column('extra', Text()))
    user_table.create(migrate_engine, checkfirst=True)

    orig_user_table = Table('orig_user', meta, autoload=True)
    for user in session.query(orig_user_table):
        session.execute("insert into user (id, name, extra) "
                        "values ( :id, :name, :extra);",
                        {'id': user.id,
                         'name': user.name,
                         'extra': user.extra})
    session.execute("drop table orig_user;")
    session.close()


def downgrade_tenant_table_with_copy(meta, migrate_engine):
    maker = sessionmaker(bind=migrate_engine)
    session = maker()
    session.execute("ALTER TABLE tenant RENAME TO orig_tenant;")

    tenant_table = Table(
        'tenant',
        meta,
        Column('id', String(64), primary_key=True),
        Column('name', String(64), unique=True, nullable=False),
        Column('extra', Text()))
    tenant_table.create(migrate_engine, checkfirst=True)

    orig_tenant_table = Table('orig_tenant', meta, autoload=True)
    for tenant in session.query(orig_tenant_table):
        session.execute("insert into tenant (id, name, extra) "
                        "values ( :id, :name, :extra);",
                        {'id': tenant.id,
                         'name': tenant.name,
                         'extra': tenant.extra})
    session.execute("drop table orig_tenant;")
    session.close()


def downgrade_user_table_with_column_drop(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    user_table.drop_column(Column('password', String(128)))
    user_table.drop_column(Column('enabled', types.Boolean,
                                  default=True))


def downgrade_tenant_table_with_column_drop(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)
    tenant_table.drop_column(Column('description', Text()))
    tenant_table.drop_column(Column('enabled', types.Boolean))


def upgrade_user_table(meta, migrate_engine):
    user_table = Table('user', meta, autoload=True)
    user_table.create_column(Column('password', String(128)))
    user_table.create_column(Column('enabled', types.Boolean,
                                    default=True))


def upgrade_tenant_table(meta, migrate_engine):
    tenant_table = Table('tenant', meta, autoload=True)
    tenant_table.create_column(Column('description', Text()))
    tenant_table.create_column(Column('enabled', types.Boolean))


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    upgrade_user_table(meta, migrate_engine)
    upgrade_tenant_table(meta, migrate_engine)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    if migrate_engine.name == 'sqlite':
        downgrade_user_table_with_copy(meta, migrate_engine)
        downgrade_tenant_table_with_copy(meta, migrate_engine)
    else:
        downgrade_user_table_with_column_drop(meta, migrate_engine)
        downgrade_tenant_table_with_column_drop(meta, migrate_engine)
