
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

import sqlalchemy
from sqlalchemy.orm import sessionmaker


def upgrade(migrate_engine):
    if migrate_engine.name == 'sqlite':
        drop_credential_table_foreign_key_constraints_for_sqlite(
            migrate_engine)


def downgrade(migrate_engine):
    if migrate_engine.name == 'sqlite':
        add_credential_table_foreign_key_constraints_for_sqlite(migrate_engine)


def drop_credential_table_foreign_key_constraints_for_sqlite(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    # NOTE(nachiappan): SQLite does not support ALTER TABLE DROP constraint.
    #                   So we need to move the data to new credenital table
    #                   created without constraints, drop the old table and
    #                   rename the new table to credential.
    sqlalchemy.Table('user', meta, autoload=True)
    tenant_table = sqlalchemy.Table(
        'tenant',
        meta,
        sqlalchemy.Column('id', sqlalchemy.String(64), primary_key=True),
        sqlalchemy.Column(
            'name', sqlalchemy.String(64), unique=True, nullable=False),
        sqlalchemy.Column('extra', sqlalchemy.Text()))
    tenant_table.create(migrate_engine, checkfirst=True)
    cred_table = sqlalchemy.Table('credential', meta, autoload=True)

    session = sessionmaker(bind=migrate_engine)()
    new_credential_table = sqlalchemy.Table(
        'new_credential',
        meta,
        sqlalchemy.Column('id', sqlalchemy.String(64), primary_key=True),
        sqlalchemy.Column('user_id',
                          sqlalchemy.String(64),
                          nullable=False),
        sqlalchemy.Column('project_id',
                          sqlalchemy.String(64)),
        sqlalchemy.Column('blob', sqlalchemy.Text(), nullable=False),
        sqlalchemy.Column('type', sqlalchemy.String(255), nullable=False),
        sqlalchemy.Column('extra', sqlalchemy.Text()))
    new_credential_table.create(migrate_engine, checkfirst=True)

    insert = new_credential_table.insert()
    for credential in session.query(cred_table):
        insert.execute({'id': credential.id,
                        'user_id': credential.user_id,
                        'project_id': credential.project_id,
                        'blob': credential.blob,
                        'type': credential.type,
                        'extra': credential.extra})
    cred_table.drop()
    tenant_table.drop()
    new_credential_table.rename('credential')
    session.commit()
    session.close()


def add_credential_table_foreign_key_constraints_for_sqlite(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    cred_table = sqlalchemy.Table('credential', meta, autoload=True)
    sqlalchemy.Table('user', meta, autoload=True)

    session = sessionmaker(bind=migrate_engine)()
    old_credential_table = sqlalchemy.Table(
        'old_credential',
        meta,
        sqlalchemy.Column('id', sqlalchemy.String(64), primary_key=True),
        sqlalchemy.Column('user_id',
                          sqlalchemy.String(64),
                          sqlalchemy.ForeignKey('user.id'),
                          nullable=False),
        # NOTE(nachiappan): Not creating the foreign key constraint with
        #                   project  table as version 15 conflicts with
        #                   version 7.
        sqlalchemy.Column('project_id',
                          sqlalchemy.String(64)),
        sqlalchemy.Column('blob', sqlalchemy.Text(), nullable=False),
        sqlalchemy.Column('type', sqlalchemy.String(255), nullable=False),
        sqlalchemy.Column('extra', sqlalchemy.Text()))
    old_credential_table.create(migrate_engine, checkfirst=True)

    insert = old_credential_table.insert()
    for credential in session.query(cred_table):
        insert.execute({'id': credential.id,
                        'user_id': credential.user_id,
                        'project_id': credential.project_id,
                        'blob': credential.blob,
                        'type': credential.type,
                        'extra': credential.extra})
    cred_table.drop()
    old_credential_table.rename('credential')
    session.commit()
    session.close()
