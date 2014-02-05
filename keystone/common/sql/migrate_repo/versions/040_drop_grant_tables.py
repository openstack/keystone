# Copyright 2014 IBM Corp.
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

import sqlalchemy as sql

USER_PROJECT_TABLE = 'user_project_metadata'
GROUP_PROJECT_TABLE = 'group_project_metadata'
USER_DOMAIN_TABLE = 'user_domain_metadata'
GROUP_DOMAIN_TABLE = 'group_domain_metadata'

GRANT_TABLES = [USER_PROJECT_TABLE, USER_DOMAIN_TABLE,
                GROUP_PROJECT_TABLE, GROUP_DOMAIN_TABLE]


def recreate_grant_tables(meta, migrate_engine):
    sql.Table('user', meta, autoload=True)
    sql.Table('group', meta, autoload=True)
    sql.Table('project', meta, autoload=True)
    sql.Table('domain', meta, autoload=True)

    user_project_metadata_table = sql.Table(
        USER_PROJECT_TABLE,
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    user_project_metadata_table.create(migrate_engine, checkfirst=True)

    group_project_metadata_table = sql.Table(
        GROUP_PROJECT_TABLE,
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    group_project_metadata_table.create(migrate_engine, checkfirst=True)

    user_domain_metadata_table = sql.Table(
        USER_DOMAIN_TABLE,
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'domain_id',
            sql.String(64),
            sql.ForeignKey('domain.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    user_domain_metadata_table.create(migrate_engine, checkfirst=True)

    group_domain_metadata_table = sql.Table(
        GROUP_DOMAIN_TABLE,
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'domain_id',
            sql.String(64),
            sql.ForeignKey('domain.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    group_domain_metadata_table.create(migrate_engine, checkfirst=True)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    for table_name in GRANT_TABLES:
        grant_table = sql.Table(table_name, meta, autoload=True)
        grant_table.drop(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    recreate_grant_tables(meta, migrate_engine)
