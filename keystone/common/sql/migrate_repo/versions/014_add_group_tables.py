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

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('domain', meta, autoload=True)
    group_table = sql.Table(
        'group',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), sql.ForeignKey('domain.id'),
                   nullable=False),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('description', sql.Text()),
        sql.Column('extra', sql.Text()),
        sql.UniqueConstraint('domain_id', 'name'))
    group_table.create(migrate_engine, checkfirst=True)

    sql.Table('user', meta, autoload=True)
    user_group_membership_table = sql.Table(
        'user_group_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'group_id',
            sql.String(64),
            sql.ForeignKey('group.id'),
            primary_key=True))
    user_group_membership_table.create(migrate_engine, checkfirst=True)

    sql.Table('tenant', meta, autoload=True)
    group_project_metadata_table = sql.Table(
        'group_project_metadata',
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            sql.ForeignKey('group.id'),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('tenant.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    group_project_metadata_table.create(migrate_engine, checkfirst=True)

    group_domain_metadata_table = sql.Table(
        'group_domain_metadata',
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            sql.ForeignKey('group.id'),
            primary_key=True),
        sql.Column(
            'domain_id',
            sql.String(64),
            sql.ForeignKey('domain.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    group_domain_metadata_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    tables = ['user_group_membership', 'group_project_metadata',
              'group_domain_metadata', 'group']
    for t in tables:
        table = sql.Table(t, meta, autoload=True)
        table.drop(migrate_engine, checkfirst=True)
