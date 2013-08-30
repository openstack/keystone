# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json

import sqlalchemy as sql

from keystone import config


CONF = config.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)
    role_table = sql.Table('role', meta, autoload=True)

    user_project_role_table = sql.Table(
        'user_project_metadata',
        meta,
        sql.Column('user_id',
                   sql.String(64),
                   sql.ForeignKey('user.id'),
                   primary_key=True),
        sql.Column('project_id',
                   sql.String(64),
                   sql.ForeignKey('project.id'),
                   primary_key=True),
        sql.Column('data', sql.Text()))
    user_project_role_table.create(migrate_engine, checkfirst=True)

    conn = migrate_engine.connect()
    conn.execute(role_table.insert(),
                 id=CONF.member_role_id,
                 name=CONF.member_role_name,
                 extra=json.dumps({'description':
                                   'Default role for project membership',
                                   'enabled': 'True'}))

    user_project_membership_table = sql.Table('user_project_membership',
                                              meta, autoload=True)
    session = sql.orm.sessionmaker(bind=migrate_engine)()
    for membership in session.query(user_project_membership_table):
        data = {'roles': [config.CONF.member_role_id]}
        ins = user_project_role_table.insert().values(
            user_id=membership.user_id,
            project_id=membership.tenant_id,
            data=json.dumps(data))
        conn.execute(ins)
    session.close()
    user_project_membership_table.drop()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)

    user_project_membership_table = sql.Table(
        'user_project_membership',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'tenant_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True))
    user_project_membership_table.create(migrate_engine, checkfirst=True)

    user_project_metadata_table = sql.Table(
        'user_project_metadata',
        meta,
        autoload=True)

    session = sql.orm.sessionmaker(bind=migrate_engine)()
    for membership in session.query(user_project_metadata_table):
        if 'roles' in membership:
            roles = membership['roles']
            if config.CONF.member_role_id in roles:
                user_project_membership_table.insert().values(
                    user_id=membership.user_id,
                    tenant_id=membership.project_id)
    session.close()
    role_table = sql.Table('role', meta, autoload=True)
    conn = migrate_engine.connect()
    user_project_membership_table = sql.Table(
        'user_project_membership', meta, autoload=True)

    role_table = sql.Table('role', meta, autoload=True)
    conn.execute(role_table.delete().where(role_table.c.id ==
                                           config.CONF.member_role_id))
    user_project_metadata_table.drop()
