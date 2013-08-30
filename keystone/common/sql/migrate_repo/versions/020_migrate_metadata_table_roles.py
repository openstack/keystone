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
    sql.Table('role', meta, autoload=True)
    sql.Table('project', meta, autoload=True)
    new_metadata_table = sql.Table('user_project_metadata',
                                   meta,
                                   autoload=True)

    old_metadata_table = sql.Table('metadata', meta, autoload=True)
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(old_metadata_table):
        data = json.loads(metadata.data)
        if config.CONF.member_role_id not in metadata.data:
            data['roles'].append(config.CONF.member_role_id)

        r = session.query(new_metadata_table).filter_by(
            user_id=metadata.user_id,
            project_id=metadata.tenant_id).first()

        if r is not None:
            # roles should be the union of the two role lists
            old_roles = data['roles']
            new_roles = json.loads(r.data)['roles']
            data['roles'] = list(set(old_roles) | set(new_roles))
            q = new_metadata_table.update().where(
                new_metadata_table.c.user_id == metadata.user_id).where(
                    new_metadata_table.c.project_id ==
                    metadata.tenant_id).values(data=json.dumps(data))
        else:
            q = new_metadata_table.insert().values(
                user_id=metadata.user_id,
                project_id=metadata.tenant_id,
                data=json.dumps(data))

        session.execute(q)

    session.commit()
    old_metadata_table.drop()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        sql.Column(
            u'user_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            u'tenant_id',
            sql.String(64),
            primary_key=True),
        sql.Column('data',
                   sql.Text()))
    metadata_table.create(migrate_engine, checkfirst=True)

    user_project_metadata_table = sql.Table(
        'user_project_metadata',
        meta,
        autoload=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        autoload=True)

    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(user_project_metadata_table):
        if 'roles' in metadata:
            metadata_table.insert().values(
                user_id=metadata.user_id,
                tenant_id=metadata.project_id)

    session.close()
