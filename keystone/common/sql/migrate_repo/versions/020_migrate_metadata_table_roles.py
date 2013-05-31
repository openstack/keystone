import json
import uuid

import sqlalchemy as sql
from sqlalchemy import orm

from keystone import config
from keystone import exception


CONF = config.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    role_table = sql.Table('role', meta, autoload=True)
    project_table = sql.Table('project', meta, autoload=True)
    new_metadata_table = sql.Table('user_project_metadata',
                                   meta,
                                   autoload=True)

    old_metadata_table = sql.Table('metadata', meta, autoload=True)
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(old_metadata_table):
        if not config.CONF.member_role_id in metadata.data:
            data = json.loads(metadata.data)
            data['roles'].append(config.CONF.member_role_id)
        else:
            data = metadata.data

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

    user_table = sql.Table('user', meta, autoload=True)
    project_table = sql.Table('project', meta, autoload=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        sql.Column(
            'user_id',
            sql.String(64),
            sql.ForeignKey('user.id'),
            primary_key=True),
        sql.Column(
            'tenant_id',
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
            roles = json.loads(metadata.data)
            ins = (metadata_table.insert()
                   .values(user_id=metadata.user_id,
                           tenant_id=metadata.project_id))

    session.close()
