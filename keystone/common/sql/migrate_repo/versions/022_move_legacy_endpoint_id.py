import json

import sqlalchemy as sql
from sqlalchemy import orm

from keystone import config


CONF = config.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table('endpoint', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for endpoint in session.query(endpoint_table).all():
        try:
            extra = json.loads(endpoint.extra)
            legacy_endpoint_id = extra.pop('legacy_endpoint_id')
        except KeyError:
            # if there is no legacy_endpoint_id, there's nothing to do
            pass
        else:
            q = endpoint_table.update()
            q = q.where(endpoint_table.c.id == endpoint.id)
            q = q.values({
                endpoint_table.c.extra: json.dumps(extra),
                endpoint_table.c.legacy_endpoint_id: legacy_endpoint_id})
            migrate_engine.execute(q)
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table('endpoint', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for endpoint in session.query(endpoint_table).all():
        if endpoint.legacy_endpoint_id is not None:
            extra = json.loads(endpoint.extra)
            extra['legacy_endpoint_id'] = endpoint.legacy_endpoint_id

            q = endpoint_table.update()
            q = q.where(endpoint_table.c.id == endpoint.id)
            q = q.values({
                endpoint_table.c.extra: json.dumps(extra),
                endpoint_table.c.legacy_endpoint_id: None})
            migrate_engine.execute(q)
    session.close()
