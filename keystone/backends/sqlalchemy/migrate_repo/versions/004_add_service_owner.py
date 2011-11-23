"""
Adds support for owner id in services
"""
# pylint: disable=C0103


import sqlalchemy
import migrate


meta = sqlalchemy.MetaData()

service = {}
service['id'] = sqlalchemy.Column('id', sqlalchemy.Integer,
        primary_key=True, autoincrement=True)
service['name'] = sqlalchemy.Column('name', sqlalchemy.String(255),
        unique=True)
service['type'] = sqlalchemy.Column('type', sqlalchemy.String(255))
service['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
services = sqlalchemy.Table('services', meta, *service.values())

owner_id = sqlalchemy.Column('owner_id', sqlalchemy.Integer,
        nullable=True)

sqlalchemy.UniqueConstraint(service['name'])


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.create_column(owner_id, services)
    assert services.c.owner_id is owner_id


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.drop_column(owner_id, services)
    assert not hasattr(services.c, 'owner_id')
