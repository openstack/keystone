# pylint: disable=C0103,R0801


import sqlalchemy
import migrate


meta = sqlalchemy.MetaData()


# define the previous state of tenants

tenant = {}
tenant['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
        autoincrement=True)
tenant['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
tenant['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
tenant['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
tenants = sqlalchemy.Table('tenants', meta, *tenant.values())


# this column will become unique/non-nullable after populating it
tenant_uid = sqlalchemy.Column('uid', sqlalchemy.String(255),
    unique=False, nullable=True)


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.create_column(tenant_uid, tenants)
    assert tenants.c.uid is tenant_uid


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.drop_column(tenant_uid, tenants)
    assert not hasattr(tenants.c, 'uid')
