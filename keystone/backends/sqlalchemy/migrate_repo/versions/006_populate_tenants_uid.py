"""
Data migration to populate tenants.uid with existing tenants.id values.
"""
# pylint: disable=C0103,R0801


import sqlalchemy


meta = sqlalchemy.MetaData()


# define the previous state of tenants

tenant = {}
tenant['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
tenant['uid'] = sqlalchemy.Column('uid', sqlalchemy.String(255), unique=False,
    nullable=True)
tenant['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
tenant['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
tenant['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
tenants = sqlalchemy.Table('tenants', meta, *tenant.values())


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    dtenants = tenants.select().execute()
    for dtenant in dtenants:
        whereclause = "`id`='%s'" % (dtenant.id)
        values = {'uid': str(dtenant.id)}

        tenants.update(whereclause=whereclause, values=values).execute()


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    tenants.update(values={'uid': None}).execute()
