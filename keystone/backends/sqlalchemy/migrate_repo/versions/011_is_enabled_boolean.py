"""
Change 'enabled' columns to boolean types
"""
# pylint: disable=C0103,R0801


import sqlalchemy
from migrate.changeset import constraint


meta = sqlalchemy.MetaData()


# define the previous state of users

user = {}
user['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
user['uid'] = sqlalchemy.Column('uid', sqlalchemy.String(255), unique=False,
    nullable=False)
user['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
user['password'] = sqlalchemy.Column('password', sqlalchemy.String(255))
user['email'] = sqlalchemy.Column('email', sqlalchemy.String(255))
user['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
user['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
users = sqlalchemy.Table('users', meta, *user.values())
constraint.UniqueConstraint(user['uid'])

tenant = {}
tenant['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
tenant['uid'] = sqlalchemy.Column('uid', sqlalchemy.String(255), unique=False,
    nullable=False)
tenant['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
tenant['desc'] = sqlalchemy.Column('desc', sqlalchemy.String(255))
tenant['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
tenants = sqlalchemy.Table('tenants', meta, *tenant.values())
constraint.UniqueConstraint(tenant['uid'])


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    user['enabled'].alter(type=sqlalchemy.Boolean)
    assert users.c.enabled is user['enabled']

    tenant['enabled'].alter(type=sqlalchemy.Boolean)
    assert tenants.c.enabled is tenant['enabled']


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    user['enabled'].alter(type=sqlalchemy.Integer)
    assert users.c.enabled is user['enabled']

    tenant['enabled'].alter(type=sqlalchemy.Integer)
    assert tenants.c.enabled is tenant['enabled']
