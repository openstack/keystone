# pylint: disable=C0103,R0801


import sqlalchemy
import migrate


meta = sqlalchemy.MetaData()


# define the previous state of users

user = {}
user['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
user['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
user['password'] = sqlalchemy.Column('password', sqlalchemy.String(255))
user['email'] = sqlalchemy.Column('email', sqlalchemy.String(255))
user['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
user['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
users = sqlalchemy.Table('users', meta, *user.values())


# this column will become unique/non-nullable after populating it
user_uid = sqlalchemy.Column('uid', sqlalchemy.String(255),
    unique=False, nullable=True)


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.create_column(user_uid, users)
    assert users.c.uid is user_uid


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    migrate.drop_column(user_uid, users)
    assert not hasattr(users.c, 'uid')
