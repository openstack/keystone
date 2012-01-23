"""
Schema migration to enforce uniqueness on users.uid
"""
# pylint: disable=C0103,R0801


import sqlalchemy
import migrate
from migrate.changeset import constraint


meta = sqlalchemy.MetaData()


# define the previous state of users

user = {}
user['id'] = sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True,
    autoincrement=True)
user['uid'] = sqlalchemy.Column('uid', sqlalchemy.String(255), unique=False,
    nullable=True)
user['name'] = sqlalchemy.Column('name', sqlalchemy.String(255), unique=True)
user['password'] = sqlalchemy.Column('password', sqlalchemy.String(255))
user['email'] = sqlalchemy.Column('email', sqlalchemy.String(255))
user['enabled'] = sqlalchemy.Column('enabled', sqlalchemy.Integer)
user['tenant_id'] = sqlalchemy.Column('tenant_id', sqlalchemy.Integer)
users = sqlalchemy.Table('users', meta, *user.values())

unique_constraint = constraint.UniqueConstraint(user['uid'])


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    user['uid'].alter(nullable=False)
    assert not users.c.uid.nullable

    unique_constraint.create()


def downgrade(migrate_engine):
    meta.bind = migrate_engine

    try:
        # this is NOT supported in sqlite!
        # but let's try anyway, in case it is
        unique_constraint.drop()
    except migrate.exceptions.NotSupportedError, e:
        if migrate_engine.name == 'sqlite':
            # skipping the constraint drop doesn't seem to cause any issues
            # *in sqlite*
            # as constraints are only checked on row insert/update,
            # and don't apply to nulls.
            print 'WARNING: Skipping dropping unique constraint ' \
                'from `users`, UNIQUE (uid)'
        else:
            raise e

    user['uid'].alter(nullable=True)
    assert users.c.uid.nullable
