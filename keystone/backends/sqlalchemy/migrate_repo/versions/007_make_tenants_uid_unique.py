"""
Schema migration to enforce uniqueness on tenants.uid
"""
# pylint: disable=C0103,R0801


import sqlalchemy
import migrate
from migrate.changeset import constraint


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


unique_constraint = constraint.UniqueConstraint(tenant['uid'])


def upgrade(migrate_engine):
    meta.bind = migrate_engine

    tenant['uid'].alter(nullable=False)
    assert not tenants.c.uid.nullable

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
                'from `tenants`, UNIQUE (uid)'
        else:
            raise e

    tenant['uid'].alter(nullable=True)
    assert tenants.c.uid.nullable
