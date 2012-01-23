"""
Addresses bug 854425

Renames the 'token' table to 'tokens',
in order to appear more consistent with
other table names.
"""
# pylint: disable=C0103,R0801


import sqlalchemy


meta = sqlalchemy.MetaData()


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    # pylint: disable=E1101
    sqlalchemy.Table('token', meta).rename('tokens')


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    # pylint: disable=E1101
    sqlalchemy.Table('tokens', meta).rename('token')
