import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    token = sql.Table('token', meta, autoload=True)
    idx = sql.Index('ix_token_valid', token.c.valid)
    idx.create(migrate_engine)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    token = sql.Table('token', meta, autoload=True)
    idx = sql.Index('ix_token_valid', token.c.valid)
    idx.drop(migrate_engine)
