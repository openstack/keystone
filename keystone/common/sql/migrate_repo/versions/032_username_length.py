import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)
    user_table.c.name.alter(type=sql.String(255))


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)
    if migrate_engine.name != 'mysql':
        # NOTE(aloga): sqlite does not enforce length on the
        # VARCHAR types: http://www.sqlite.org/faq.html#q9
        # postgresql and DB2 do not truncate.
        maker = sessionmaker(bind=migrate_engine)
        session = maker()
        for user in session.query(user_table).all():
            values = {'name': user.name[:64]}
            update = (user_table.update().
                      where(user_table.c.id == user.id).
                      values(values))
            migrate_engine.execute(update)

        session.commit()
        session.close()
    user_table.c.name.alter(type=sql.String(64))
