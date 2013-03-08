import json
import uuid

import sqlalchemy as sql
from sqlalchemy import orm

from keystone import config
from keystone import exception


CONF = config.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    role_table = sql.Table('role', meta, autoload=True)
    # name should be 255 characters to match fresh database
    role_table.c.name.alter(type=sql.String(length=255))

    # blank 'extra' field should be "{}"
    none = None
    update = role_table.update().where(role_table.c.extra == none).values(
        {role_table.c.extra: "{}"})
    migrate_engine.execute(update)


def downgrade(migrate_engine):
    # this fixes bugs in migration 001 and 007 that result in discrepancies
    # between fresh databases and databases updated from 004 (folsom).
    # the changes fixing 007 will be rolled back in 007's rollback if
    # the user desires to return to a state before the existence of the extra
    # column.
    # the name length change reflects the current default and should not be
    # rolled back.
    pass
