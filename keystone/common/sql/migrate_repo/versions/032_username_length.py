# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

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
