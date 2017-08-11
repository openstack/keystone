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

import datetime

import pytz
import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


_epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)


def _convert_value_datetime_to_int(dt):
    dt = dt.replace(tzinfo=pytz.utc)
    return int((dt - _epoch).total_seconds() * 1000000)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    maker = sessionmaker(bind=migrate_engine)
    session = maker()

    password_table = sql.Table('password', meta, autoload=True)
    passwords = list(password_table.select().execute())

    for passwd in passwords:
        values = {
            'created_at_int': _convert_value_datetime_to_int(passwd.created_at)
        }

        if passwd.expires_at is not None:
            values['expires_at_int'] = _convert_value_datetime_to_int(
                passwd.expires_at)

        update = password_table.update().where(
            password_table.c.id == passwd.id).values(values)
        session.execute(update)
        session.commit()

    password_table = sql.Table('password', meta, autoload=True)
    # The created_at_int data cannot really be nullable long term. This
    # corrects the data to be not nullable, but must be done in the contract
    # phase for two reasons. The first is due to "additive only" requirements.
    # The second is because we need to ensure all nodes in the deployment are
    # running the Pike code-base before we migrate all password entries. This
    # avoids locking the password table or having a partial outage while doing
    # the migration.
    password_table.c.created_at_int.alter(nullable=False, default=0,
                                          server_default='0')
    session.close()
