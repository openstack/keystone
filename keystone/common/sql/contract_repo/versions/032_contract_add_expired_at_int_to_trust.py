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

from migrate import UniqueConstraint
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

    trust_table = sql.Table('trust', meta, autoload=True)
    trusts = list(trust_table.select().execute())

    for trust in trusts:
        values = {}
        if trust.expires_at is not None:
            values['expires_at_int'] = _convert_value_datetime_to_int(
                trust.expires_at)

            update = trust_table.update().where(
                trust_table.c.id == trust.id).values(values)
            session.execute(update)
            session.commit()

    UniqueConstraint(table=trust_table,
                     name='duplicate_trust_constraint').drop()
    session.close()
