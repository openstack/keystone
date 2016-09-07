# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime

import sqlalchemy as sql
import sqlalchemy.sql.expression as expression


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    password = sql.Table('password', meta, autoload=True)
    # reset created_at column
    password.c.created_at.drop()
    created_at = sql.Column('created_at', sql.DateTime(),
                            nullable=True,
                            default=datetime.datetime.utcnow)
    password.create_column(created_at)
    # update created_at value
    now = datetime.datetime.utcnow()
    values = {'created_at': now}
    stmt = password.update().where(
        password.c.created_at == expression.null()).values(values)
    stmt.execute()
    # set not nullable
    password.c.created_at.alter(nullable=False)
