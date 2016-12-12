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

import sqlalchemy as sql
import sqlalchemy.sql.expression as expression


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)

    # update user domain_id from local_user
    local_table = sql.Table('local_user', meta, autoload=True)
    _update_user_domain_id(migrate_engine, user_table, local_table)

    # update user domain_id from nonlocal_user
    nonlocal_table = sql.Table('nonlocal_user', meta, autoload=True)
    _update_user_domain_id(migrate_engine, user_table, nonlocal_table)


def _update_user_domain_id(migrate_engine, user_table, child_user_table):
    join = sql.join(user_table, child_user_table,
                    user_table.c.id == child_user_table.c.user_id)
    where = user_table.c.domain_id == expression.null()
    sel = (
        sql.select([user_table.c.id, child_user_table.c.domain_id])
           .select_from(join).where(where)
    )
    with migrate_engine.begin() as conn:
        for user in conn.execute(sel):
            values = {'domain_id': user['domain_id']}
            stmt = user_table.update().where(
                user_table.c.id == user['id']).values(values)
            conn.execute(stmt)
