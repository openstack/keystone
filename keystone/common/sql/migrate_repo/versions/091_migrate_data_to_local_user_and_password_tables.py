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

import migrate
import sqlalchemy as sql
from sqlalchemy import func


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    local_user_table = sql.Table('local_user', meta, autoload=True)
    password_table = sql.Table('password', meta, autoload=True)

    # migrate data to local_user table
    local_user_values = []
    for row in user_table.select().execute():
        # skip the row that already exists in `local_user`, this could
        # happen if run into a partially-migrated table due to the
        # bug #1549705.
        filter_by = local_user_table.c.user_id == row['id']
        user_count = sql.select([func.count()]).select_from(
            local_user_table).where(filter_by).execute().fetchone()[0]
        if user_count == 0:
            local_user_values.append({'user_id': row['id'],
                                      'domain_id': row['domain_id'],
                                      'name': row['name']})
    if local_user_values:
        local_user_table.insert().values(local_user_values).execute()

    # migrate data to password table
    sel = (
        sql.select([user_table, local_user_table], use_labels=True)
           .select_from(user_table.join(local_user_table, user_table.c.id ==
                                        local_user_table.c.user_id))
    )
    user_rows = sel.execute()
    password_values = []
    for row in user_rows:
        if row['user_password']:
            password_values.append({'local_user_id': row['local_user_id'],
                                    'password': row['user_password']})
    if password_values:
        password_table.insert().values(password_values).execute()

    # remove domain_id and name unique constraint
    if migrate_engine.name != 'sqlite':
        migrate.UniqueConstraint(user_table.c.domain_id,
                                 user_table.c.name,
                                 name='ixu_user_name_domain_id').drop()

    # drop user columns
    user_table.c.domain_id.drop()
    user_table.c.name.drop()
    user_table.c.password.drop()
