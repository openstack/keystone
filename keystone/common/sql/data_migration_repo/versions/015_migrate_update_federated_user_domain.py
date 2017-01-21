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
    federated_table = sql.Table('federated_user', meta, autoload=True)
    idp_table = sql.Table('identity_provider', meta, autoload=True)

    join = sql.join(federated_table, idp_table,
                    federated_table.c.idp_id == idp_table.c.id)
    sel = sql.select(
        [federated_table.c.user_id, idp_table.c.domain_id]).select_from(join)
    with migrate_engine.begin() as conn:
        for user in conn.execute(sel):
            values = {'domain_id': user['domain_id']}
            stmt = user_table.update().where(
                sql.and_(
                    user_table.c.domain_id == expression.null(),
                    user_table.c.id == user['user_id'])).values(values)
            conn.execute(stmt)
