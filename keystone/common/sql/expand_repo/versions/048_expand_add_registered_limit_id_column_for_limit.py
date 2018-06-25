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


def upgrade(migrate_engine):

    meta = sql.MetaData()
    meta.bind = migrate_engine
    registered_limit_table = sql.Table('registered_limit', meta, autoload=True)
    limit_table = sql.Table('limit', meta, autoload=True)

    registered_limit_id = sql.Column(
        'registered_limit_id', sql.String(64),
        sql.ForeignKey(registered_limit_table.c.id))
    limit_table.create_column(registered_limit_id)
