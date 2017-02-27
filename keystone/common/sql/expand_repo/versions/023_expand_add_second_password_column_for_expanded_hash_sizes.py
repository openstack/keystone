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

    # NOTE(notmorgan): To support the full range of scrypt and pbkfd password
    # hash lengths, this should be closer to varchar(1500) instead of
    # varchar(255).
    password_hash = sql.Column('password_hash', sql.String(255), nullable=True)
    password_table = sql.Table('password', meta, autoload=True)
    password_table.create_column(password_hash)
