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


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    password = sql.Table('password', meta, autoload=True)
    # Because it's difficult to get a timestamp server default working among
    # all of the supported databases and versions, I'm choosing to drop and
    # then recreate the column as I think this is a more cleaner option. This
    # will only impact operators that have already deployed the 105 migration;
    # resetting the password created_at for security compliance features, if
    # enabled.
    password.c.created_at.drop()
    # sqlite doesn't support server_default=sql.func.now(), so skipping.
    if migrate_engine.name == 'sqlite':
        created_at = sql.Column('created_at', sql.TIMESTAMP, nullable=True)
    else:
        # Changing type to timestamp as mysql 5.5 and older doesn't support
        # datetime defaults.
        created_at = sql.Column('created_at', sql.TIMESTAMP, nullable=False,
                                default=datetime.datetime.utcnow,
                                server_default=sql.func.now())
    password.create_column(created_at)
