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

    user = sql.Table('user', meta, autoload=True)

    local_user = sql.Table(
        'local_user',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('user_id', sql.String(64),
                   sql.ForeignKey(user.c.id, ondelete='CASCADE'),
                   nullable=False, unique=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('name', sql.String(255), nullable=False),
        sql.UniqueConstraint('domain_id', 'name'))
    local_user.create(migrate_engine, checkfirst=True)

    password = sql.Table(
        'password',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('local_user_id', sql.Integer,
                   sql.ForeignKey(local_user.c.id, ondelete='CASCADE'),
                   nullable=False),
        sql.Column('password', sql.String(128), nullable=False))
    password.create(migrate_engine, checkfirst=True)
