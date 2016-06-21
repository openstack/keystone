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


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    idp_table = sql.Table('identity_provider', meta, autoload=True)
    protocol_table = sql.Table('federation_protocol', meta, autoload=True)

    federated_table = sql.Table(
        'federated_user',
        meta,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('user_id', sql.String(64),
                   sql.ForeignKey(user_table.c.id, ondelete='CASCADE'),
                   nullable=False),
        sql.Column('idp_id', sql.String(64),
                   sql.ForeignKey(idp_table.c.id, ondelete='CASCADE'),
                   nullable=False),
        sql.Column('protocol_id', sql.String(64), nullable=False),
        sql.Column('unique_id', sql.String(255), nullable=False),
        sql.Column('display_name', sql.String(255), nullable=True),
        sql.UniqueConstraint('idp_id', 'protocol_id', 'unique_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    federated_table.create(migrate_engine, checkfirst=True)

    migrate.ForeignKeyConstraint(
        columns=[federated_table.c.protocol_id, federated_table.c.idp_id],
        refcolumns=[protocol_table.c.id, protocol_table.c.idp_id]).create()
