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

    identity_provider = sql.Table('identity_provider', meta, autoload=True)
    authorization_ttl = sql.Column('authorization_ttl', sql.Integer,
                                   nullable=True)
    identity_provider.create_column(authorization_ttl)

    user_table = sql.Table('user', meta, autoload=True)
    group_table = sql.Table('group', meta, autoload=True)
    idp_table = sql.Table('identity_provider', meta, autoload=True)

    expiring_user_group_membership = sql.Table(
        'expiring_user_group_membership', meta,

        sql.Column('user_id', sql.String(64),
                   sql.ForeignKey(user_table.c.id), primary_key=True),
        sql.Column('group_id', sql.String(64),
                   sql.ForeignKey(group_table.c.id), primary_key=True),
        sql.Column('idp_id',
                   sql.String(64),
                   sql.ForeignKey(idp_table.c.id,
                                  ondelete='CASCADE'),
                   primary_key=True),
        sql.Column('last_verified', sql.DateTime(), nullable=False),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    expiring_user_group_membership.create(migrate_engine, checkfirst=True)
