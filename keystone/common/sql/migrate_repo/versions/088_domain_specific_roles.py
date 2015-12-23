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

_ROLE_NAME_OLD_CONSTRAINT = 'ixu_role_name'
_ROLE_NAME_NEW_CONSTRAINT = 'ixu_role_name_domain_id'
_ROLE_TABLE_NAME = 'role'
_DOMAIN_ID_COLUMN_NAME = 'domain_id'
_NULL_DOMAIN_ID = '<<null>>'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    role_table = sql.Table(_ROLE_TABLE_NAME, meta, autoload=True)
    domain_id = sql.Column(_DOMAIN_ID_COLUMN_NAME, sql.String(64),
                           nullable=False, server_default=_NULL_DOMAIN_ID)
    role_table.create_column(domain_id)

    migrate.UniqueConstraint(role_table.c.name,
                             name=_ROLE_NAME_OLD_CONSTRAINT).drop()

    migrate.UniqueConstraint(role_table.c.name,
                             role_table.c.domain_id,
                             name=_ROLE_NAME_NEW_CONSTRAINT).create()
