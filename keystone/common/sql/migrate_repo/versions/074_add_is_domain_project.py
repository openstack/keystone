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


_PROJECT_TABLE_NAME = 'project'
_IS_DOMAIN_COLUMN_NAME = 'is_domain'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    project_table = sql.Table(_PROJECT_TABLE_NAME, meta, autoload=True)
    is_domain = sql.Column(_IS_DOMAIN_COLUMN_NAME, sql.Boolean, nullable=False,
                           server_default='0', default=False)
    project_table.create_column(is_domain)
