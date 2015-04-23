# Copyright 2014 IBM Corp.
#
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


_REGION_TABLE_NAME = 'region'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    region_table = sql.Table(_REGION_TABLE_NAME, meta, autoload=True)
    url_column = sql.Column('url', sql.String(255), nullable=True)
    region_table.create_column(url_column)
