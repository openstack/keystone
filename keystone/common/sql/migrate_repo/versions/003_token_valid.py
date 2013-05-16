# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind

    meta = sql.MetaData()
    meta.bind = migrate_engine
    token = sql.Table('token', meta, autoload=True)
    # creating the column immediately with nullable=False fails with
    # PostgreSQL (LP 1068181), so do it in two steps instead
    valid = sql.Column(
        'valid', sql.Boolean(), sql.ColumnDefault(True), nullable=True)
    valid.create(token, populate_default=True)
    valid.alter(type=sql.Boolean(), default=True, nullable=False)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    token = sql.Table('token', meta, autoload=True)
    token.drop_column('valid')
