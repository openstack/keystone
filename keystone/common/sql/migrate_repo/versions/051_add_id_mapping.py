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

from keystone.identity.mapping_backends import mapping


MAPPING_TABLE = 'id_mapping'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    mapping_table = sql.Table(
        MAPPING_TABLE,
        meta,
        sql.Column('public_id', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('local_id', sql.String(64), nullable=False),
        sql.Column('entity_type', sql.Enum(
            mapping.EntityType.USER,
            mapping.EntityType.GROUP,
            name='entity_type'),
            nullable=False),
        sql.UniqueConstraint('domain_id', 'local_id', 'entity_type'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    mapping_table.create(migrate_engine, checkfirst=True)
