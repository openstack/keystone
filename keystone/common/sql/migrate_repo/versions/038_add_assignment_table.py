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

from keystone.assignment.backends import sql as assignment_sql

ASSIGNMENT_TABLE = 'assignment'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('role', meta, autoload=True)
    assignment_table = sql.Table(
        ASSIGNMENT_TABLE,
        meta,
        sql.Column('type', sql.Enum(
            assignment_sql.AssignmentType.USER_PROJECT,
            assignment_sql.AssignmentType.GROUP_PROJECT,
            assignment_sql.AssignmentType.USER_DOMAIN,
            assignment_sql.AssignmentType.GROUP_DOMAIN,
            name='type'),
            nullable=False),
        sql.Column('actor_id', sql.String(64), nullable=False),
        sql.Column('target_id', sql.String(64), nullable=False),
        sql.Column('role_id', sql.String(64), sql.ForeignKey('role.id'),
                   nullable=False),
        sql.Column('inherited', sql.Boolean, default=False, nullable=False),
        sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id', 'role_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    assignment_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    assignment = sql.Table(ASSIGNMENT_TABLE, meta, autoload=True)
    assignment.drop(migrate_engine, checkfirst=True)
