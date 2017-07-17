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

    project_table = sql.Table('project', meta, autoload=True)

    # NOTE(lamt) To allow tag name to be case sensitive for MySQL, the 'name'
    # column needs to use collation, which is incompatible with Postgresql.
    # Using unicode to mirror nova's server tag:
    # https://github.com/openstack/nova/blob/master/nova/db/sqlalchemy/models.py
    project_tags_table = sql.Table(
        'project_tag',
        meta,
        sql.Column('project_id',
                   sql.String(64),
                   sql.ForeignKey(project_table.c.id, ondelete='CASCADE'),
                   nullable=False,
                   primary_key=True),
        sql.Column('name',
                   sql.Unicode(255),
                   nullable=False,
                   primary_key=True),
        sql.UniqueConstraint('project_id', 'name'),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    project_tags_table.create(migrate_engine, checkfirst=True)
