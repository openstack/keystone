# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

import sqlalchemy

from keystone.common.sql import migration_helpers


def list_constraints(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    user_table = sqlalchemy.Table('user', meta, autoload=True)
    sqlalchemy.Table('project', meta, autoload=True)
    group_table = sqlalchemy.Table('group', meta, autoload=True)
    user_domain_metadata_table = sqlalchemy.Table('user_domain_metadata',
                                                  meta, autoload=True)
    group_domain_metadata_table = sqlalchemy.Table('group_domain_metadata',
                                                   meta, autoload=True)
    user_project_metadata_table = sqlalchemy.Table('user_project_metadata',
                                                   meta, autoload=True)
    group_project_metadata_table = sqlalchemy.Table('group_project_metadata',
                                                    meta, autoload=True)

    constraints = [{'table': user_domain_metadata_table,
                    'fk_column': 'user_id',
                    'ref_column': user_table.c.id},
                   {'table': group_domain_metadata_table,
                    'fk_column': 'group_id',
                    'ref_column': group_table.c.id},
                   {'table': user_project_metadata_table,
                    'fk_column': 'user_id',
                    'ref_column': user_table.c.id},
                   {'table': group_project_metadata_table,
                    'fk_column': 'group_id',
                    'ref_column': group_table.c.id},
                   ]
    return constraints


def upgrade(migrate_engine):
    if migrate_engine.name == 'sqlite':
        return
    migration_helpers.remove_constraints(list_constraints(migrate_engine))


def downgrade(migrate_engine):
    if migrate_engine.name == 'sqlite':
        return
    migration_helpers.add_constraints(list_constraints(migrate_engine))
