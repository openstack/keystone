# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

import json

import sqlalchemy as sql


def build_update(table_name, upgrade_table, row, values):
    if table_name == 'user_project_metadata':
        update = upgrade_table.update().where(
            upgrade_table.c.user_id == row.user_id).where(
                upgrade_table.c.project_id == row.project_id).values(values)
    elif table_name == 'group_project_metadata':
        update = upgrade_table.update().where(
            upgrade_table.c.group_id == row.group_id).where(
                upgrade_table.c.project_id == row.project_id).values(values)
    elif table_name == 'user_domain_metadata':
        update = upgrade_table.update().where(
            upgrade_table.c.user_id == row.user_id).where(
                upgrade_table.c.domain_id == row.domain_id).values(values)
    else:
        update = upgrade_table.update().where(
            upgrade_table.c.group_id == row.group_id).where(
                upgrade_table.c.domain_id == row.domain_id).values(values)
    return update


def upgrade_grant_table(meta, migrate_engine, session, table_name):

    # Convert the roles component of the metadata from a list
    # of ids to a list of dicts

    def list_to_dict_list(metadata):
        json_metadata = json.loads(metadata)
        if 'roles' in json_metadata:
            json_metadata['roles'] = (
                [{'id': x} for x in json_metadata['roles']])
        return json.dumps(json_metadata)

    upgrade_table = sql.Table(table_name, meta, autoload=True)
    for assignment in session.query(upgrade_table):
        values = {'data': list_to_dict_list(assignment.data)}
        update = build_update(table_name, upgrade_table, assignment, values)
        migrate_engine.execute(update)


def downgrade_grant_table(meta, migrate_engine, session, table_name):

    # Convert the roles component of the metadata from a list
    # of dicts to a simple list of ids.  Any inherited roles are deleted
    # since they would have no meaning

    def dict_list_to_list(metadata):
        json_metadata = json.loads(metadata)
        if 'roles' in json_metadata:
            json_metadata['roles'] = ([x['id'] for x in json_metadata['roles']
                                      if 'inherited_to' not in x])
        return json.dumps(json_metadata)

    downgrade_table = sql.Table(table_name, meta, autoload=True)
    for assignment in session.query(downgrade_table):
        values = {'data': dict_list_to_list(assignment.data)}
        update = build_update(table_name, downgrade_table, assignment, values)
        migrate_engine.execute(update)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for grant_table in ['user_project_metadata', 'user_domain_metadata',
                        'group_project_metadata', 'group_domain_metadata']:
        upgrade_grant_table(meta, migrate_engine, session, grant_table)
    session.commit()
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for grant_table in ['user_project_metadata', 'user_domain_metadata',
                        'group_project_metadata', 'group_domain_metadata']:
        downgrade_grant_table(meta, migrate_engine, session, grant_table)
    session.commit()
    session.close()
