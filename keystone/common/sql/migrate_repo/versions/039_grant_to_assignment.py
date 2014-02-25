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

import json

import sqlalchemy as sql

from keystone.assignment.backends import sql as assignment_sql

USER_PROJECT_TABLE = 'user_project_metadata'
GROUP_PROJECT_TABLE = 'group_project_metadata'
USER_DOMAIN_TABLE = 'user_domain_metadata'
GROUP_DOMAIN_TABLE = 'group_domain_metadata'

ASSIGNMENT_TABLE = 'assignment'

GRANT_TABLES = [USER_PROJECT_TABLE, USER_DOMAIN_TABLE,
                GROUP_PROJECT_TABLE, GROUP_DOMAIN_TABLE]


def migrate_grant_table(meta, migrate_engine, session, table_name):

    def extract_actor_and_target(table_name, composite_grant):
        if table_name == USER_PROJECT_TABLE:
            return {'type': assignment_sql.AssignmentType.USER_PROJECT,
                    'actor_id': composite_grant.user_id,
                    'target_id': composite_grant.project_id}
        elif table_name == GROUP_PROJECT_TABLE:
            return {'type': assignment_sql.AssignmentType.GROUP_PROJECT,
                    'actor_id': composite_grant.group_id,
                    'target_id': composite_grant.project_id}
        elif table_name == USER_DOMAIN_TABLE:
            return {'type': assignment_sql.AssignmentType.USER_DOMAIN,
                    'actor_id': composite_grant.user_id,
                    'target_id': composite_grant.domain_id}
        else:
            return {'type': assignment_sql.AssignmentType.GROUP_DOMAIN,
                    'actor_id': composite_grant.group_id,
                    'target_id': composite_grant.domain_id}

    def grant_to_grant_dict_list(table_name, composite_grant):
        """Make each role in the list of this entry a separate assignment."""
        json_metadata = json.loads(composite_grant.data)
        role_dict_list = []
        if 'roles' in json_metadata:
            for x in json_metadata['roles']:
                if x.get('id') is None:
                    # Looks like an invalid role, drop it
                    break
                grant = extract_actor_and_target(table_name, composite_grant)
                grant['role_id'] = x.get('id')
                grant['inherited'] = False
                if x.get('inherited_to') == 'projects':
                    grant['inherited'] = True
                role_dict_list.append(grant)
        return role_dict_list

    upgrade_table = sql.Table(table_name, meta, autoload=True)
    assignment_table = sql.Table(ASSIGNMENT_TABLE, meta, autoload=True)

    # For each grant in this table, expand it out to be an assignment entry for
    # each role in the metadata
    for grant in session.query(upgrade_table).all():
        for grant_role in grant_to_grant_dict_list(table_name, grant):
            new_entry = assignment_table.insert().values(
                type=grant_role['type'],
                actor_id=grant_role['actor_id'],
                target_id=grant_role['target_id'],
                role_id=grant_role['role_id'],
                inherited=grant_role['inherited'])
            migrate_engine.execute(new_entry)

    # Delete all the rows
    migrate_engine.execute(upgrade_table.delete())


def downgrade_assignment_table(meta, migrate_engine):

    def add_to_dict_list(metadata, assignment_row):
        """Update a metadata dict list with the role.

        For the assignment row supplied, we need to append the role_id into
        the metadata list of dicts.  If the row is inherited, then we mark
        it so in the dict we append.

        """
        new_entry = {'id': assignment_row.role_id}
        if assignment_row.inherited and (
                assignment_row.type ==
                assignment_sql.AssignmentType.USER_DOMAIN or
                assignment_row.type ==
                assignment_sql.AssignmentType.GROUP_DOMAIN):
            new_entry['inherited_to'] = 'projects'

        if metadata is not None:
            json_metadata = json.loads(metadata)
        else:
            json_metadata = {}

        if json_metadata.get('roles') is None:
            json_metadata['roles'] = []

        json_metadata['roles'].append(new_entry)
        return json.dumps(json_metadata)

    def build_user_project_entry(meta, session, row):
        update_table = sql.Table(USER_PROJECT_TABLE, meta, autoload=True)
        q = session.query(update_table)
        q = q.filter_by(user_id=row.actor_id)
        q = q.filter_by(project_id=row.target_id)
        ref = q.first()
        if ref is not None:
            values = {'data': add_to_dict_list(ref.data, row)}
            update = update_table.update().where(
                update_table.c.user_id == ref.user_id).where(
                    update_table.c.project_id == ref.project_id).values(values)
        else:
            values = {'user_id': row.actor_id,
                      'project_id': row.target_id,
                      'data': add_to_dict_list(None, row)}
            update = update_table.insert().values(values)
        return update

    def build_group_project_entry(meta, session, row):
        update_table = sql.Table(GROUP_PROJECT_TABLE, meta, autoload=True)
        q = session.query(update_table)
        q = q.filter_by(group_id=row.actor_id)
        q = q.filter_by(project_id=row.target_id)
        ref = q.first()
        if ref is not None:
            values = {'data': add_to_dict_list(ref.data, row)}
            update = update_table.update().where(
                update_table.c.group_id == ref.group_id).where(
                    update_table.c.project_id == ref.project_id).values(values)
        else:
            values = {'group_id': row.actor_id,
                      'project_id': row.target_id,
                      'data': add_to_dict_list(None, row)}
            update = update_table.insert().values(values)
        return update

    def build_user_domain_entry(meta, session, row):
        update_table = sql.Table(USER_DOMAIN_TABLE, meta, autoload=True)
        q = session.query(update_table)
        q = q.filter_by(user_id=row.actor_id)
        q = q.filter_by(domain_id=row.target_id)
        ref = q.first()
        if ref is not None:
            values = {'data': add_to_dict_list(ref.data, row)}
            update = update_table.update().where(
                update_table.c.user_id == ref.user_id).where(
                    update_table.c.domain_id == ref.domain_id).values(values)
        else:
            values = {'user_id': row.actor_id,
                      'domain_id': row.target_id,
                      'data': add_to_dict_list(None, row)}
            update = update_table.insert().values(values)
        return update

    def build_group_domain_entry(meta, session, row):
        update_table = sql.Table(GROUP_DOMAIN_TABLE, meta, autoload=True)
        q = session.query(update_table)
        q = q.filter_by(group_id=row.actor_id)
        q = q.filter_by(domain_id=row.target_id)
        ref = q.first()
        if ref is not None:
            values = {'data': add_to_dict_list(ref.data, row)}
            update = update_table.update().where(
                update_table.c.group_id == ref.group_id).where(
                    update_table.c.domain_id == ref.domain_id).values(values)
        else:
            values = {'group_id': row.actor_id,
                      'domain_id': row.target_id,
                      'data': add_to_dict_list(None, row)}
            update = update_table.insert().values(values)
        return update

    def build_update(meta, session, row):
        """Build an update or an insert to the correct metadata table."""
        if row.type == assignment_sql.AssignmentType.USER_PROJECT:
            return build_user_project_entry(meta, session, row)
        elif row.type == assignment_sql.AssignmentType.GROUP_PROJECT:
            return build_group_project_entry(meta, session, row)
        elif row.type == assignment_sql.AssignmentType.USER_DOMAIN:
            return build_user_domain_entry(meta, session, row)
        elif row.type == assignment_sql.AssignmentType.GROUP_DOMAIN:
            return build_group_domain_entry(meta, session, row)
        # If the row type doesn't match any that we understand we drop
        # the data.

    session = sql.orm.sessionmaker(bind=migrate_engine)()
    downgrade_table = sql.Table(ASSIGNMENT_TABLE, meta, autoload=True)
    for assignment in session.query(downgrade_table).all():
        update = build_update(meta, session, assignment)
        if update is not None:
            migrate_engine.execute(update)
            session.commit()

    # Delete all the rows
    migrate_engine.execute(downgrade_table.delete())

    session.commit()
    session.close()


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    session = sql.orm.sessionmaker(bind=migrate_engine)()
    for table_name in GRANT_TABLES:
        migrate_grant_table(meta, migrate_engine, session, table_name)
    session.commit()
    session.close()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    downgrade_assignment_table(meta, migrate_engine)
