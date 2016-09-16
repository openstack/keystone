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

from keystone.common.sql import upgrades


_PROJECT_TABLE_NAME = 'project'
_DOMAIN_TABLE_NAME = 'domain'
_PARENT_ID_COLUMN_NAME = 'parent_id'
_DOMAIN_ID_COLUMN_NAME = 'domain_id'

# Above the driver level, the domain_id of a project acting as a domain is
# None. However, in order to enable sql integrity constraints to still operate
# on this column, we create a special "root of all domains" row, with an ID of
# NULL_DOMAIN_ID, which all projects acting as a domain reference in their
# domain_id attribute. This special row, as well as NULL_DOMAIN_ID, are never
# exposed outside of sql driver layer.
NULL_DOMAIN_ID = '<<keystone.domain.root>>'


def list_existing_project_constraints(project_table, domain_table):
    constraints = [{'table': project_table,
                    'fk_column': _PARENT_ID_COLUMN_NAME,
                    'ref_column': project_table.c.id},
                   {'table': project_table,
                    'fk_column': _DOMAIN_ID_COLUMN_NAME,
                    'ref_column': domain_table.c.id}]

    return constraints


def list_new_project_constraints(project_table):
    constraints = [{'table': project_table,
                    'fk_column': _PARENT_ID_COLUMN_NAME,
                    'ref_column': project_table.c.id},
                   {'table': project_table,
                    'fk_column': _DOMAIN_ID_COLUMN_NAME,
                    'ref_column': project_table.c.id}]

    return constraints


def upgrade(migrate_engine):

    def _project_from_domain(domain):
        # Creates a project dict with is_domain=True from the provided
        # domain.

        description = None
        extra = {}
        if domain.extra is not None:
            # 'description' property is an extra attribute in domains but a
            # first class attribute in projects
            extra = json.loads(domain.extra)
            description = extra.pop('description', None)

        return {
            'id': domain.id,
            'name': domain.name,
            'enabled': domain.enabled,
            'description': description,
            'domain_id': NULL_DOMAIN_ID,
            'is_domain': True,
            'parent_id': None,
            'extra': json.dumps(extra)
        }

    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    project_table = sql.Table(_PROJECT_TABLE_NAME, meta, autoload=True)
    domain_table = sql.Table(_DOMAIN_TABLE_NAME, meta, autoload=True)

    # NOTE(htruta): Remove the parent_id constraint during the migration
    # because for every root project inside this domain, we will set
    # the project domain_id to be its parent_id. We re-enable the constraint
    # in the end of this method. We also remove the domain_id constraint,
    # while be recreated a FK to the project_id at the end.
    upgrades.remove_constraints(
        list_existing_project_constraints(project_table, domain_table))

    # For each domain, create a project acting as a domain. We ignore the
    # "root of all domains" row, since we already have one of these in the
    # project table.
    domains = list(domain_table.select().execute())
    for domain in domains:
        if domain.id == NULL_DOMAIN_ID:
            continue
        is_domain_project = _project_from_domain(domain)
        new_entry = project_table.insert().values(**is_domain_project)
        session.execute(new_entry)
        session.commit()

    # For each project, that has no parent (i.e. a top level project), update
    # it's parent_id to point at the project acting as its domain. We ignore
    # the "root of all domains" row, since its parent_id must always be None.
    projects = list(project_table.select().execute())
    for project in projects:
        if (project.parent_id is not None or project.is_domain or
                project.id == NULL_DOMAIN_ID):
            continue
        values = {'parent_id': project.domain_id}
        update = project_table.update().where(
            project_table.c.id == project.id).values(values)
        session.execute(update)
        session.commit()

    upgrades.add_constraints(
        list_new_project_constraints(project_table))

    session.close()
