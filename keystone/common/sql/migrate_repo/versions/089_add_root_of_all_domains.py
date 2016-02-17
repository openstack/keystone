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
_DOMAIN_TABLE_NAME = 'domain'
NULL_DOMAIN_ID = '<<keystone.domain.root>>'


def upgrade(migrate_engine):

    def _generate_root_domain_project():
        # Generate a project that will act as a root for all domains, in order
        # for use to be able to use a FK constraint on domain_id. Projects
        # acting as a domain will not reference this as their parent_id, just
        # as domain_id.
        #
        # This special project is filtered out by the driver, so is never
        # visible to the manager or API.

        project_ref = {
            'id': NULL_DOMAIN_ID,
            'name': NULL_DOMAIN_ID,
            'enabled': False,
            'description': '',
            'domain_id': NULL_DOMAIN_ID,
            'is_domain': True,
            'parent_id': None,
            'extra': '{}'
        }
        return project_ref

    def _generate_root_domain():
        # Generate a similar root for the domain table, this is an interim
        # step so as to allow continuation of current project domain_id FK.
        #
        # This special domain is filtered out by the driver, so is never
        # visible to the manager or API.

        domain_ref = {
            'id': NULL_DOMAIN_ID,
            'name': NULL_DOMAIN_ID,
            'enabled': False,
            'extra': '{}'
        }
        return domain_ref

    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    project_table = sql.Table(_PROJECT_TABLE_NAME, meta, autoload=True)
    domain_table = sql.Table(_DOMAIN_TABLE_NAME, meta, autoload=True)

    root_domain = _generate_root_domain()
    new_entry = domain_table.insert().values(**root_domain)
    session.execute(new_entry)
    session.commit()

    root_domain_project = _generate_root_domain_project()
    new_entry = project_table.insert().values(**root_domain_project)
    session.execute(new_entry)
    session.commit()

    session.close()
