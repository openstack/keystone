#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import migrate
import sqlalchemy as sql


ROLE_TABLE = 'role'
IMPLIED_ROLE_TABLE = 'implied_role'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    role = sql.Table(ROLE_TABLE, meta, autoload=True)
    implied_role = sql.Table(IMPLIED_ROLE_TABLE, meta, autoload=True)

    fkeys = [
        {'columns': [implied_role.c.prior_role_id],
         'references': [role.c.id]},
        {'columns': [implied_role.c.implied_role_id],
         'references': [role.c.id]},
    ]

    # NOTE(stevemar): We need to divide these into two separate loops otherwise
    # they may clobber each other and only end up with one foreign key.
    for fkey in fkeys:
        migrate.ForeignKeyConstraint(columns=fkey['columns'],
                                     refcolumns=fkey['references'],
                                     name=fkey.get('name')).drop()
    for fkey in fkeys:
        migrate.ForeignKeyConstraint(columns=fkey['columns'],
                                     refcolumns=fkey['references'],
                                     name=fkey.get('name'),
                                     ondelete="CASCADE").create()
