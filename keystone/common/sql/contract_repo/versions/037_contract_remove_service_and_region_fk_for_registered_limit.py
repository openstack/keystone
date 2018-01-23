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

from migrate import ForeignKeyConstraint
import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    registered_limit_table = sql.Table('registered_limit', meta, autoload=True)
    service_table = sql.Table('service', meta, autoload=True)
    region_table = sql.Table('region', meta, autoload=True)

    inspector = sql.engine.reflection.Inspector.from_engine(migrate_engine)
    for fk in inspector.get_foreign_keys('registered_limit'):
        if fk['referred_table'] == 'service':
            fkey = ForeignKeyConstraint([registered_limit_table.c.service_id],
                                        [service_table.c.id],
                                        name=fk['name'])
            fkey.drop()
        else:
            fkey = ForeignKeyConstraint([registered_limit_table.c.region_id],
                                        [region_table.c.id],
                                        name=fk['name'])
            fkey.drop()
