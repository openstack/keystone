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

from oslo_serialization import jsonutils
import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    service_table = sql.Table('service', meta, autoload=True)
    services = list(service_table.select().execute())

    for service in services:
        if service.extra is not None:
            extra_dict = jsonutils.loads(service.extra)
        else:
            extra_dict = {}

        # Skip records where service is not null
        if extra_dict.get('name') is not None:
            continue
        # Default the name to empty string
        extra_dict['name'] = ''
        new_values = {
            'extra': jsonutils.dumps(extra_dict),
        }
        f = service_table.c.id == service.id
        update = service_table.update().where(f).values(new_values)
        migrate_engine.execute(update)
