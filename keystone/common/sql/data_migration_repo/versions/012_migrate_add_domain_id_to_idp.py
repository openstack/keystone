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

import uuid

import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker

from keystone.resource.backends import base


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    maker = sessionmaker(bind=migrate_engine)
    session = maker()

    idp_table = sql.Table('identity_provider', meta, autoload=True)

    for idp_row in idp_table.select().execute():
        domain_id = _create_federated_domain(meta, session, idp_row['id'])
        # update idp with the new federated domain_id
        values = {'domain_id': domain_id}
        stmt = idp_table.update().where(
            idp_table.c.id == idp_row['id']).values(values)
        stmt.execute()


def _create_federated_domain(meta, session, idp_id):
    domain_id = uuid.uuid4().hex
    desc = 'Auto generated federated domain for Identity Provider: ' + idp_id
    federated_domain = {
        'id': domain_id,
        'name': domain_id,
        'enabled': True,
        'description': desc,
        'domain_id': base.NULL_DOMAIN_ID,
        'is_domain': True,
        'parent_id': None,
        'extra': '{}'
    }
    project_table = sql.Table('project', meta, autoload=True)
    new_row = project_table.insert().values(**federated_domain)
    session.execute(new_row)
    session.commit()
    return domain_id
