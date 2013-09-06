# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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
from sqlalchemy import orm

from keystone import config


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


def upgrade(migrate_engine):
    """Creates the default domain."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    domain_table = sql.Table('domain', meta, autoload=True)

    domain = {
        'id': DEFAULT_DOMAIN_ID,
        'name': 'Default',
        'enabled': True,
        'extra': json.dumps({
            'description': 'Owns users and tenants (i.e. projects) available '
                           'on Identity API v2.'})}

    session = orm.sessionmaker(bind=migrate_engine)()
    insert = domain_table.insert()
    insert.execute(domain)
    session.commit()


def downgrade(migrate_engine):
    """Delete the default domain."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('domain', meta, autoload=True)
    session = orm.sessionmaker(bind=migrate_engine)()
    session.execute(
        'DELETE FROM domain WHERE id=:id', {'id': DEFAULT_DOMAIN_ID})
    session.commit()
