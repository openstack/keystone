# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
import uuid

import sqlalchemy as sql
from sqlalchemy import orm


ENDPOINT_TYPES = ['public', 'internal', 'admin']


def upgrade(migrate_engine):
    """Split each legacy endpoint into separate records for each interface."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    legacy_table = sql.Table('endpoint_v2', meta, autoload=True)
    new_table = sql.Table('endpoint_v3', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for ref in session.query(legacy_table).all():
        # pull urls out of extra
        extra = json.loads(ref.extra)
        urls = dict((i, extra.pop('%surl' % i)) for i in ENDPOINT_TYPES)

        for interface in ENDPOINT_TYPES:
            endpoint = {
                'id': uuid.uuid4().hex,
                'legacy_endpoint_id': ref.id,
                'interface': interface,
                'region': ref.region,
                'service_id': ref.service_id,
                'url': urls[interface],
                'extra': json.dumps(extra),
            }
            insert = new_table.insert().values(endpoint)
            migrate_engine.execute(insert)
    session.commit()
    session.close()


def downgrade(migrate_engine):
    """Re-create the v2 endpoints table based on v3 endpoints."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    legacy_table = sql.Table('endpoint_v2', meta, autoload=True)
    new_table = sql.Table('endpoint_v3', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for ref in session.query(new_table).all():
        extra = json.loads(ref.extra)
        legacy_id = ref.legacy_endpoint_id or extra.get('legacy_endpoint_id')
        if not legacy_id:
            continue

        q = session.query(legacy_table)
        q = q.filter_by(id=legacy_id)
        legacy_ref = q.first()
        if legacy_ref:
            # We already have one, so just update the extra
            # attribute with the urls.
            extra = json.loads(legacy_ref.extra)
            extra['%surl' % ref.interface] = ref.url
            values = {'extra': json.dumps(extra)}
            update = legacy_table.update().\
                where(legacy_table.c.id == legacy_ref.id).\
                values(values)
            migrate_engine.execute(update)
        else:
            # This is the first one of this legacy ID, so
            # we can insert instead.
            extra = json.loads(ref.extra)
            extra['%surl' % ref.interface] = ref.url
            endpoint = {
                'id': legacy_id,
                'region': ref.region,
                'service_id': ref.service_id,
                'extra': json.dumps(extra),
            }
            insert = legacy_table.insert().values(endpoint)
            migrate_engine.execute(insert)
        session.commit()
    session.close()
